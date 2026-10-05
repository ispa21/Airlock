"""``verify.run`` and ``export.*``: check a protected copy, then let it leave.

A copy can be saved or copied only after ``verify.run`` read it back and
found none of the protected values (status *passed*), or found only new
items the user has looked at (status *review* with ``acknowledge_review``).
The bytes that leave are exactly the bytes that were checked.

``export.prepare`` and ``export.save`` are for the host only: it asks for the
suggested name, shows the native save dialog and passes the chosen path. The
web view can never name a destination.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Any

from airlock_engine import safelog
from airlock_engine.api.scan import detect_document
from airlock_engine.core import errors
from airlock_engine.extraction import isolation
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.wire import WireError, document_from_wire
from airlock_engine.ipc.server import (
    InvalidParams,
    MethodRegistry,
    RequestCancelled,
    RequestContext,
    require_str,
)
from airlock_engine.masking.artifacts import Artifact, ArtifactStore
from airlock_engine.storage import Storage
from airlock_engine.verification.export import validate_destination, write_atomically
from airlock_engine.verification.verifier import PASSED, REVIEW, ai_text, evaluate

#: Longest text export.text returns (IPC messages are capped at 16 MB).
MAX_TEXT_CHARS = 4_000_000

_TEXT_FILTER = "Text file"


def _flag(params: dict[str, Any], key: str) -> bool:
    value = params.get(key, False)
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be a boolean")
    return value


def register(
    registry: MethodRegistry,
    storage: Storage,
    artifacts: ArtifactStore,
    private_folders: list[Path],
) -> None:
    def get(params: dict[str, Any]) -> Artifact:
        artifact = artifacts.get(require_str(params, "artifact_id", max_len=64))
        if artifact is None or artifact.check is None:
            raise errors.copy_not_found()
        return artifact

    def run(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Read the copy back in an isolated worker (OCR if the scan used it),
        search its stored bytes, run every detector again, and decide."""
        artifact = get(params)
        check = artifact.check
        assert check is not None
        started = time.perf_counter()
        artifact.verification = None
        artifact.verified_sha256 = ""
        artifact.verified_text = None
        extension = artifact.path.suffix.lstrip(".")
        safelog.log.info("verify_started", file_type=artifact.format_id)
        try:
            raw = isolation.run_job(
                {
                    "op": "verify",
                    "path": str(artifact.path),
                    "sha256": artifact.sha256,
                    "extension": extension,
                    "format": artifact.format_id,
                    "format_label": artifact.format_id,
                    "options": ExtractionOptions(ocr=check.ocr).to_wire(),
                    "values": [value for value, _ in check.protected],
                    "replacements": sorted(check.replacements),
                    "log_level": "info",
                },
                on_progress=ctx.progress,
                is_cancelled=lambda: ctx.cancelled,
            )
        except isolation.JobCancelled as exc:
            raise RequestCancelled from exc
        except errors.AirlockError as exc:
            safelog.log.warning("verify_failed", file_type=artifact.format_id, error_kind=exc.kind)
            raise
        try:
            if not isinstance(raw, dict):
                raise WireError("verify result")
            document = document_from_wire(raw["document"])
            hits = [(int(i), str(part)) for i, part in raw.get("raw_hits", [])]
        except (WireError, KeyError, TypeError, ValueError) as exc:
            raise errors.verification_unreadable() from exc

        outcome, context, _, _ = detect_document(storage, document, check.use_ner, ctx)
        result = evaluate(document, hits, outcome.detected, check, context.entities())
        artifact.verification = result
        artifact.verified_sha256 = artifact.sha256
        if result.status in (PASSED, REVIEW):
            artifact.verified_text = ai_text(document)
        duration = round((time.perf_counter() - started) * 1000)
        safelog.log.info(
            "verify_completed",
            file_type=artifact.format_id,
            status=result.status,
            remaining_count=len(result.leaks),
            finding_count=len(result.new),
            duration_ms=duration,
        )
        return {"artifact_id": artifact.artifact_id, **result.to_json(), "duration_ms": duration}

    def exportable(artifact: Artifact, params: dict[str, Any]) -> None:
        """Only checked bytes leave, and only if the check allows it."""
        result = artifact.verification
        if result is None or not artifact.verified_sha256:
            raise errors.copy_not_verified()
        if result.status == REVIEW and not _flag(params, "acknowledge_review"):
            raise errors.review_required()
        if result.status not in (PASSED, REVIEW):
            raise errors.verification_failed()
        try:
            current = hashlib.sha256(artifact.path.read_bytes()).hexdigest()
        except OSError as exc:
            raise errors.copy_not_found() from exc
        if current != artifact.verified_sha256:
            raise errors.copy_changed()

    def target(artifact: Artifact, as_text: bool) -> tuple[str, str, str]:
        """(suggested file name, extension, dialog filter label)."""
        name = artifact.suggested_name
        if as_text:
            stem = name.rsplit(".", 1)[0] if "." in name else name
            return f"{stem}.txt", "txt", _TEXT_FILTER
        extension = artifact.path.suffix.lstrip(".")
        return name, extension, f"{extension.upper()} file"

    def prepare(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Host only: the name and filter for the native save dialog."""
        artifact = get(params)
        exportable(artifact, params)
        as_text = _flag(params, "as_text")
        name, extension, label = target(artifact, as_text)
        return {"file_name": name, "extension": extension, "filter_label": label}

    def save(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Host only: write the checked copy (or its text) where the user chose."""
        artifact = get(params)
        exportable(artifact, params)
        as_text = _flag(params, "as_text")
        _, extension, _ = target(artifact, as_text)
        never = [Path(artifact.source_path)] if artifact.source_path else []
        destination = validate_destination(
            params.get("destination"),
            extension=extension,
            never=never,
            private_folders=[artifacts.work_dir, *private_folders],
        )
        if as_text:
            data = (artifact.verified_text or "").encode("utf-8")
        else:
            data = artifact.path.read_bytes()
            if hashlib.sha256(data).hexdigest() != artifact.verified_sha256:
                raise errors.copy_changed()
        write_atomically(destination, data)
        safelog.log.info(
            "export_completed",
            file_type="txt" if as_text else artifact.format_id,
            size_bytes=len(data),
        )
        return {"ok": True, "file_name": destination.name, "size_bytes": len(data)}

    def text(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The checked copy's readable text, for pasting into an AI tool."""
        artifact = get(params)
        exportable(artifact, params)
        value = artifact.verified_text or ""
        if len(value) > MAX_TEXT_CHARS:
            raise errors.text_too_long()
        safelog.log.info("export_text", file_type=artifact.format_id, size_bytes=len(value))
        return {"text": value, "chars": len(value)}

    registry.register("verify.run", run)
    registry.register("export.prepare", prepare)
    registry.register("export.save", save)
    registry.register("export.text", text)
