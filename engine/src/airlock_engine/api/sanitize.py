"""``sanitize.*`` and ``vault.*``: protected copies and reversible placeholders."""

from __future__ import annotations

import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.core.models import Action
from airlock_engine.extraction import isolation
from airlock_engine.ipc.server import (
    InvalidParams,
    MethodRegistry,
    RequestCancelled,
    RequestContext,
    require_str,
)
from airlock_engine.masking.artifacts import ArtifactStore
from airlock_engine.masking.masker import BlockedFindings, build_plan
from airlock_engine.masking.pdf_text import pdf_sections
from airlock_engine.masking.vault import Vault, VaultEntry, VaultError
from airlock_engine.scan import SessionStore
from airlock_engine.security.keyprotect import KeyProtectionError, MemoryProtector
from airlock_engine.storage import Storage, StorageError
from airlock_engine.verification.verifier import CopyCheck, normalize

#: Text accepted by vault.restore (an AI response), in characters.
MAX_RESTORE_CHARS = 2_000_000


class _VaultHolder:
    """Opens the vault lazily; a broken vault never blocks scanning."""

    def __init__(self, storage: Storage, directory: Path | None) -> None:
        self._storage = storage
        self._directory = directory
        self._vault: Vault | None = None
        self._lock = threading.Lock()

    def get(self) -> Vault:
        with self._lock:
            if self._vault is None:
                try:
                    protector = (
                        self._storage.key_protector() if self._directory else MemoryProtector()
                    )
                    self._vault = Vault(self._directory, protector)
                    self._vault.purge()
                except (StorageError, VaultError, KeyProtectionError, OSError) as exc:
                    raise errors.vault_unavailable() from exc
            return self._vault


def register(
    registry: MethodRegistry,
    storage: Storage,
    sessions: SessionStore,
    artifacts: ArtifactStore,
    vault_dir: Path | None,
) -> None:
    vaults = _VaultHolder(storage, vault_dir)

    def run(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Create the protected copy for a scan, using its current decisions.

        Runs in an isolated worker. The copy goes to Airlock's private work
        folder; it can only be saved or copied after ``verify.run`` passes.
        """
        session = sessions.get(require_str(params, "scan_id", max_len=64))
        if session is None:
            raise errors.scan_not_found()
        strip = params.get("strip_metadata", True)
        if not isinstance(strip, bool):
            raise InvalidParams("'strip_metadata' must be a boolean")
        meta = session.meta
        with session.lock:
            decision = session.decision or session.redecide()
            try:
                plan = build_plan(session.document, decision)
            except BlockedFindings as exc:
                raise errors.blocked_findings(exc.count) from exc
        wire = plan.to_wire(session.document, strip_metadata=strip)
        if session.format_id == "pdf":
            wire["pdf_pages"] = pdf_sections(session.document, plan)

        artifact = artifacts.create(
            session.scan_id,
            session.format_id,
            meta.get("extension", ""),
            meta.get("name", "file"),
            source_path=str(meta.get("path", "")),
        )
        started = time.perf_counter()
        safelog.log.info("sanitize_started", file_type=session.format_id)
        try:
            result = isolation.run_job(
                {
                    "op": "sanitize",
                    "path": meta["path"],
                    "sha256": meta["sha256"],
                    "format": session.format_id,
                    "format_label": meta.get("format_label", "file"),
                    "destination": str(artifact.path),
                    "plan": wire,
                    "log_level": "info",
                },
                on_progress=ctx.progress,
                is_cancelled=lambda: ctx.cancelled,
            )
        except isolation.JobCancelled as exc:
            artifacts.discard(artifact.artifact_id)
            raise RequestCancelled from exc
        except errors.AirlockError as exc:
            artifacts.discard(artifact.artifact_id)
            safelog.log.warning("sanitize_failed", file_type=session.format_id, error_kind=exc.kind)
            raise
        if not isinstance(result, dict) or not artifact.path.exists():
            artifacts.discard(artifact.artifact_id)
            raise errors.extraction_crashed()

        removed = [(str(k), str(label)) for k, label in result.get("removed", [])]
        artifact.size_bytes = int(result.get("size_bytes", 0))
        artifact.sha256 = str(result.get("sha256", ""))
        artifact.removed = removed
        artifact.check = CopyCheck(
            protected=list(dict.fromkeys(plan.protected)),
            replacements=frozenset(text for _, text in plan.sweep)
            | frozenset(text for *_, text in plan.edits),
            kept=frozenset(
                normalize(f.detection.matched_value.reveal())
                for f in decision.findings
                if (f.effective_action or f.action) is Action.ALLOW
            ),
            use_ner=bool(meta.get("use_ner", True)),
            ocr=bool(meta.get("ocr", True)),
        )

        entries = [
            VaultEntry(text, original, entity_type)
            for text, (original, entity_type) in plan.reversible.items()
        ]
        vault_status: dict[str, Any] = {
            "entries": len(entries),
            "stored": False,
            "protection": None,
        }
        if entries:
            try:
                vault = vaults.get()
                vault.put(
                    artifact.artifact_id,
                    entries,
                    {"format": session.format_id, "scan_id": session.scan_id},
                )
                vault_status.update(stored=True, protection=vault.protector.name)
            except (errors.AirlockError, VaultError, OSError):
                safelog.log.warning("vault_store_failed")

        counts = Counter({k: v for k, v in plan.counts.items()})
        removed_summary = Counter(label for _, label in removed)
        response = {
            "artifact_id": artifact.artifact_id,
            "file_name": artifact.suggested_name,
            "format": "pdf" if session.format_id == "pdf" else session.format_id,
            "size_bytes": artifact.size_bytes,
            "replaced": {a: counts.get(a, 0) for a in ("MASK", "REDACT", "GENERALIZE")},
            "removed": [{"label": label, "count": n} for label, n in removed_summary.items()],
            "vault": vault_status,
            # verify.run must pass before the copy can be saved or copied.
            "verified": False,
            "duration_ms": round((time.perf_counter() - started) * 1000),
        }
        artifact.summary = response
        safelog.log.info(
            "sanitize_completed",
            file_type=session.format_id,
            finding_count=sum(counts.values()),
            size_bytes=artifact.size_bytes,
            duration_ms=response["duration_ms"],
        )
        return response

    def discard(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Delete a protected copy from the work folder (its vault record stays)."""
        return {
            "ok": True,
            "discarded": artifacts.discard(require_str(params, "artifact_id", max_len=64)),
        }

    def restore(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Put the original values back into text that contains this copy's
        placeholders (e.g. an AI response). The only method that returns
        original values to the UI, and only on this explicit request."""
        record_id = require_str(params, "artifact_id", max_len=64)
        text = params.get("text")
        if not isinstance(text, str) or len(text) > MAX_RESTORE_CHARS:
            raise InvalidParams("'text' must be a string")
        try:
            restored = vaults.get().restore(record_id, text)
        except VaultError as exc:
            raise errors.vault_record_not_found() from exc
        if restored is None:
            raise errors.vault_record_not_found()
        safelog.log.info("vault_restored", entity_count=restored[1])
        return {"text": restored[0], "restored": restored[1]}

    def forget(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Delete the stored placeholders of a protected copy for good."""
        record_id = require_str(params, "artifact_id", max_len=64)
        try:
            deleted = vaults.get().forget(record_id)
        except VaultError as exc:
            raise errors.vault_record_not_found() from exc
        return {"ok": True, "deleted": deleted}

    def status(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        vault = vaults.get()
        return {"protection": vault.protector.name, "records": len(vault.ids())}

    registry.register("sanitize.run", run)
    registry.register("sanitize.discard", discard)
    registry.register("vault.restore", restore)
    registry.register("vault.forget", forget)
    registry.register("vault.status", status)
