"""Validate a path and extract it in an isolated worker (shared by
``document.extract`` and ``scan.start``)."""

from __future__ import annotations

import time
from dataclasses import dataclass

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.core.models import ExtractedDocument
from airlock_engine.documents.formats import FormatSpec, Support
from airlock_engine.extraction import isolation
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.wire import WireError, document_from_wire
from airlock_engine.ipc.server import RequestCancelled, RequestContext
from airlock_engine.security.input_files import validate_input_file


@dataclass(frozen=True)
class Extraction:
    document: ExtractedDocument
    spec: FormatSpec
    duration_ms: float
    #: SHA-256 of the exact bytes that were scanned.
    sha256: str = ""
    path: str = ""
    size_bytes: int = 0
    extension: str = ""


def extract_path(path: str, options: ExtractionOptions, ctx: RequestContext) -> Extraction:
    validated = validate_input_file(path)
    spec = validated.spec
    if spec.support is not Support.AVAILABLE:
        raise errors.unsupported_format(validated.extension)
    started = time.perf_counter()
    safelog.log.info("extraction_started", file_type=spec.format_id)
    job = {
        "op": "extract",
        "path": str(validated.path),
        "size_bytes": validated.size_bytes,
        "extension": validated.extension,
        "format": spec.format_id,
        "format_label": spec.label,
        "options": options.to_wire(),
        "log_level": "info",
    }
    try:
        raw = isolation.run_job(
            job,
            on_progress=ctx.progress,
            is_cancelled=lambda: ctx.cancelled,
        )
    except isolation.JobCancelled as exc:
        safelog.log.info("extraction_cancelled", file_type=spec.format_id)
        raise RequestCancelled from exc
    except errors.AirlockError as exc:
        safelog.log.warning("extraction_failed", file_type=spec.format_id, error_kind=exc.kind)
        raise
    try:
        document = document_from_wire(raw)
    except WireError as exc:
        raise errors.extraction_crashed() from exc
    sha256 = raw.get("source_sha256", "") if isinstance(raw, dict) else ""
    return Extraction(
        document,
        spec,
        (time.perf_counter() - started) * 1000,
        sha256=str(sha256),
        path=str(validated.path),
        size_bytes=validated.size_bytes,
        extension=validated.extension,
    )
