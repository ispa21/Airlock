"""``document.*`` methods.

Documents are always referenced by path. The engine reads the file itself, so
document bytes never travel over IPC and never pass through the web view.
"""

from __future__ import annotations

import time
from typing import Any

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.documents.formats import Support
from airlock_engine.extraction import isolation
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.summary import summarize
from airlock_engine.extraction.wire import WireError, document_from_wire
from airlock_engine.ipc.server import (
    MethodRegistry,
    RequestCancelled,
    RequestContext,
    require_str,
)
from airlock_engine.security.input_files import validate_input_file


def register(registry: MethodRegistry) -> None:
    def inspect(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Validate a dropped file and report what Airlock will do with it.

        Read-only: the file is opened for reading and never modified.
        """
        validated = validate_input_file(require_str(params, "path"))
        spec = validated.spec
        safelog.log.info(
            "document_inspected", file_type=spec.format_id, size_bytes=validated.size_bytes
        )
        return {
            "file_name": validated.path.name,
            "extension": validated.extension,
            "size_bytes": validated.size_bytes,
            "format": spec.format_id,
            "format_label": spec.label,
            "family": spec.family.value,
            "support": spec.support.value,
            "scannable": spec.support is Support.AVAILABLE,
        }

    def extract(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Read every text-bearing part of a file in an isolated worker.

        Returns a content-free summary. The extracted text stays in the engine.
        """
        validated = validate_input_file(require_str(params, "path"))
        spec = validated.spec
        if spec.support is not Support.AVAILABLE:
            raise errors.unsupported_format(validated.extension)
        options = ExtractionOptions(ocr=params.get("ocr", True) is not False)
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

        duration_ms = (time.perf_counter() - started) * 1000
        summary = summarize(document, spec, duration_ms)
        safelog.log.info(
            "extraction_completed",
            file_type=spec.format_id,
            segment_count=summary["segment_count"],
            duration_ms=summary["duration_ms"],
        )
        return summary

    registry.register("document.inspect", inspect)
    registry.register("document.extract", extract)
