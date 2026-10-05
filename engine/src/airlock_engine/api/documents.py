"""``document.*`` methods.

Documents are always referenced by path. The engine reads the file itself, so
document bytes never travel over IPC and never pass through the web view.
"""

from __future__ import annotations

from typing import Any

from airlock_engine import safelog
from airlock_engine.documents.formats import Support
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.service import extract_path
from airlock_engine.extraction.summary import summarize
from airlock_engine.ipc.server import MethodRegistry, RequestContext, require_str
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
        options = ExtractionOptions(ocr=params.get("ocr", True) is not False)
        extraction = extract_path(require_str(params, "path"), options, ctx)
        document, spec, duration_ms = extraction.document, extraction.spec, extraction.duration_ms
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
