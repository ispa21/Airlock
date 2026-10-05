"""Route a sanitize job to the right format. Runs inside the isolated worker."""

from __future__ import annotations

from airlock_engine.core import errors
from airlock_engine.documents import formats
from airlock_engine.documents.formats import Family
from airlock_engine.documents.ooxml.rewrite import RewriteError
from airlock_engine.documents.sanitize_plan import SanitizeOutput, SanitizePlan
from airlock_engine.masking.sweep import Sweeper

_OOXML = {
    "docx": "Word document",
    "docm": "Word document",
    "xlsx": "Excel workbook",
    "xlsm": "Excel workbook",
    "pptx": "PowerPoint presentation",
    "pptm": "PowerPoint presentation",
}
_IMAGES = {"png": "png", "jpeg": "jpeg", "webp": "webp", "tiff": "tiff"}
_TEXT_FAMILIES = frozenset({Family.TEXT, Family.CONFIG, Family.CODE})


def sanitize_failed() -> errors.AirlockError:
    return errors.AirlockError(
        kind="sanitize_failed",
        message="Airlock could not produce a protected copy of this file. Nothing was "
        "saved, and your original file was not changed.",
        next_step="Try again. If it keeps happening, save the file in another format "
        "(for example PDF or DOCX) and scan that.",
    )


def sanitize_bytes(data: bytes, format_id: str, plan: SanitizePlan) -> SanitizeOutput:
    """Produce the protected copy, then sweep a second time for any value that
    was never found on word edges (so it cannot survive by an edge case)."""
    sweeper = Sweeper(plan.sweep)
    try:
        out = _dispatch(data, format_id, plan, sweeper, 0)
        missing = sweeper.missing()
        if missing and format_id != "pdf" and format_id not in _IMAGES:
            second = _dispatch(
                out.data, format_id, plan.without_structure(), Sweeper(missing, bounded=False), 0
            )
            out.data = second.data
    except RewriteError as exc:
        raise sanitize_failed() from exc
    return out


def _dispatch(
    data: bytes, format_id: str, plan: SanitizePlan, sweeper: Sweeper, depth: int
) -> SanitizeOutput:
    if format_id in _OOXML:
        from airlock_engine.documents.ooxml.sanitize import sanitize_ooxml

        return sanitize_ooxml(
            data, _OOXML[format_id], plan, sweeper, depth=depth, recurse=_dispatch
        )
    if format_id == "pdf":
        from airlock_engine.documents.pdf.rebuild import build_pdf

        removed = [("pdf_hidden", "Comments, form values, attachments, bookmarks and properties")]
        return SanitizeOutput(build_pdf(plan.pdf_pages), removed, "pdf")
    if format_id in _IMAGES:
        from airlock_engine.documents.images.sanitize import sanitize_image

        paint = {path: boxes for (part, path), boxes in plan.paint.items() if part == "frame"}
        clean, had_metadata = sanitize_image(data, _IMAGES[format_id], paint)
        removed = [("metadata", "Image metadata (EXIF, GPS, text)")] if had_metadata else []
        return SanitizeOutput(clean, removed)
    if format_id in ("csv", "tsv"):
        from airlock_engine.documents.text.sanitize import sanitize_text

        return SanitizeOutput(sanitize_text(data, plan, sweeper))
    spec = next((s for s in formats.all_specs() if s.format_id == format_id), None)
    if spec is not None and spec.family in _TEXT_FAMILIES:
        from airlock_engine.documents.text.sanitize import sanitize_text

        return SanitizeOutput(sanitize_text(data, plan, sweeper))
    raise errors.unsupported_format(format_id)
