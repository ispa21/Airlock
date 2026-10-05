"""Routes bytes to the right adapter. Runs inside the isolated worker process."""

from __future__ import annotations

import io
import zipfile
from collections.abc import Callable

from airlock_engine.core import errors
from airlock_engine.core.interfaces import DocumentAdapter, OcrProvider
from airlock_engine.core.models import ExtractedDocument
from airlock_engine.documents import formats
from airlock_engine.documents.formats import Family, Support
from airlock_engine.extraction.context import ExtractionContext, ExtractionOptions, ProgressFn

_TEXT_FAMILIES = frozenset({Family.TEXT, Family.CONFIG, Family.CODE})


def adapter_for(format_id: str) -> DocumentAdapter:
    """Import lazily so heavy libraries load only for the formats in use."""
    if format_id == "pdf":
        from airlock_engine.documents.pdf.adapter import PdfAdapter

        return PdfAdapter()
    if format_id in ("docx", "docm"):
        from airlock_engine.documents.docx.adapter import DocxAdapter

        return DocxAdapter()
    if format_id in ("xlsx", "xlsm"):
        from airlock_engine.documents.xlsx.adapter import XlsxAdapter

        return XlsxAdapter()
    if format_id in ("pptx", "pptm"):
        from airlock_engine.documents.pptx.adapter import PptxAdapter

        return PptxAdapter()
    if format_id in ("csv", "tsv"):
        from airlock_engine.documents.text.adapter import DelimitedTextAdapter

        return DelimitedTextAdapter(tab_separated=format_id == "tsv")
    if format_id in ("png", "jpeg", "webp", "tiff"):
        from airlock_engine.documents.images.adapter import ImageAdapter

        return ImageAdapter()
    spec = next((s for s in formats.all_specs() if s.format_id == format_id), None)
    if spec is not None and spec.family in _TEXT_FAMILIES:
        from airlock_engine.documents.text.adapter import PlainTextAdapter

        return PlainTextAdapter()
    raise errors.unsupported_format(format_id)


def _default_ocr() -> OcrProvider:
    from airlock_engine.extraction.ocr import default_ocr_provider

    return default_ocr_provider()


def extract_bytes(
    data: bytes,
    format_id: str,
    options: ExtractionOptions | None = None,
    *,
    progress: ProgressFn | None = None,
    ocr_factory: Callable[[], OcrProvider] | None = _default_ocr,
) -> ExtractedDocument:
    ctx = ExtractionContext(
        options,
        progress=progress,
        ocr_factory=ocr_factory,
        embedded_handler=_extract_embedded,
    )
    adapter_for(format_id).extract(data, ctx)
    return ctx.build(format_id)


def _embedded_format(data: bytes, name: str) -> str | None:
    head = data[:65536]
    names: set[str] | None = None
    if head.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = set(archive.namelist()[:20_000])
        except (zipfile.BadZipFile, ValueError, EOFError):
            return None
    detected = formats.detect_format(head, names)
    if detected is not None:
        return detected
    spec = formats.spec_for_extension(formats.extension_of_name(name))
    if spec is not None and spec.family in _TEXT_FAMILIES | {Family.SPREADSHEET}:
        try:
            formats.sniff_stream(io.BytesIO(data), spec, spec.extensions[0])
        except errors.AirlockError:
            return None
        return spec.format_id
    return None


def _extract_embedded(
    ctx: ExtractionContext, data: bytes, name: str, part: str, label: str
) -> None:
    format_id = _embedded_format(data, name)
    spec = next((s for s in formats.all_specs() if s.format_id == format_id), None)
    if spec is None or spec.support is not Support.AVAILABLE:
        ctx.unextracted("embedded_object", label)
        return
    if spec.family is Family.IMAGE:
        from airlock_engine.documents.imaging import open_image

        try:
            image = open_image(data)
        except errors.AirlockError:
            ctx.unextracted("image", label)
            return
        ctx.ocr_image(image, part, "0", label=label, embedded=True)
        return
    with ctx.nested(part, label):
        try:
            adapter_for(spec.format_id).extract(data, ctx)
        except errors.AirlockError as exc:
            if exc.kind in ("content_too_large", "unsafe_archive"):
                raise
            ctx.unextracted("embedded_object", "unreadable")
        except MemoryError:
            raise
        except Exception:  # a broken embedded file must not abort the host document
            ctx.unextracted("embedded_object", "unreadable")
