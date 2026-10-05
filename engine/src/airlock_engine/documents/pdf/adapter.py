"""PDF documents via PDFium (pypdfium2, Apache-2.0/BSD-3).

Besides page text this reads everything a PDF can hide: document info and XMP
metadata, bookmarks, annotation comments and their authors, form field
values, link targets, file attachments (extracted recursively), and text in
images (scanned pages are rendered and OCR'd; pictures on text pages are
OCR'd individually). Earlier revisions kept by incremental saves and
embedded scripts cannot be read, so they are reported.
"""

from __future__ import annotations

import contextlib
import ctypes
import re
from typing import Any, Final

from airlock_engine.core import errors
from airlock_engine.core.interfaces import DocumentAdapter
from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.ooxml.package import XmlUnreadable, parse_xml
from airlock_engine.documents.ooxml.text import extract_part
from airlock_engine.extraction.context import ExtractionContext

_LABEL: Final = "PDF document"
#: Pages with less text than this are treated as scanned and OCR'd.
_SCANNED_PAGE_CHARS: Final = 16
_OCR_DPI: Final = 300
_MIN_IMAGE_PX: Final = 64
_MAX_BOOKMARKS: Final = 10_000
_XMP: Final = re.compile(rb"<x:xmpmeta[\s\S]{0,4000000}?</x:xmpmeta>")
_METADATA_KEYS: Final = ("Title", "Author", "Subject", "Keywords", "Creator", "Producer")


def _utf16_value(fn: Any, *args: Any) -> str:
    """Call a PDFium getter that fills a UTF-16LE buffer (two-call pattern)."""
    import pypdfium2.raw as raw

    size = fn(*args, None, 0)
    if size <= 2:
        return ""
    buffer = (ctypes.c_ubyte * size)()
    fn(*args, ctypes.cast(buffer, ctypes.POINTER(raw.FPDF_WCHAR)), size)
    return bytes(buffer).decode("utf-16-le", errors="replace").rstrip("\x00")


class PdfAdapter(DocumentAdapter):
    formats = ("pdf",)

    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        import pypdfium2 as pdfium
        import pypdfium2.raw as raw

        try:
            pdf = pdfium.PdfDocument(data)
        except pdfium.PdfiumError as exc:
            if getattr(exc, "err_code", None) in (raw.FPDF_ERR_PASSWORD, raw.FPDF_ERR_SECURITY):
                raise errors.encrypted_document() from exc
            raise errors.extraction_failed(_LABEL) from exc
        try:
            with contextlib.suppress(pdfium.PdfiumError):
                pdf.init_forms()  # needed to read form field values
            pages = len(pdf)
            if pages > ctx.options.max_pages:
                raise errors.content_too_large(f"more than {ctx.options.max_pages:,} pages")
            ctx.count("pages", pages)
            self._metadata(pdf, ctx)
            self._xmp(data, ctx)
            self._bookmarks(pdf, ctx)
            for index in range(pages):
                ctx.progress("pages", index, pages)
                page = pdf[index]
                try:
                    self._page(pdf, page, index, ctx)
                finally:
                    page.close()
            ctx.progress("pages", pages, pages)
            self._attachments(pdf, ctx)
        except pdfium.PdfiumError as exc:
            raise errors.extraction_failed(_LABEL) from exc
        finally:
            pdf.close()
        self._report_unreadable(data, ctx)

    # ------------------------------------------------------------- document
    @staticmethod
    def _metadata(pdf: Any, ctx: ExtractionContext) -> None:
        info = pdf.get_metadata_dict(skip_empty=True)
        for key in _METADATA_KEYS:
            ctx.add(
                str(info.get(key, "")),
                "info",
                key,
                kind=SegmentKind.METADATA,
                label="Document properties",
            )

    @staticmethod
    def _xmp(data: bytes, ctx: ExtractionContext) -> None:
        for n, match in enumerate(_XMP.finditer(data)):
            if n >= 5:
                break
            try:
                root = parse_xml(match.group(0))
            except XmlUnreadable:
                continue
            extract_part(ctx, root, f"xmp/{n}", kind=SegmentKind.METADATA, label="XMP metadata")

    @staticmethod
    def _bookmarks(pdf: Any, ctx: ExtractionContext) -> None:
        for n, bookmark in enumerate(pdf.get_toc()):
            if n >= _MAX_BOOKMARKS:
                break
            ctx.add(
                bookmark.get_title() or "",
                "outline",
                str(n),
                kind=SegmentKind.NAME,
                label="Bookmarks",
            )

    @staticmethod
    def _attachments(pdf: Any, ctx: ExtractionContext) -> None:
        for k in range(pdf.count_attachments()):
            attachment = pdf.get_attachment(k)
            name = attachment.get_name() or f"attachment-{k + 1}"
            ctx.add(
                name, "attachment", f"{k}/name", kind=SegmentKind.NAME, label="Attachment names"
            )
            payload = attachment.get_data()
            if payload is not None:
                ctx.embedded(bytes(payload), name, f"attachment/{k}", f"Attachment {k + 1}")

    @staticmethod
    def _report_unreadable(data: bytes, ctx: ExtractionContext) -> None:
        saves = data.count(b"%%EOF")
        if b"/Linearized" in data[:4096]:
            saves -= 1  # linearised files legitimately contain two
        if saves > 1:
            ctx.unextracted("revisions", "Earlier versions of this PDF kept inside the file")
        if b"/JavaScript" in data or b"/JS " in data or b"/JS(" in data:
            ctx.unextracted("script", "Embedded scripts")

    # ----------------------------------------------------------------- page
    def _page(self, pdf: Any, page: Any, index: int, ctx: ExtractionContext) -> None:
        import pypdfium2.raw as raw

        number = index + 1
        textpage = page.get_textpage()
        try:
            text = textpage.get_text_range().replace("\r\n", "\n").replace("\r", "\n")
        finally:
            textpage.close()
        ctx.add(text, "page", str(index), label=f"Page {number}")

        if len(text.strip()) < _SCANNED_PAGE_CHARS:
            width, height = page.get_size()
            scale = min(_OCR_DPI / 72, ctx.options.max_ocr_side / max(width, height, 1))
            bitmap = page.render(scale=scale)
            try:
                ctx.ocr_image(
                    bitmap.to_pil(), "page", f"{index}/ocr", label=f"Page {number} (scanned)"
                )
            finally:
                bitmap.close()
        else:
            for k, obj in enumerate(page.get_objects(filter=[raw.FPDF_PAGEOBJ_IMAGE], max_depth=4)):
                w, h = obj.get_px_size()
                if min(w, h) < _MIN_IMAGE_PX:
                    continue
                try:
                    bitmap = obj.get_bitmap(render=True)
                except Exception:  # undecodable image stream
                    ctx.unextracted("image", f"Page {number} image {k + 1}")
                    continue
                try:
                    ctx.ocr_image(
                        bitmap.to_pil(),
                        "page",
                        f"{index}/image/{k}",
                        label=f"Page {number} image {k + 1}",
                        embedded=True,
                    )
                finally:
                    bitmap.close()
        self._annotations(pdf, page, index, ctx)

    @staticmethod
    def _annotations(pdf: Any, page: Any, index: int, ctx: ExtractionContext) -> None:
        import pypdfium2.raw as raw

        number = index + 1
        for j in range(raw.FPDFPage_GetAnnotCount(page)):
            annot = raw.FPDFPage_GetAnnot(page, j)
            if not annot:
                continue
            try:
                subtype = raw.FPDFAnnot_GetSubtype(annot)
                path = f"{index}/annot/{j}"

                def value(key: str, annot: Any = annot) -> str:
                    return _utf16_value(raw.FPDFAnnot_GetStringValue, annot, key.encode())

                ctx.add(
                    value("Contents"),
                    "page",
                    f"{path}/contents",
                    kind=SegmentKind.COMMENT,
                    label=f"Page {number} comments",
                )
                ctx.add(
                    value("Subj"),
                    "page",
                    f"{path}/subject",
                    kind=SegmentKind.COMMENT,
                    label=f"Page {number} comments",
                )
                if subtype == raw.FPDF_ANNOT_WIDGET:
                    ctx.add(
                        value("T"),
                        "page",
                        f"{path}/name",
                        kind=SegmentKind.NAME,
                        label="Form field names",
                    )
                    ctx.add(
                        value("TU"),
                        "page",
                        f"{path}/tooltip",
                        kind=SegmentKind.NAME,
                        label="Form field names",
                    )
                    if pdf.formenv is not None:
                        field_value = _utf16_value(
                            raw.FPDFAnnot_GetFormFieldValue, pdf.formenv, annot
                        )
                        ctx.add(
                            field_value, "page", f"{path}/value", label=f"Page {number} form field"
                        )
                else:
                    ctx.add(
                        value("T"),
                        "page",
                        f"{path}/author",
                        kind=SegmentKind.METADATA,
                        label=f"Page {number} comment authors",
                    )
                link = raw.FPDFAnnot_GetLink(annot)
                action = raw.FPDFLink_GetAction(link) if link else None
                if action:
                    size = raw.FPDFAction_GetURIPath(pdf, action, None, 0)
                    if size > 1:
                        buffer = ctypes.create_string_buffer(size)
                        raw.FPDFAction_GetURIPath(pdf, action, buffer, size)
                        uri = buffer.value.decode("utf-8", errors="replace")
                        ctx.add(
                            uri,
                            "page",
                            f"{path}/uri",
                            kind=SegmentKind.LINK,
                            label=f"Page {number} links",
                        )
            finally:
                raw.FPDFPage_CloseAnnot(annot)
