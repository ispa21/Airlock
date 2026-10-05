from __future__ import annotations

import io

import pytest
from PIL import Image
from PIL.PngImagePlugin import PngInfo

import builders
from airlock_engine.core.errors import AirlockError
from airlock_engine.core.models import SegmentKind as K
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.pipeline import extract_bytes
from conftest import canaries, kinds_of


def extract(data: bytes, fmt: str, provider=None, **options):  # type: ignore[no-untyped-def]
    return extract_bytes(
        data,
        fmt,
        ExtractionOptions(**options),
        ocr_factory=(lambda: provider) if provider else None,
    )


# ----------------------------------------------------------------------- PDF
@pytest.fixture(scope="module")
def pdf_doc():  # type: ignore[no-untyped-def]
    attachment = b"name,pan\nCANARY_ATTACHED_ROW,ABCDE1234F\n"
    return extract(builders.build_pdf(attachment=attachment), "pdf")


@pytest.mark.parametrize(
    ("canary", "kind"),
    [
        ("CANARY_PDF_BODY", K.BODY),
        ("CANARY_PDF_PAGE2", K.BODY),
        ("CANARY_PDF_AUTHOR", K.METADATA),
        ("CANARY_PDF_TITLE", K.METADATA),
        ("CANARY_BOOKMARK", K.NAME),
        ("CANARY_PDF_COMMENT", K.COMMENT),
        ("CANARY_FORM_VALUE", K.BODY),
        ("CANARY_ATTACHED_ROW", K.BODY),
    ],
)
def test_pdf_every_hidden_place_is_extracted(pdf_doc, canary: str, kind: K) -> None:  # type: ignore[no-untyped-def]
    assert kind in kinds_of(pdf_doc, canary), kinds_of(pdf_doc, canary)


def test_pdf_pages_links_and_attachment_locators(pdf_doc) -> None:  # type: ignore[no-untyped-def]
    assert pdf_doc.counts["pages"] == 2
    assert any(
        s.text == "https://canary-pdf-link.example.invalid/" and s.kind is K.LINK
        for s in pdf_doc.segments
    )
    assert any(s.text == "pan_number" and s.kind is K.NAME for s in pdf_doc.segments)
    (attached,) = [s for s in pdf_doc.segments if s.text == "CANARY_ATTACHED_ROW"]
    assert attached.locator.part == "attachment/0!/table"
    assert attached.context == "name"
    page1 = next(s for s in pdf_doc.segments if "CANARY_PDF_BODY" in s.text)
    assert (page1.locator.part, page1.locator.path, page1.label) == ("page", "0", "Page 1")


def test_pdf_incremental_revisions_are_reported() -> None:
    import pypdfium2 as pdfium

    pdf = pdfium.PdfDocument(builders.build_pdf())
    buffer = io.BytesIO()
    pdf.save(buffer, flags=pdfium.raw.FPDF_INCREMENTAL)
    pdf.close()
    doc = extract(buffer.getvalue(), "pdf")
    assert "revisions" in {u.kind for u in doc.unextracted}


def test_pdf_scripts_are_reported() -> None:
    doc = extract(builders.build_pdf() + b"\n% /JavaScript\n", "pdf")
    assert "script" in {u.kind for u in doc.unextracted}


def test_encrypted_pdf_is_explained() -> None:
    with pytest.raises(AirlockError) as info:
        extract(builders.build_encrypted_pdf(), "pdf")
    assert info.value.kind == "encrypted_document"


def test_corrupt_pdf_is_explained() -> None:
    with pytest.raises(AirlockError) as info:
        extract(b"%PDF-1.7\n" + b"\x00garbage" * 50, "pdf")
    assert info.value.kind == "extraction_failed"
    assert "PDF" in info.value.message


def test_page_limit() -> None:
    with pytest.raises(AirlockError) as info:
        extract(builders.build_pdf(), "pdf", max_pages=1)
    assert info.value.kind == "content_too_large"


def test_scanned_pdf_page_is_ocrd(ocr_provider) -> None:  # type: ignore[no-untyped-def]
    doc = extract(builders.build_pdf(scanned_page=True), "pdf", ocr_provider)
    (scanned,) = [s for s in doc.segments if s.kind is K.OCR]
    assert "SCANNED CANARY PAGE 2024" in scanned.text
    assert scanned.label == "Page 3 (scanned)"
    assert scanned.boxes and scanned.boxes[0].x1 > scanned.boxes[0].x0


def test_ocr_disabled_reports_unread_pages() -> None:
    doc = extract(builders.build_pdf(scanned_page=True), "pdf", None, ocr=False)
    assert ("image", "Page 3 (scanned)") in {(u.kind, u.label) for u in doc.unextracted}


# -------------------------------------------------------------------- images
def _png_with_text_chunk() -> bytes:
    info = PngInfo()
    info.add_text("Author", "CANARY_PNG_AUTHOR")
    buffer = io.BytesIO()
    builders.text_image("Invoice for Rahul Sharma").save(buffer, "PNG", pnginfo=info)
    return buffer.getvalue()


def _jpeg_with_exif() -> bytes:
    image = builders.text_image("Contract 2024")
    exif = image.getexif()
    exif[315] = "CANARY_ARTIST"
    exif[40093] = "CANARY_XP_AUTHOR".encode("utf-16-le") + b"\x00\x00"
    gps = exif.get_ifd(0x8825)
    gps.update({1: "N", 2: (18.0, 31.0, 13.44), 3: "E", 4: (73.0, 51.0, 24.12)})
    buffer = io.BytesIO()
    image.save(buffer, "JPEG", exif=exif, comment=b"CANARY_JPEG_COMMENT")
    return buffer.getvalue()


def test_png_ocr_and_text_chunks(ocr_provider) -> None:  # type: ignore[no-untyped-def]
    doc = extract(_png_with_text_chunk(), "png", ocr_provider)
    (ocr,) = [s for s in doc.segments if s.kind is K.OCR]
    assert ocr.text == "Invoice for Rahul Sharma"
    assert ocr.label == "Text in image"
    assert "CANARY_PNG_AUTHOR" in canaries(doc, K.METADATA)


def test_jpeg_exif_gps_and_comment_without_ocr() -> None:
    doc = extract(_jpeg_with_exif(), "jpeg", None, ocr=False)
    assert {"CANARY_ARTIST", "CANARY_XP_AUTHOR", "CANARY_JPEG_COMMENT"} <= canaries(doc, K.METADATA)
    (gps,) = [s for s in doc.segments if s.label == "Location where the photo was taken"]
    assert gps.text.startswith("18.52") and "73.85" in gps.text


def test_multipage_tiff_and_webp(ocr_provider) -> None:  # type: ignore[no-untyped-def]
    pages = [builders.text_image("FIRST PAGE TEXT"), builders.text_image("SECOND PAGE TEXT")]
    buffer = io.BytesIO()
    pages[0].save(buffer, "TIFF", save_all=True, append_images=pages[1:])
    doc = extract(buffer.getvalue(), "tiff", ocr_provider)
    assert doc.counts["pages"] == 2
    assert [s.label for s in doc.segments if s.kind is K.OCR] == ["Page 1 text", "Page 2 text"]
    assert "SECOND PAGE TEXT" in doc.segments[-1].text

    webp = io.BytesIO()
    builders.text_image("WEBP CANARY TEXT").save(webp, "WEBP", quality=95)
    assert "WEBP CANARY TEXT" in extract(webp.getvalue(), "webp", ocr_provider).segments[0].text


def test_decompression_bomb_is_refused() -> None:
    buffer = io.BytesIO()
    Image.new("1", (20_000, 12_000)).save(buffer, "PNG")  # 240 MP, tiny file
    with pytest.raises(AirlockError) as info:
        extract(buffer.getvalue(), "png")
    assert info.value.kind == "content_too_large"


def test_truncated_image_is_explained() -> None:
    data = _png_with_text_chunk()
    with pytest.raises(AirlockError) as info:
        extract(data[: len(data) // 3], "png")
    assert info.value.kind == "extraction_failed"
