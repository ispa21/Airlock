from __future__ import annotations

import io
import zipfile

import pytest

import builders
from airlock_engine.core.errors import AirlockError
from airlock_engine.core.models import SegmentKind as K
from airlock_engine.extraction.pipeline import extract_bytes
from conftest import kinds_of


def extract(data: bytes, fmt: str, ocr=None):  # type: ignore[no-untyped-def]
    return extract_bytes(data, fmt, ocr_factory=(lambda: ocr) if ocr else None)


# ---------------------------------------------------------------------- DOCX
@pytest.fixture(scope="module")
def docx_doc():  # type: ignore[no-untyped-def]
    return extract(builders.build_docx(), "docx")


@pytest.mark.parametrize(
    ("canary", "kind"),
    [
        ("CANARY_BODY", K.BODY),
        ("CANARY_TABLE", K.BODY),
        ("CANARY_HEADER", K.HEADER_FOOTER),
        ("CANARY_FOOTER", K.HEADER_FOOTER),
        ("CANARY_COMMENT", K.COMMENT),
        ("CANARY_COMMENT_AUTHOR", K.METADATA),
        ("CANARY_PROP_AUTHOR", K.METADATA),
        ("CANARY_PROP_EDITOR", K.METADATA),
        ("CANARY_PROP_DESCRIPTION", K.METADATA),
        ("CANARY_DELETED", K.TRACKED_CHANGE),
        ("CANARY_REVIEWER", K.METADATA),
        ("CANARY_ALT_TEXT", K.ALT_TEXT),
        ("CANARY_DOCVAR", K.HIDDEN),
        ("CANARY_CUSTOMXML", K.METADATA),
        ("CANARY_TEXTBOX", K.BODY),
    ],
)
def test_docx_every_hidden_place_is_extracted(docx_doc, canary: str, kind: K) -> None:  # type: ignore[no-untyped-def]
    assert kind in kinds_of(docx_doc, canary), kinds_of(docx_doc, canary)


def test_docx_runs_are_joined_into_one_paragraph(docx_doc) -> None:  # type: ignore[no-untyped-def]
    texts = [s.text for s in docx_doc.segments]
    assert "Customer Rahul Sharma CANARY_BODY" in texts


def test_docx_text_box_is_not_duplicated_into_outer_paragraph(docx_doc) -> None:  # type: ignore[no-untyped-def]
    holders = [s.text for s in docx_doc.segments if "CANARY_TEXTBOX" in s.text]
    assert holders == ["CANARY_TEXTBOX"]
    assert any(s.text == "OUTER_PARAGRAPH" for s in docx_doc.segments)


def test_docx_field_codes_and_external_links(docx_doc) -> None:  # type: ignore[no-untyped-def]
    assert any(
        "mailto:canary.field@example.invalid" in s.text and s.kind is K.FIELD
        for s in docx_doc.segments
    )
    assert any(
        s.text == "https://canary-link.example.invalid/x" and s.kind is K.LINK
        for s in docx_doc.segments
    )


def test_docx_embedded_workbook_is_extracted_recursively(docx_doc) -> None:  # type: ignore[no-untyped-def]
    (segment,) = [s for s in docx_doc.segments if "CANARY_EMBEDDED_XLSX" in s.text]
    assert segment.locator.part.startswith("word/embeddings/Microsoft_Excel_Worksheet1.xlsx!/")
    assert segment.label.startswith("Embedded file")
    assert docx_doc.counts["embedded"] == 1


def test_docx_macros_are_reported_not_ignored(docx_doc) -> None:  # type: ignore[no-untyped-def]
    assert ("macro", "Macros (VBA project)") in {(u.kind, u.label) for u in docx_doc.unextracted}


def test_docx_labels_and_locators_never_contain_content(docx_doc) -> None:  # type: ignore[no-untyped-def]
    for segment in docx_doc.segments:
        assert "CANARY" not in segment.label
        assert "CANARY" not in segment.locator.part + segment.locator.path


def test_docx_embedded_image_is_ocrd(ocr_provider) -> None:  # type: ignore[no-untyped-def]
    doc = extract(builders.build_docx(with_ocr_image=True), "docx", ocr_provider)
    ocr_text = " ".join(s.text for s in doc.segments if s.kind is K.OCR)
    assert "CANARY OCR IN DOCX" in ocr_text
    assert doc.ocr_used


# ---------------------------------------------------------------------- XLSX
@pytest.fixture(scope="module")
def xlsx_doc():  # type: ignore[no-untyped-def]
    return extract(builders.build_xlsx(), "xlsx")


@pytest.mark.parametrize(
    ("canary", "kind"),
    [
        ("CANARY_CELL", K.BODY),
        ("CANARY_SHARED_STRING", K.BODY),
        ("CANARY_HIDDEN_ROW", K.HIDDEN),
        ("CANARY_HIDDEN_COL", K.HIDDEN),
        ("CANARY_HIDDEN_SHEET", K.HIDDEN),
        ("CANARY_ORPHAN_STRING", K.HIDDEN),
        ("CANARY_PIVOT_CACHE", K.HIDDEN),
        ("CANARY_CELL_COMMENT", K.COMMENT),
        ("CANARY_NOTE_AUTHOR", K.COMMENT),
        ("CANARY_FORMULA", K.FIELD),
        ("CANARY_DV", K.FIELD),
        ("CANARY_PRINT_HEADER", K.HEADER_FOOTER),
        ("CANARY_NAMED_RANGE", K.NAME),
        ("CANARY_DB_PASSWORD", K.LINK),
        ("CANARY_XLSX_AUTHOR", K.METADATA),
    ],
)
def test_xlsx_every_hidden_place_is_extracted(xlsx_doc, canary: str, kind: K) -> None:  # type: ignore[no-untyped-def]
    assert kind in kinds_of(xlsx_doc, canary), kinds_of(xlsx_doc, canary)


def test_xlsx_cells_have_locators_labels_and_header_context(xlsx_doc) -> None:  # type: ignore[no-untyped-def]
    cells = {
        s.locator.path: s for s in xlsx_doc.segments if s.locator.part == "xl/worksheets/sheet1.xml"
    }
    assert cells["B2"].text == "234567890123"  # number kept as digits, matchable as Aadhaar
    assert cells["B2"].context == "Aadhaar"
    assert cells["B2"].label == "Sheet 1 · B2"
    assert cells["A3"].label.endswith("(hidden)")
    assert cells["A1"].context == ""  # headers have no header


def test_xlsx_sheet_count_and_links(xlsx_doc) -> None:  # type: ignore[no-untyped-def]
    assert xlsx_doc.counts["sheets"] == 2
    assert any(
        "canary-xlsx-link.example.invalid" in s.text and s.kind is K.LINK for s in xlsx_doc.segments
    )


def test_xlsx_number_normalisation() -> None:
    from airlock_engine.documents.xlsx.adapter import _normalize_number

    assert _normalize_number("1.23456789012E+11") == "123456789012"
    assert _normalize_number("9876543210") == "9876543210"
    assert _normalize_number("1.5E+2") == "150"
    assert _normalize_number("1.25E-3") == "1.25E-3"


# ---------------------------------------------------------------------- PPTX
@pytest.fixture(scope="module")
def pptx_doc():  # type: ignore[no-untyped-def]
    return extract(builders.build_pptx(), "pptx")


@pytest.mark.parametrize(
    ("canary", "kind"),
    [
        ("CANARY_SLIDE_TITLE", K.BODY),
        ("CANARY_SLIDE_BODY", K.BODY),
        ("CANARY_PPT_TABLE", K.BODY),
        ("CANARY_SPEAKER_NOTES", K.NOTE),
        ("CANARY_HIDDEN_SLIDE", K.HIDDEN),
        ("CANARY_CHART_CATEGORY", K.CHART),
        ("CANARY_PPT_COMMENT", K.COMMENT),
        ("CANARY_PPT_COMMENTER", K.METADATA),
        ("CANARY_PPT_AUTHOR", K.METADATA),
    ],
)
def test_pptx_every_hidden_place_is_extracted(pptx_doc, canary: str, kind: K) -> None:  # type: ignore[no-untyped-def]
    assert kind in kinds_of(pptx_doc, canary), kinds_of(pptx_doc, canary)


def test_pptx_slide_labels_follow_presentation_order(pptx_doc) -> None:  # type: ignore[no-untyped-def]
    labels = {s.label for s in pptx_doc.segments if s.text.startswith("CANARY_")}
    assert "Slide 1 · paragraph 1" in labels
    assert "Slide 1 notes · paragraph 1" in labels
    assert "Slide 3 (hidden) · paragraph 1" in labels
    assert pptx_doc.counts["slides"] == 3


def test_pptx_chart_workbook_is_extracted_recursively(pptx_doc) -> None:  # type: ignore[no-untyped-def]
    embedded = [
        s for s in pptx_doc.segments if "CANARY_CHART_CATEGORY" in s.text and "!/" in s.locator.part
    ]
    assert embedded, "chart data workbook should be extracted"


def test_pptx_default_object_names_are_not_reported(pptx_doc) -> None:  # type: ignore[no-untyped-def]
    assert not any(s.text in ("Title 1", "Content Placeholder 2") for s in pptx_doc.segments)


# ------------------------------------------------------------------- hostile
def _zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, body in entries.items():
            z.writestr(name, body)
    return buffer.getvalue()


def test_zip_bomb_is_refused() -> None:
    bomb = _zip(
        {"[Content_Types].xml": b"<Types/>", "word/document.xml": b"\x00" * (64 * 1024 * 1024)}
    )
    with pytest.raises(AirlockError) as info:
        extract(bomb, "docx")
    assert info.value.kind == "unsafe_archive"


def test_too_many_entries_is_refused() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for i in range(20_001):
            z.writestr(f"x/{i}", b"")
    with pytest.raises(AirlockError) as info:
        extract(buffer.getvalue(), "docx")
    assert info.value.kind == "unsafe_archive"


def test_entity_expansion_bomb_is_not_expanded() -> None:
    entities = ['<!ENTITY lol0 "lol">']
    entities += [f'<!ENTITY lol{i} "{f"&lol{i - 1};" * 10}">' for i in range(1, 10)]
    lol = (
        f'<?xml version="1.0"?><!DOCTYPE lolz [{"".join(entities)}]>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        "<w:body><w:p><w:r><w:t>&lol9;</w:t></w:r></w:p></w:body></w:document>"
    ).encode()
    data = builders.rewrite_zip(builders.build_docx(), replace={"word/document.xml": lol})
    doc = extract(data, "docx")
    assert sum(len(s.text) for s in doc.segments) < 200_000  # nothing was expanded
