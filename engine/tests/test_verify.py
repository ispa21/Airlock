"""Verification of protected copies and safe export (Phase 7), unit level."""

from __future__ import annotations

import io
import json
import os
import zipfile
from pathlib import Path

import pytest

from airlock_engine.core import errors
from airlock_engine.core.models import (
    ExtractedDocument,
    Locator,
    SegmentKind,
    TextSegment,
    UnextractedPart,
)
from airlock_engine.detectors.pipeline import DetectionEngine
from airlock_engine.scan.report import entity_info
from airlock_engine.verification.export import validate_destination, write_atomically
from airlock_engine.verification.raw import part_label, raw_hits
from airlock_engine.verification.verifier import (
    FAILED,
    PASSED,
    REVIEW,
    CopyCheck,
    Verification,
    ai_text,
    evaluate,
    normalize,
)

EMAIL = "priya.r@example.invalid"
NAME = "Priya Raghavan"
CARD = "4111 1111 1111 1111"


def segment(
    i: int, text: str, kind: SegmentKind = SegmentKind.BODY, part: str = "word/document.xml"
) -> TextSegment:
    return TextSegment(i, text, Locator(part, f"p/{i}"), kind, f"Body · paragraph {i + 1}")


def document(*texts: str, unextracted: tuple[UnextractedPart, ...] = ()) -> ExtractedDocument:
    return ExtractedDocument(
        "docx", tuple(segment(i, t) for i, t in enumerate(texts)), unextracted=unextracted
    )


def check(
    texts: list[str],
    protected: list[tuple[str, str]],
    *,
    replacements: tuple[str, ...] = (),
    kept: tuple[str, ...] = (),
    raw: list[tuple[int, str]] | None = None,
    unextracted: tuple[UnextractedPart, ...] = (),
) -> Verification:
    doc = document(*texts, unextracted=unextracted)
    outcome = DetectionEngine().run(doc)
    return evaluate(
        doc,
        raw or [],
        outcome.detected,
        CopyCheck(
            protected,
            frozenset(replacements),
            frozenset(normalize(k) for k in kept),
            use_ner=False,
            ocr=False,
        ),
        entity_info({}),
    )


PROTECTED = [(EMAIL, "EMAIL"), (NAME, "PERSON")]


def test_a_clean_copy_passes() -> None:
    result = check(
        ["Contact [PERSON_1] at [EMAIL_1]."],
        PROTECTED,
        replacements=("[EMAIL_1]", "[PERSON_1]"),
    )
    assert result.status == PASSED
    assert result.to_json()["checked"]["protected_values"] == 2


def test_a_protected_value_left_in_the_text_fails() -> None:
    result = check([f"Contact {NAME} at [EMAIL_1]."], PROTECTED, replacements=("[EMAIL_1]",))
    assert result.status == FAILED
    (row,) = result.leaks
    assert row.entity_type == "PERSON" and row.location_label == "Body · paragraph 1"
    assert NAME not in json.dumps(result.to_json())


def test_letter_case_and_word_edges() -> None:
    assert check([NAME.upper()], PROTECTED).status == FAILED
    short = [("Ram", "PERSON")]
    assert check(["Add more RAM to the server."], short).status == PASSED
    assert check(["Ramesh will call."], short).status == PASSED
    assert check(["Ram will call."], short).status == FAILED


def test_the_same_number_written_differently_fails() -> None:
    result = check(["Card on file: 4111-1111-1111-1111."], [(CARD, "CREDIT_CARD")])
    assert result.status == FAILED
    assert result.leaks[0].preview.endswith("1111") and "4111" not in result.leaks[0].preview


def test_text_airlock_inserted_is_not_a_leak() -> None:
    result = check(
        ["Hello Sam Example, meet Avery Sample."],
        [("Sam", "PERSON")],
        replacements=("Sam Example", "Avery Sample"),
    )
    assert result.status == PASSED


def test_a_value_only_in_the_stored_bytes_fails() -> None:
    result = check(["Nothing here."], PROTECTED, raw=[(0, "word/settings.xml")])
    assert result.status == FAILED
    (row,) = result.leaks
    assert row.location_kind == "file_data"
    assert row.location_label == "Stored inside the file (word/settings.xml)"


def test_kept_values_and_replacements_are_expected() -> None:
    result = check(
        [f"Write to {EMAIL} or visit https://example.invalid/link-1 today."],
        [("https://acme.example/x", "URL")],
        replacements=("https://example.invalid/link-1",),
        kept=(EMAIL,),
    )
    assert result.status == PASSED
    assert (result.kept_count, result.replacement_count) == (1, 1)


def test_new_findings_need_review() -> None:
    result = check(["Escalate to other.person@example.invalid."], PROTECTED)
    assert result.status == REVIEW
    (row,) = result.new
    assert row.reason == "new" and row.entity_type == "EMAIL"
    assert "other.person" not in row.preview
    assert result.to_json()["new_count"] == 1 and result.to_json()["remaining_count"] == 0


def test_content_that_cannot_be_checked_fails() -> None:
    result = check(
        ["Clean."],
        PROTECTED,
        unextracted=(UnextractedPart("macro", "Macros (VBA project)"),) * 2,
    )
    assert result.status == FAILED
    assert result.to_json()["unreadable"] == [{"label": "Macros (VBA project)", "count": 2}]


def _zip(parts: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    return buffer.getvalue()


def test_raw_search_reads_every_part_and_embedded_packages() -> None:
    inner = _zip({"word/document.xml": b"<w:t>Escalate to Priya Raghavan</w:t>"})
    package = _zip(
        {
            "word/document.xml": b"<w:t>[PERSON_1]</w:t>",
            "word/settings.xml": b'<w:docVar w:val="Acme &amp; Sons"/>',
            "word/theme/theme1.xml": b'<a:font script="Yiii" typeface="Microsoft Yi Baiti"/>',
            "word/fontTable.xml": b'<w:font w:name="Microsoft Sans Serif"/>',
            "word/embeddings/Microsoft_Word_Document.docx": inner,
            "customXml/item1.xml": b"<x>Sam Example</x>",
        }
    )
    hits = raw_hits(
        package, ["Acme & Sons", NAME, "Microsoft", "Sam"], replacements=["Sam Example"]
    )
    assert hits == [
        (0, "word/settings.xml"),
        (1, "word/embeddings/Microsoft_Word_Document.docx/word/document.xml"),
    ]
    # Short plain words are checked in the extracted text, not in markup.
    styles = _zip({"word/styles.xml": b'<w:shd w:themeFillShade="CC"/>'})
    assert raw_hits(styles, ["CC"]) == []


def test_raw_search_on_plain_and_utf16_files() -> None:
    assert raw_hits(f"name={NAME}\n".encode(), [NAME]) == [(0, "file")]
    assert raw_hits(NAME.encode("utf-16-le"), [NAME]) == []  # no BOM: not read as text
    assert raw_hits(b"\xff\xfe" + NAME.encode("utf-16-le"), [NAME]) == [(0, "file")]
    assert raw_hits(b"anything", []) == []


def test_part_labels_are_never_document_text() -> None:
    assert part_label("xl/worksheets/sheet1.xml") == "xl/worksheets/sheet1.xml"
    assert part_label("word/media/Priya's passport.png") == "a part of the file"
    assert part_label("x" * 200) == "a part of the file"


def test_ai_text_keeps_reading_order_and_table_rows() -> None:
    cells = [("A1", "Name"), ("B1", "Amount"), ("A2", "[PERSON_1]"), ("C2", "100")]
    segments = [
        segment(0, "Quarterly summary"),
        segment(1, "Reviewer note", SegmentKind.COMMENT),
        segment(2, "Author", SegmentKind.METADATA),
        *[
            TextSegment(
                3 + i,
                text,
                Locator("xl/worksheets/sheet1.xml", ref),
                SegmentKind.BODY,
                f"Payroll · {ref}",
            )
            for i, (ref, text) in enumerate(cells)
        ],
        TextSegment(9, "a", Locator("table", "r1c1"), SegmentKind.BODY, "Row 1 · Column A"),
        TextSegment(10, "b", Locator("table", "r1c2"), SegmentKind.BODY, "Row 1 · Column B"),
    ]
    text = ai_text(ExtractedDocument("xlsx", tuple(segments)))
    assert text == "Quarterly summary\n\nPayroll\nName\tAmount\n[PERSON_1]\t\t100\n\na\tb\n"


def test_destination_rules(tmp_path: Path) -> None:
    original = tmp_path / "Contract.docx"
    original.write_bytes(b"original")
    private = tmp_path / "airlock-data"
    private.mkdir()

    def validate(raw: object, extension: str = "docx") -> Path:
        return validate_destination(
            raw, extension=extension, never=[original], private_folders=[private]
        )

    good = tmp_path / "Contract (Airlock protected).docx"
    assert validate(str(good)) == good
    assert validate(str(tmp_path / "notes.TXT"), "txt").name == "notes.TXT"
    cases: list[tuple[object, str]] = [
        ("Contract.docx", "export_destination_invalid"),
        (None, "export_destination_invalid"),
        (str(tmp_path / "copy.pdf"), "export_wrong_extension"),
        (str(tmp_path / "missing" / "copy.docx"), "export_destination_invalid"),
        (str(original), "export_would_overwrite_original"),
        (str(private / "copy.docx"), "export_destination_invalid"),
        (str(tmp_path / "a\x00.docx"), "export_destination_invalid"),
    ]
    folder = tmp_path / "folder.docx"
    folder.mkdir()
    cases.append((str(folder), "export_destination_invalid"))
    if os.name == "posix":
        link = tmp_path / "link.docx"
        link.symlink_to(original)
        cases.append((str(link), "export_destination_invalid"))
    for raw, kind in cases:
        with pytest.raises(errors.AirlockError) as caught:
            validate(raw)
        assert caught.value.kind == kind, raw
        assert str(tmp_path) not in caught.value.message


def test_atomic_write_replaces_and_leaves_nothing_behind(tmp_path: Path) -> None:
    target = tmp_path / "copy.docx"
    write_atomically(target, b"first")
    write_atomically(target, b"second")
    assert target.read_bytes() == b"second"
    assert [p.name for p in tmp_path.iterdir()] == ["copy.docx"]


@pytest.mark.skipif(os.name != "posix" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_atomic_write_reports_a_read_only_folder(tmp_path: Path) -> None:
    folder = tmp_path / "locked"
    folder.mkdir()
    folder.chmod(0o500)
    try:
        with pytest.raises(errors.AirlockError) as caught:
            write_atomically(folder / "copy.docx", b"x")
        assert caught.value.kind == "export_not_permitted"
    finally:
        folder.chmod(0o700)
