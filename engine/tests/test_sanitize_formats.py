"""Format sanitizers, in-process: structure preserved, values gone."""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Iterable

import pytest
from PIL import Image

import builders
from airlock_engine.documents.ooxml.package import OoxmlPackage, parse_xml
from airlock_engine.documents.ooxml.rewrite import rewrite_xml
from airlock_engine.documents.sanitize import sanitize_bytes
from airlock_engine.documents.sanitize_plan import SanitizePlan
from airlock_engine.masking.sweep import Sweeper


def plan(sweep: Iterable[tuple[str, str]] = (), **kw: object) -> SanitizePlan:
    return SanitizePlan(sweep=list(sweep), **kw)  # type: ignore[arg-type]


def parts(data: bytes) -> dict[str, bytes]:
    z = zipfile.ZipFile(io.BytesIO(data))
    return {n: z.read(n) for n in z.namelist()}


# --- text ---------------------------------------------------------------------


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig", "utf-16", "cp1252"])
def test_text_keeps_encoding_bom_and_line_endings(encoding: str) -> None:
    text = "Café report\r\nowner: rahul@example.invalid\r\ncc rahul@example.invalid\r\n"
    data = text.encode(encoding)
    out = sanitize_bytes(
        data,
        "txt",
        plan([("rahul@example.invalid", "[EMAIL_1]")], adapter_state={"encoding": encoding}),
    ).data
    assert out.decode(encoding) == text.replace("rahul@example.invalid", "[EMAIL_1]")
    assert out.startswith(data[:3]) if encoding in ("utf-8-sig", "utf-16") else True


def test_text_exact_edits_apply_at_offsets() -> None:
    data = b"key=Xk9mQ2vL7p and Xk9mQ2vL7pZ"
    p = plan([("Xk9mQ2vL7p", "[PASSWORD_1]")], adapter_state={"encoding": "utf-8"})
    p.edits = [("text", "char/0", 4, 14, "[PASSWORD_1]")]
    out = sanitize_bytes(data, "env", p).data
    # The edited span is replaced; the glued copy is caught by the second pass.
    assert out == b"key=[PASSWORD_1] and [PASSWORD_1]Z"


def test_csv_quoted_values_and_structure() -> None:
    data = b'name,secret\r\n"Sharma, Rahul","pa""ss"\r\nOther,x\r\n'
    out = sanitize_bytes(
        data,
        "csv",
        plan(
            [("Sharma, Rahul", "[PERSON_1]"), ('pa"ss', "[PASSWORD_1]")],
            adapter_state={"encoding": "utf-8", "delimiter": ","},
        ),
    ).data
    assert out == b'name,secret\r\n"[PERSON_1]","[PASSWORD_1]"\r\nOther,x\r\n'


# --- OOXML --------------------------------------------------------------------


def _docx(build) -> bytes:  # type: ignore[no-untyped-def]
    import docx

    document = docx.Document()
    build(document)
    out = io.BytesIO()
    document.save(out)
    return out.getvalue()


def test_value_split_across_runs_is_replaced_once() -> None:
    def build(d) -> None:  # type: ignore[no-untyped-def]
        p = d.add_paragraph("Owner: ")
        p.add_run("Ra").bold = True
        p.add_run("hul Sha")
        p.add_run("rma").italic = True
        p.add_run(" (lead)")

    out = sanitize_bytes(_docx(build), "docx", plan([("Rahul Sharma", "[PERSON_1]")])).data
    import docx

    assert docx.Document(io.BytesIO(out)).paragraphs[0].text == "Owner: [PERSON_1] (lead)"


def test_namespace_prefixes_and_ignorable_list_survive() -> None:
    data = _docx(lambda d: d.add_paragraph("Contact rahul@example.invalid"))
    before = parts(data)["word/document.xml"]
    out = parts(sanitize_bytes(data, "docx", plan([("rahul@example.invalid", "[EMAIL_1]")])).data)
    after = out["word/document.xml"]
    ignorable = re.search(rb'mc:Ignorable="([^"]*)"', before)
    assert ignorable is not None and ignorable.group() in after
    for prefix in ignorable.group(1).split():
        assert b"xmlns:" + prefix + b"=" in after
    assert after == before.replace(b"rahul@example.invalid", b"[EMAIL_1]")


def test_entities_and_attributes_are_handled() -> None:
    xml = (
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        b"<w:body><w:p><w:r><w:t>AT&amp;T Phoenix &amp; co</w:t></w:r></w:p>"
        b'<w:comment w:author="AT&amp;T Phoenix" w:id="0"/></w:body></w:document>'
    )
    out = rewrite_xml(xml, Sweeper([("AT&T Phoenix", "[CLIENT_NAME_1]")]))
    parse_xml(out)
    assert b"[CLIENT_NAME_1] &amp; co" in out
    assert b'w:author="[CLIENT_NAME_1]"' in out
    assert b'w:id="0"' in out


def test_external_link_targets_are_swept_internal_ones_untouched() -> None:
    rels = (
        b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        b'<Relationship Id="rId1" Type="t" Target="https://intranet.example.invalid/hr" TargetMode="External"/>'
        b'<Relationship Id="rId2" Type="t" Target="https://intranet.example.invalid/hr"/>'
        b"</Relationships>"
    )
    out = rewrite_xml(rels, Sweeper([("https://intranet.example.invalid/hr", "[URL_1]")]))
    assert out.count(b"[URL_1]") == 1 and b'Id="rId2" Type="t" Target="https://' in out


def test_numeric_cells_become_text_cells() -> None:
    import openpyxl

    wb = openpyxl.Workbook()
    ws = wb.active
    ws["A1"], ws["B1"] = "Aadhaar", "Amount"
    ws["A2"], ws["B2"] = 234567890124, 1000
    buf = io.BytesIO()
    wb.save(buf)
    out = sanitize_bytes(buf.getvalue(), "xlsx", plan([("234567890124", "[AADHAAR_1]")])).data
    sheet = openpyxl.load_workbook(io.BytesIO(out)).active
    assert sheet["A2"].value == "[AADHAAR_1]"
    assert sheet["B2"].value == 1000
    assert b"234567890124" not in b"".join(parts(out).values())


def test_scientific_notation_number_is_matched() -> None:
    xml = (
        b'<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        b'<sheetData><row r="1"><c r="A1"><f>B1*1</f><v>1.23456789012E+11</v></c>'
        b'<c r="B1" t="s"><v>0</v></c></row></sheetData></worksheet>'
    )
    out = rewrite_xml(xml, Sweeper([("123456789012", "[BANK_ACCOUNT_1]")]), spreadsheet=True)
    parse_xml(out)
    assert b'<c t="str" r="A1"><f>B1*1</f><v>[BANK_ACCOUNT_1]</v></c>' in out
    assert b'<c r="B1" t="s"><v>0</v></c>' in out


def test_pivot_cache_numbers_become_strings() -> None:
    xml = (
        b'<pivotCacheRecords xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        b'<r><n v="9876543210"/><s v="Rahul"/></r></pivotCacheRecords>'
    )
    out = rewrite_xml(
        xml, Sweeper([("9876543210", "[PHONE_1]"), ("Rahul", "[PERSON_1]")]), spreadsheet=True
    )
    assert out.endswith(b'<r><s v="[PHONE_1]"/><s v="[PERSON_1]"/></r></pivotCacheRecords>')


def test_macros_thumbnail_and_their_references_are_removed() -> None:
    out = sanitize_bytes(builders.build_docx(), "docx", plan()).data
    names = parts(out)
    assert not any("vbaProject" in n or "thumbnail" in n.lower() for n in names)
    assert b'PartName="/word/vbaProject.bin"' not in names["[Content_Types].xml"]
    # Every internal relationship still points to an existing part.
    pkg = OoxmlPackage(out, "Word document")
    for rels_name in [n for n in names if n.endswith(".rels")]:
        source = "" if rels_name == "_rels/.rels" else rels_name.replace("_rels/", "")[:-5]
        for rel in pkg.relationships(source):
            assert rel.external or pkg.has(rel.target), (rels_name, rel.target)


def test_unreadable_pictures_are_blanked() -> None:
    data = builders.rewrite_zip(
        _docx(lambda d: d.add_paragraph("x")),
        add={"word/media/logo.emf": b"\x01\x00\x00\x00" + b"CANARY_EMF_TEXT" * 20},
    )
    out = parts(sanitize_bytes(data, "docx", plan()).data)
    assert b"CANARY" not in out["word/media/logo.emf"]
    Image.open(io.BytesIO(out["word/media/logo.emf"]))  # a valid (blank) EMF


def test_untouched_parts_are_byte_identical() -> None:
    data = _docx(lambda d: d.add_paragraph("Nothing sensitive here"))
    before, after = parts(data), parts(sanitize_bytes(data, "docx", plan([("zzz", "[X]")])).data)
    for name in ("word/document.xml", "word/styles.xml", "[Content_Types].xml"):
        assert after[name] == before[name]


# --- images ---------------------------------------------------------------------


def test_image_boxes_painted_and_metadata_dropped() -> None:
    image = Image.new("RGB", (400, 80), "white")
    exif = Image.Exif()
    exif[0x010E] = "CANARY_EXIF_DESCRIPTION"
    buf = io.BytesIO()
    image.save(buf, format="JPEG", exif=exif.tobytes())
    p = plan(paint={("frame", "0"): [(10.0, 10.0, 200.0, 40.0)]})
    out = sanitize_bytes(buf.getvalue(), "jpeg", p)
    clean = Image.open(io.BytesIO(out.data))
    assert not clean.info.get("exif") and b"CANARY" not in out.data
    assert clean.convert("L").getpixel((100, 25)) < 20  # inside the box: black
    assert clean.convert("L").getpixel((350, 70)) > 200  # outside: untouched
    assert out.removed == [("metadata", "Image metadata (EXIF, GPS, text)")]


def test_multipage_tiff_keeps_pages_and_blacks_out_unknown_positions() -> None:
    frames = [builders.text_image(f"page {i}") for i in range(3)]
    buf = io.BytesIO()
    frames[0].save(buf, format="TIFF", save_all=True, append_images=frames[1:])
    out = sanitize_bytes(buf.getvalue(), "tiff", plan(paint={("frame", "1"): None})).data
    clean = Image.open(io.BytesIO(out))
    assert clean.n_frames == 3
    clean.seek(1)
    assert clean.convert("L").getextrema() == (0, 0)  # page 2 fully black
    clean.seek(0)
    assert clean.convert("L").getextrema()[1] > 200


# --- PDF ------------------------------------------------------------------------


def test_pdf_is_rebuilt_from_masked_text_only() -> None:
    import pypdfium2

    p = plan(pdf_pages=[("Page 1", "Contact [EMAIL_1] about <Project> & co"), ("Page 2", "")])
    out = sanitize_bytes(builders.build_pdf(), "pdf", p)
    pdf = pypdfium2.PdfDocument(out.data)
    assert len(pdf) == 2
    text = pdf[0].get_textpage().get_text_range()
    assert "[EMAIL_1]" in text and "<Project> & co" in text
    assert b"CANARY" not in out.data
    meta = pdf.get_metadata_dict()
    assert meta.get("Author", "") == "" and "CANARY" not in str(meta)
    assert out.removed and out.removed[0][0] == "pdf_hidden"
