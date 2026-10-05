"""Synthetic test documents with a canary value in every place text can hide.

All data is synthetic. Canaries are unique uppercase tokens so tests can
assert exactly where each one was found.
"""

from __future__ import annotations

import io
import re
import zipfile
from collections.abc import Mapping

from PIL import Image, ImageDraw, ImageFont


def text_image(text: str, size: tuple[int, int] = (1000, 160), font_size: int = 48) -> Image.Image:
    image = Image.new("RGB", size, "white")
    ImageDraw.Draw(image).text(
        (24, 40), text, fill="black", font=ImageFont.load_default(size=font_size)
    )
    return image


def png_bytes(image: Image.Image) -> bytes:
    buffer = io.BytesIO()
    image.save(buffer, "PNG")
    return buffer.getvalue()


def rewrite_zip(
    data: bytes,
    *,
    add: Mapping[str, bytes] | None = None,
    replace: Mapping[str, bytes] | None = None,
    patch: Mapping[str, tuple[str, str]] | None = None,
    content_types: Mapping[str, str] | None = None,
) -> bytes:
    """Copy an OOXML package, adding/replacing parts and content-type defaults."""
    add = dict(add or {})
    replace = dict(replace or {})
    source = zipfile.ZipFile(io.BytesIO(data))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as target:
        for info in source.infolist():
            body = replace.get(info.filename, source.read(info.filename))
            if patch and info.filename in patch:
                old, new = patch[info.filename]
                text = body.decode("utf-8")
                assert old in text, f"patch anchor missing in {info.filename}"
                body = text.replace(old, new, 1).encode("utf-8")
            if info.filename == "[Content_Types].xml" and content_types:
                text = body.decode("utf-8")
                for ext, ctype in content_types.items():
                    if f'Extension="{ext}"' not in text:
                        text = text.replace(
                            "<Default ",
                            f'<Default Extension="{ext}" ContentType="{ctype}"/><Default ',
                            1,
                        )
                body = text.encode("utf-8")
            target.writestr(info.filename, body)
        for name, body in add.items():
            target.writestr(name, body)
    return out.getvalue()


# --------------------------------------------------------------------- DOCX
def build_docx(*, with_ocr_image: bool = False) -> bytes:
    import docx
    from docx.opc.constants import RELATIONSHIP_TYPE as RT

    document = docx.Document()
    p = document.add_paragraph("Customer ")
    p.add_run("Ra")
    p.add_run("hul Sharma").bold = True
    p.add_run(" CANARY_BODY")
    table = document.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "PAN"
    table.cell(0, 1).text = "CANARY_TABLE"
    section = document.sections[0]
    section.header.paragraphs[0].text = "CANARY_HEADER"
    section.footer.paragraphs[0].text = "CANARY_FOOTER"
    document.add_comment(
        p.runs[0], text="CANARY_COMMENT", author="CANARY_COMMENT_AUTHOR", initials="CC"
    )
    props = document.core_properties
    props.author = "CANARY_PROP_AUTHOR"
    props.last_modified_by = "CANARY_PROP_EDITOR"
    props.comments = "CANARY_PROP_DESCRIPTION"

    tiny = Image.new("RGB", (8, 8), "white")
    document.add_picture(io.BytesIO(png_bytes(tiny)))
    if with_ocr_image:
        document.add_picture(io.BytesIO(png_bytes(text_image("CANARY OCR IN DOCX"))))

    # External relationship: the URL lives only in word/_rels/document.xml.rels.
    document.part.relate_to("https://canary-link.example.invalid/x", RT.HYPERLINK, is_external=True)
    buffer = io.BytesIO()
    document.save(buffer)

    body_extra = (
        '<w:p><w:del w:id="91" w:author="CANARY_REVIEWER"><w:r><w:delText>CANARY_DELETED</w:delText>'
        "</w:r></w:del></w:p>"
        '<w:p><w:r><w:instrText xml:space="preserve"> HYPERLINK "mailto:canary.field@example.invalid" '
        "</w:instrText></w:r></w:p>"
        '<w:p><w:r><w:t>OUTER_PARAGRAPH</w:t></w:r><w:r><w:pict><v:shape xmlns:v="urn:schemas-microsoft-com:vml">'
        "<v:textbox><w:txbxContent><w:p><w:r><w:t>CANARY_TEXTBOX</w:t></w:r></w:p></w:txbxContent>"
        "</v:textbox></v:shape></w:pict></w:r></w:p>"
    )
    data = rewrite_zip(
        buffer.getvalue(),
        patch={
            "word/document.xml": ("<w:sectPr", body_extra + "<w:sectPr"),
            "word/settings.xml": (
                "</w:settings>",
                '<w:docVars><w:docVar w:name="client" w:val="CANARY_DOCVAR"/></w:docVars></w:settings>',
            ),
        },
        add={
            "word/embeddings/Microsoft_Excel_Worksheet1.xlsx": build_xlsx(
                minimal="CANARY_EMBEDDED_XLSX"
            ),
            "word/vbaProject.bin": b"\xd0\xcf\x11\xe0fake-macro-project",
            "customXml/item99.xml": b"<data><client>CANARY_CUSTOMXML</client></data>",
        },
        content_types={
            "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "bin": "application/vnd.ms-office.vbaProject",
        },
    )
    return _set_alt(data)


def _part(data: bytes, name: str) -> bytes:
    return zipfile.ZipFile(io.BytesIO(data)).read(name)


def _set_alt(data: bytes) -> bytes:
    """Give the first picture alt text (python-docx leaves it empty)."""
    xml = _part(data, "word/document.xml").decode()
    xml = re.sub(r"(<wp:docPr [^>]*?)(/?>)", r'\1 descr="CANARY_ALT_TEXT"\2', xml, count=1)
    return rewrite_zip(data, replace={"word/document.xml": xml.encode()})


# --------------------------------------------------------------------- XLSX
def build_xlsx(*, minimal: str | None = None) -> bytes:
    import openpyxl
    from openpyxl.comments import Comment
    from openpyxl.workbook.defined_name import DefinedName
    from openpyxl.worksheet.datavalidation import DataValidation

    workbook = openpyxl.Workbook()
    sheet = workbook.active
    sheet.title = "Payroll"
    if minimal is not None:
        sheet["A1"] = minimal
        buffer = io.BytesIO()
        workbook.save(buffer)
        return buffer.getvalue()

    sheet.append(["Name", "Aadhaar", "Salary"])
    sheet.append(["CANARY_CELL", 234567890123, 125000])
    sheet.append(["CANARY_HIDDEN_ROW", 345678901234, 99000])
    sheet.row_dimensions[3].hidden = True
    sheet["E2"] = "CANARY_HIDDEN_COL"
    sheet.column_dimensions["E"].hidden = True
    sheet["A2"].comment = Comment("CANARY_CELL_COMMENT", "CANARY_NOTE_AUTHOR")
    sheet["D2"] = '=CONCATENATE("CANARY_FORMULA", A2)'
    sheet["F2"] = "Portal"
    sheet["F2"].hyperlink = "https://canary-xlsx-link.example.invalid/"
    validation = DataValidation(type="list", formula1='"CANARY_DV,Other"')
    sheet.add_data_validation(validation)
    validation.add("G2")
    sheet.oddHeader.center.text = "CANARY_PRINT_HEADER"
    hidden = workbook.create_sheet("Secret")
    hidden.sheet_state = "hidden"
    hidden["A1"] = "CANARY_HIDDEN_SHEET"
    workbook.defined_names["CANARY_NAMED_RANGE"] = DefinedName(
        "CANARY_NAMED_RANGE", attr_text="Payroll!$A$2"
    )
    workbook.properties.creator = "CANARY_XLSX_AUTHOR"
    buffer = io.BytesIO()
    workbook.save(buffer)

    pivot = (
        b'<pivotCacheRecords xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1">'
        b'<r><s v="CANARY_PIVOT_CACHE"/><n v="777"/></r></pivotCacheRecords>'
    )
    connections = (
        b'<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        b'<connection id="1" name="crm"><dbPr connection="Provider=SQLOLEDB;Password=CANARY_DB_PASSWORD" '
        b'command="SELECT * FROM clients"/></connection></connections>'
    )
    # openpyxl writes inline strings; Excel uses a shared-strings table, where
    # text no cell uses any more can linger. Add one used and one orphaned entry.
    data = buffer.getvalue()
    sst = (
        b'<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2">'
        b"<si><t>CANARY_SHARED_STRING</t></si><si><r><t>CANARY_ORPHAN</t></r><r><t>_STRING</t></r></si></sst>"
    )
    sheet_xml = _part(data, "xl/worksheets/sheet1.xml").decode()
    sheet_xml = re.sub(
        r'(<row r="2"[^>]*>.*?)(</row>)', r'\1<c r="H2" t="s"><v>0</v></c>\2', sheet_xml, count=1
    )
    return rewrite_zip(
        data,
        replace={"xl/worksheets/sheet1.xml": sheet_xml.encode()},
        patch={
            "xl/_rels/workbook.xml.rels": (
                "</Relationships>",
                '<Relationship Id="rIdSst" Target="sharedStrings.xml" Type="http://schemas.openxmlformats.org/'
                'officeDocument/2006/relationships/sharedStrings"/></Relationships>',
            ),
            "[Content_Types].xml": (
                "</Types>",
                '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-'
                'officedocument.spreadsheetml.sharedStrings+xml"/></Types>',
            ),
        },
        add={
            "xl/sharedStrings.xml": sst,
            "xl/pivotCache/pivotCacheRecords1.xml": pivot,
            "xl/connections.xml": connections,
        },
    )


# --------------------------------------------------------------------- PPTX
def build_pptx() -> bytes:
    import pptx
    from pptx.chart.data import CategoryChartData
    from pptx.enum.chart import XL_CHART_TYPE
    from pptx.util import Inches

    presentation = pptx.Presentation()
    slide = presentation.slides.add_slide(presentation.slide_layouts[1])
    slide.shapes.title.text = "CANARY_SLIDE_TITLE"
    slide.placeholders[1].text = "Revenue CANARY_SLIDE_BODY"
    slide.notes_slide.notes_text_frame.text = "CANARY_SPEAKER_NOTES"
    table = slide.shapes.add_table(1, 2, Inches(1), Inches(5), Inches(4), Inches(1)).table
    table.cell(0, 0).text = "CANARY_PPT_TABLE"

    chart_slide = presentation.slides.add_slide(presentation.slide_layouts[5])
    chart_slide.shapes.title.text = "Chart slide"
    data = CategoryChartData()
    data.categories = ["CANARY_CHART_CATEGORY", "Other"]
    data.add_series("Revenue", (10, 20))
    chart_slide.shapes.add_chart(
        XL_CHART_TYPE.COLUMN_CLUSTERED, Inches(1), Inches(2), Inches(6), Inches(4), data
    )

    hidden = presentation.slides.add_slide(presentation.slide_layouts[5])
    hidden.shapes.title.text = "CANARY_HIDDEN_SLIDE"
    hidden._element.set("show", "0")
    presentation.core_properties.author = "CANARY_PPT_AUTHOR"
    buffer = io.BytesIO()
    presentation.save(buffer)

    comments = (
        b'<p:cmLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        b'<p:cm authorId="0" idx="1"><p:text>CANARY_PPT_COMMENT</p:text></p:cm></p:cmLst>'
    )
    authors = (
        b'<p:cmAuthorLst xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">'
        b'<p:cmAuthor id="0" name="CANARY_PPT_COMMENTER" initials="CP" lastIdx="1" clrIdx="0"/>'
        b"</p:cmAuthorLst>"
    )
    return rewrite_zip(
        buffer.getvalue(),
        add={"ppt/comments/comment1.xml": comments, "ppt/commentAuthors.xml": authors},
    )


# ---------------------------------------------------------------------- PDF
def build_pdf(*, scanned_page: bool = False, attachment: bytes | None = None) -> bytes:
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer)
    c.setAuthor("CANARY_PDF_AUTHOR")
    c.setTitle("CANARY_PDF_TITLE")
    c.drawString(72, 720, "Customer CANARY_PDF_BODY contact canary@example.invalid")
    c.bookmarkPage("p1")
    c.addOutlineEntry("CANARY_BOOKMARK", "p1", level=0)
    c.textAnnotation("CANARY_PDF_COMMENT", Rect=(72, 600, 200, 650))
    c.linkURL("https://canary-pdf-link.example.invalid/", (72, 500, 200, 520))
    c.acroForm.textfield(
        name="pan_number", value="CANARY_FORM_VALUE", x=72, y=400, width=200, height=20
    )
    c.showPage()
    c.drawString(72, 720, "Second page CANARY_PDF_PAGE2")
    c.showPage()
    if scanned_page:
        c.drawImage(
            ImageReader(text_image("SCANNED CANARY PAGE 2024")), 50, 500, width=500, height=80
        )
        c.showPage()
    c.save()
    data = buffer.getvalue()
    if attachment is not None:
        import pypdfium2 as pdfium

        pdf = pdfium.PdfDocument(data)
        att = pdf.new_attachment("clients.csv")
        att.set_data(attachment)
        out = io.BytesIO()
        pdf.save(out)
        pdf.close()
        data = out.getvalue()
    return data


def build_encrypted_pdf() -> bytes:
    from reportlab.lib.pdfencrypt import StandardEncryption
    from reportlab.pdfgen import canvas

    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, encrypt=StandardEncryption("user-password", canPrint=0))
    c.drawString(72, 720, "secret")
    c.showPage()
    c.save()
    return buffer.getvalue()
