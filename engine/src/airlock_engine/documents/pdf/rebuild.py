"""Rebuild a safe PDF from masked text (architecture risk R1).

Editing a PDF in place cannot guarantee that text is gone: it can survive in
content streams, earlier revisions, form appearances or fonts. The safe copy
is therefore a new PDF that holds only the masked page text. Annotations,
form values, attachments, bookmarks, scripts, metadata and earlier revisions
are not carried over; pictures are not carried over either (their text, read
by OCR and masked, is).

Uses reportlab with the bundled Bitstream Vera font. Scripts the font does not
cover (e.g. Devanagari) render as empty boxes; a broader bundled font is a
Phase 8 packaging item.
"""

from __future__ import annotations

import io
from collections.abc import Sequence
from pathlib import Path

_FONT = "AirlockSans"
_FONT_BOLD = "AirlockSansBold"
_registered = False


def _register_fonts() -> None:
    global _registered
    if _registered:
        return
    import reportlab
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont

    fonts = Path(reportlab.__file__).parent / "fonts"
    pdfmetrics.registerFont(TTFont(_FONT, str(fonts / "Vera.ttf")))
    pdfmetrics.registerFont(TTFont(_FONT_BOLD, str(fonts / "VeraBd.ttf")))
    _registered = True


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_pdf(sections: Sequence[tuple[str, str]], title: str = "Protected copy") -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

    _register_fonts()
    body = ParagraphStyle("body", fontName=_FONT, fontSize=10, leading=14)
    heading = ParagraphStyle("heading", fontName=_FONT_BOLD, fontSize=11, leading=16, spaceAfter=6)
    story: list[object] = []
    for index, (label, text) in enumerate(sections):
        if index:
            story.append(PageBreak())
        story.append(Paragraph(_escape(label), heading))
        for block in text.split("\n\n"):
            lines = [_escape(line) for line in block.split("\n")]
            if any(line.strip() for line in lines):
                story.append(Paragraph("<br/>".join(lines), body))
                story.append(Spacer(1, 4))
    if not story:
        story.append(Paragraph("(no text)", body))
    buffer = io.BytesIO()
    # invariant=1: no creation date or random document id in the output.
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        title=title,
        author="",
        subject="",
        creator="Airlock",
        invariant=1,
    )
    doc.build(story)
    return buffer.getvalue()
