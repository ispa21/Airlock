"""Excel workbooks (XLSX/XLSM).

Cells are emitted one segment each, with the column header as detector
context. Shared strings are resolved per cell; strings that no cell uses any
more ("orphaned" text left behind by edits) are still emitted, as hidden
content. Hidden sheets, rows and columns are flagged as hidden content.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterator
from decimal import Decimal, InvalidOperation
from typing import Final, cast
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET

from airlock_engine.core import errors
from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.ooxml.base import OoxmlAdapter, PartRole, common_role, numbered
from airlock_engine.documents.ooxml.package import OoxmlPackage, XmlUnreadable
from airlock_engine.documents.ooxml.xml import local, rel_id
from airlock_engine.documents.text.adapter import column_name
from airlock_engine.extraction.context import ExtractionContext

_REF: Final = re.compile(r"^([A-Za-z]{1,3})(\d+)$")
_HEADER_FOOTER: Final = frozenset(
    {"oddHeader", "oddFooter", "evenHeader", "evenFooter", "firstHeader", "firstFooter"}
)
_TRUE: Final = frozenset({"1", "true"})


def _column_index(letters: str) -> int:
    index = 0
    for ch in letters.upper():
        index = index * 26 + (ord(ch) - 64)
    return index - 1


def _rich_text(el: Element) -> str:
    """Text of <si>/<is>: plain <t> or rich-text runs, excluding phonetic hints."""
    parts: list[str] = []
    for child in el:
        name = local(child.tag)
        if name == "t":
            parts.append(child.text or "")
        elif name == "r":
            parts.extend(t.text or "" for t in child if local(t.tag) == "t")
    return "".join(parts)


def _normalize_number(value: str) -> str:
    """'1.23456789012E+11' -> '123456789012' so IDs stored as numbers are matchable."""
    if "e" in value.lower():
        try:
            number = Decimal(value)
        except InvalidOperation:
            return value
        if number == number.to_integral_value() and abs(number) < Decimal("1e22"):
            return str(int(number))
    return value


def _interesting_formula(formula: str) -> bool:
    """Formulas with literals, external references, URLs or e-mail addresses."""
    return any(marker in formula for marker in ('"', "[", "http", "@", "\\\\"))


def _iterparse(data: bytes, events: tuple[str, ...]) -> Iterator[tuple[str, Element]]:
    return cast(
        Iterator[tuple[str, Element]],
        SafeET.iterparse(io.BytesIO(data), events=events, forbid_dtd=True),
    )


class XlsxAdapter(OoxmlAdapter):
    formats = ("xlsx", "xlsm")
    format_label = "Excel workbook"

    def extract_structured(self, pkg: OoxmlPackage, ctx: ExtractionContext, main: str) -> set[str]:
        try:
            workbook = pkg.xml(main)
        except XmlUnreadable as exc:
            raise errors.extraction_failed(self.format_label) from exc
        rels = {rel.rel_id: rel for rel in pkg.relationships(main)}
        handled = {main}

        sheets: list[tuple[str, bool, str | None]] = []  # (name, hidden, worksheet part)
        names = 0
        for el in workbook.iter():
            tag = local(el.tag)
            if tag == "sheet":
                rel = rels.get(rel_id(el))
                is_worksheet = rel is not None and rel.rel_type.endswith("/worksheet")
                part = (
                    rel.target if rel is not None and is_worksheet and pkg.has(rel.target) else None
                )
                sheets.append((el.get("name", ""), el.get("state", "visible") != "visible", part))
            elif tag == "definedName":
                ctx.add(
                    el.get("name", ""),
                    main,
                    f"name/{names}",
                    kind=SegmentKind.NAME,
                    label="Named ranges",
                )
                ctx.add(
                    el.text or "",
                    main,
                    f"name/{names}/value",
                    kind=SegmentKind.FIELD,
                    label="Named ranges",
                )
                names += 1
        for i, (name, hidden, _) in enumerate(sheets):
            ctx.add(
                name,
                main,
                f"sheet/{i}",
                kind=SegmentKind.HIDDEN if hidden else SegmentKind.NAME,
                label=f"Sheet {i + 1} name" + (" (hidden sheet)" if hidden else ""),
            )
        ctx.count("sheets", len(sheets))

        sst_part = next(
            (
                r.target
                for r in rels.values()
                if r.rel_type.endswith("/sharedStrings") and pkg.has(r.target)
            ),
            None,
        )
        strings = self._shared_strings(pkg, sst_part) if sst_part else []
        used = [False] * len(strings)
        if sst_part:
            handled.add(sst_part)

        for i, (_, hidden, part) in enumerate(sheets):
            ctx.progress("sheets", i, len(sheets))
            if part is not None:
                self._extract_sheet(pkg, ctx, part, i + 1, hidden, strings, used)
                handled.add(part)
        ctx.progress("sheets", len(sheets), len(sheets))

        for k, (text, is_used) in enumerate(zip(strings, used, strict=True)):
            if not is_used:
                ctx.add(
                    text,
                    sst_part or "",
                    f"si/{k}",
                    kind=SegmentKind.HIDDEN,
                    label="Unused text stored in the workbook",
                )
        return handled

    def _shared_strings(self, pkg: OoxmlPackage, part: str) -> list[str]:
        strings: list[str] = []
        try:
            for _, el in _iterparse(pkg.read(part), ("end",)):
                if local(el.tag) == "si":
                    strings.append(_rich_text(el))
                    el.clear()
        except (ParseError, DefusedXmlException, ValueError) as exc:
            raise errors.extraction_failed(self.format_label) from exc
        return strings

    def _extract_sheet(
        self,
        pkg: OoxmlPackage,
        ctx: ExtractionContext,
        part: str,
        number: int,
        sheet_hidden: bool,
        strings: list[str],
        used: list[bool],
    ) -> None:
        sheet = f"Sheet {number}"
        hidden_cols: list[tuple[int, int]] = []
        header: dict[int, str] = {}
        row_number = 0
        row_hidden = False
        next_col = 0
        sheet_data: Element | None = None
        extras = 0
        try:
            for event, el in _iterparse(pkg.read(part), ("start", "end")):
                tag = local(el.tag)
                if event == "start":
                    if tag == "row":
                        row_number = int(el.get("r") or row_number + 1)
                        row_hidden = el.get("hidden") in _TRUE
                        next_col = 0
                    elif tag == "sheetData":
                        sheet_data = el
                    continue

                if tag == "c":
                    next_col = self._cell(
                        ctx, part, sheet, el, row_number, next_col,
                        hidden=sheet_hidden or row_hidden,
                        hidden_cols=hidden_cols, header=header, strings=strings, used=used,
                    )  # fmt: skip
                    el.clear()
                elif tag == "row":
                    el.clear()
                    if sheet_data is not None:
                        sheet_data.clear()  # bound memory on very large sheets
                elif tag == "col" and el.get("hidden") in _TRUE:
                    hidden_cols.append((int(el.get("min", "0")) - 1, int(el.get("max", "0")) - 1))
                elif tag == "hyperlink":
                    for key in ("display", "tooltip"):
                        extras += 1
                        ctx.add(
                            el.get(key, ""),
                            part,
                            f"x/{extras}",
                            kind=SegmentKind.LINK,
                            label=f"{sheet} · link",
                        )
                elif tag in ("formula1", "formula2", "formula"):
                    extras += 1
                    ctx.add(
                        el.text or "",
                        part,
                        f"x/{extras}",
                        kind=SegmentKind.FIELD,
                        label=f"{sheet} · rules",
                    )
                elif tag in _HEADER_FOOTER:
                    extras += 1
                    ctx.add(
                        el.text or "",
                        part,
                        f"x/{extras}",
                        kind=SegmentKind.HEADER_FOOTER,
                        label=f"{sheet} · print header/footer",
                    )
        except (ParseError, DefusedXmlException, ValueError) as exc:
            raise errors.extraction_failed(self.format_label) from exc

    @staticmethod
    def _cell(
        ctx: ExtractionContext,
        part: str,
        sheet: str,
        el: Element,
        row: int,
        next_col: int,
        *,
        hidden: bool,
        hidden_cols: list[tuple[int, int]],
        header: dict[int, str],
        strings: list[str],
        used: list[bool],
    ) -> int:
        ref = el.get("r") or ""
        match = _REF.match(ref)
        col = _column_index(match.group(1)) if match else next_col
        if not match:
            ref = f"{column_name(col)}{row}"
        cell_type = el.get("t", "n")
        raw: str | None = None
        inline: str | None = None
        formula: str | None = None
        for child in el:
            name = local(child.tag)
            if name == "v":
                raw = child.text
            elif name == "is":
                inline = _rich_text(child)
            elif name == "f":
                formula = child.text

        value = ""
        if cell_type == "s" and raw is not None and raw.strip().isdigit():
            index = int(raw)
            if 0 <= index < len(strings):
                value = strings[index]
                used[index] = True
        elif cell_type == "inlineStr":
            value = inline or ""
        elif cell_type in ("str", "d"):
            value = raw or ""
        elif cell_type == "n":
            value = _normalize_number(raw or "")
        # booleans ("b") and errors ("e") carry no user text

        is_hidden = hidden or any(lo <= col <= hi for lo, hi in hidden_cols)
        if row == 1 and cell_type in ("s", "inlineStr", "str") and value.strip():
            header[col] = value.strip()
        ctx.add(
            value,
            part,
            ref,
            kind=SegmentKind.HIDDEN if is_hidden else SegmentKind.BODY,
            label=f"{sheet} · {ref}" + (" (hidden)" if is_hidden else ""),
            context=header.get(col, "") if row > 1 else "",
        )
        if formula and _interesting_formula(formula):
            ctx.add(
                formula, part, f"{ref}/f", kind=SegmentKind.FIELD, label=f"{sheet} · {ref} formula"
            )
        return col + 1

    def classify(self, name: str, content_type: str) -> PartRole | None:
        lowered = name.lower()
        if "/pivotcache/" in lowered:
            return PartRole(
                SegmentKind.HIDDEN,
                "Pivot table cache",
                {"v": SegmentKind.HIDDEN, "name": SegmentKind.HIDDEN},
            )
        if "/pivottables/" in lowered:
            return PartRole(
                SegmentKind.HIDDEN,
                "Pivot table",
                {"n": SegmentKind.HIDDEN, "name": SegmentKind.HIDDEN},
            )
        if "/threadedcomments/" in lowered:
            return PartRole(SegmentKind.COMMENT, "Threaded comments")
        if "/comments" in lowered or lowered.rsplit("/", 1)[-1].startswith("comment"):
            return PartRole(SegmentKind.COMMENT, "Cell comments")
        if "/persons/" in lowered:
            return PartRole(SegmentKind.METADATA, "Commenters")
        if lowered.endswith("connections.xml"):
            return PartRole(SegmentKind.LINK, "Data connections")
        if "/externallinks/" in lowered:
            return PartRole(SegmentKind.LINK, "External workbook links", {"val": SegmentKind.LINK})
        if "/querytables/" in lowered:
            return PartRole(SegmentKind.LINK, "Query tables", {"name": SegmentKind.LINK})
        if "/tables/" in lowered:
            return PartRole(SegmentKind.BODY, "Table definitions", {"name": SegmentKind.BODY})
        if "/drawings/" in lowered:
            if lowered.endswith(".vml"):
                return PartRole(SegmentKind.COMMENT, "Comment shapes")
            return PartRole(SegmentKind.BODY, numbered(name, "Drawing"))
        if "/chartsheets/" in lowered:
            return PartRole(SegmentKind.CHART, numbered(name, "Chart sheet"))
        if "/worksheets/" in lowered:
            return PartRole(SegmentKind.HIDDEN, "Sheet not listed in the workbook")
        if lowered.endswith("sharedstrings.xml"):
            return PartRole(SegmentKind.HIDDEN, "Unreferenced text table")
        role = common_role(name)
        if role is not None:
            return role
        return PartRole(SegmentKind.HIDDEN, "Other workbook data")
