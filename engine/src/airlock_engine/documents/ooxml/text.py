"""Generic text extraction for any OOXML XML part.

Emits:

* one segment per paragraph (``w:p`` / ``a:p``), so names split across
  formatting runs ("Ra" + "hul") are reassembled; nested paragraphs (text
  boxes) are emitted separately, never twice;
* deleted tracked-change text and field codes as separate segments;
* leaf element text outside paragraphs (properties, chart caches, custom XML);
* attribute values that carry human text: authors, reviewer e-mails, alt
  text, connection strings, field instructions.
"""

from __future__ import annotations

import html
import re
from collections.abc import Mapping
from typing import Final
from xml.etree.ElementTree import Element

from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.ooxml.xml import family, local
from airlock_engine.extraction.context import ExtractionContext

#: Attribute local names whose values are human-entered text.
SENSITIVE_ATTRS: Final[Mapping[str, SegmentKind]] = {
    "author": SegmentKind.METADATA,
    "initials": SegmentKind.METADATA,
    "userId": SegmentKind.METADATA,
    "displayName": SegmentKind.METADATA,
    "descr": SegmentKind.ALT_TEXT,
    "title": SegmentKind.ALT_TEXT,
    "instr": SegmentKind.FIELD,
    "connection": SegmentKind.LINK,
    "command": SegmentKind.LINK,
    "sourceFile": SegmentKind.LINK,
    "odcFile": SegmentKind.LINK,
    "url": SegmentKind.LINK,
    "tooltip": SegmentKind.LINK,
    "display": SegmentKind.LINK,
}
#: Drawing object properties: their ``name`` is user-editable ("Photo of ...").
_OBJECT_PROPS: Final = frozenset({"docPr", "cNvPr"})
#: Property containers that never hold document text.
_SKIP_IN_PARAGRAPH: Final = frozenset({"pPr", "rPr", "tabs", "sectPr", "tblPr"})
_DELETED_CONTAINERS: Final = frozenset({"del", "moveFrom"})
_ATTR_LABELS: Final[Mapping[SegmentKind, str]] = {
    SegmentKind.METADATA: "people",
    SegmentKind.ALT_TEXT: "object descriptions",
    SegmentKind.FIELD: "field codes",
    SegmentKind.LINK: "links and connections",
}
_TAG: Final = re.compile(r"<[^>]*>")
#: Flags and small counters (VML anchors, toggles) are never user text.
_TRIVIAL: Final = re.compile(r"^(true|false|-?\d{1,4})$", re.IGNORECASE)
#: Application-generated object names: "Title 1", "Content Placeholder 2", "TextBox 7".
_DEFAULT_OBJECT_NAME: Final = re.compile(r"^[A-Z][A-Za-z]*(?: [A-Za-z]+)* \d+$")
#: Statistics and flags in property parts ("0", "false", timestamps) carry no user text.
_METADATA_NOISE: Final = re.compile(
    r"^(true|false|\d+(\.\d+)?|\d{4}-\d\d-\d\dT[\d:.]+(Z|[+-]\d\d:\d\d)?|PT\d+M)$",
    re.IGNORECASE,
)


def _is_paragraph(el: Element) -> bool:
    return local(el.tag) == "p" and family(el.tag) in ("w", "a")


def paragraph_text(p: Element, consumed: set[int] | None = None) -> tuple[str, str, str]:
    """Return (visible text, deleted text, field instructions) of one paragraph."""
    body: list[str] = []
    deleted: list[str] = []
    instr: list[str] = []
    # Iterative DFS keeps document order without recursion limits.
    stack: list[tuple[Element, bool]] = [(child, False) for child in reversed(list(p))]
    while stack:
        el, in_deleted = stack.pop()
        name = local(el.tag)
        if not name or _is_paragraph(el) or name in _SKIP_IN_PARAGRAPH:
            continue
        if consumed is not None:
            consumed.add(id(el))
        text = el.text or ""
        if name == "t":
            (deleted if in_deleted else body).append(text)
        elif name == "delText":
            deleted.append(text)
        elif name == "instrText":
            instr.append(text)
        elif name in ("tab", "ptab"):
            body.append("\t")
        elif name in ("br", "cr"):
            body.append("\n")
        elif name == "noBreakHyphen":
            body.append("-")
        deleted_scope = in_deleted or name in _DELETED_CONTAINERS
        stack.extend((child, deleted_scope) for child in reversed(list(el)))
    return "".join(body), "".join(deleted), "".join(instr).strip()


def extract_part(
    ctx: ExtractionContext,
    root: Element,
    part: str,
    *,
    kind: SegmentKind,
    label: str,
    extra_attrs: Mapping[str, SegmentKind] | None = None,
) -> int:
    """Walk one parsed part. Returns the number of paragraphs found."""
    attrs = {**SENSITIVE_ATTRS, **(extra_attrs or {})}
    consumed: set[int] = set()
    attr_values: dict[str, dict[str, None]] = {}
    paragraphs = 0
    for index, el in enumerate(root.iter()):
        name = local(el.tag)
        if not name:
            continue
        for key, value in el.attrib.items():
            attr_name = local(key)
            if not value.strip():
                continue
            if attr_name in attrs or (
                attr_name == "name"
                and name in _OBJECT_PROPS
                and not _DEFAULT_OBJECT_NAME.match(value)
            ):
                attr_values.setdefault(attr_name, {})[value] = None
        if _is_paragraph(el):
            body, deleted, instr = paragraph_text(el, consumed)
            paragraphs += 1
            where = f"{label} · paragraph {paragraphs}"
            path = f"p/{paragraphs - 1}"
            ctx.add(body, part, path, kind=kind, label=where)
            ctx.add(
                deleted,
                part,
                f"{path}/del",
                kind=SegmentKind.TRACKED_CHANGE,
                label=f"{where} (deleted text)",
            )
            ctx.add(instr, part, f"{path}/instr", kind=SegmentKind.FIELD, label=f"{where} (field)")
        elif id(el) not in consumed and len(el) == 0 and el.text and el.text.strip():
            value = el.text.strip()
            if _TRIVIAL.match(value) or (
                kind is SegmentKind.METADATA and _METADATA_NOISE.match(value)
            ):
                continue
            ctx.add(el.text, part, f"e/{index}", kind=kind, label=label)

    for attr_name, values in attr_values.items():
        attr_kind = attrs.get(attr_name, SegmentKind.ALT_TEXT)
        for k, value in enumerate(values):
            ctx.add(
                value,
                part,
                f"@{attr_name}/{k}",
                kind=attr_kind,
                label=f"{label} ({_ATTR_LABELS.get(attr_kind, 'attributes')})",
            )
    return paragraphs


def extract_markup_fallback(
    ctx: ExtractionContext, data: bytes, part: str, *, kind: SegmentKind, label: str
) -> None:
    """For parts that are not well-formed XML (legacy VML): strip tags, keep text."""
    text = html.unescape(_TAG.sub("\n", data.decode("utf-8", errors="replace")))
    for n, line in enumerate(x.strip() for x in text.splitlines()):
        if not _TRIVIAL.match(line):
            ctx.add(line, part, f"line/{n}", kind=kind, label=label)
