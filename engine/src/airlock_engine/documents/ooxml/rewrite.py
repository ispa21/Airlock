"""Byte-preserving rewrite of one OOXML XML part.

The part is split into tokens (tags, text, comments, CDATA) and only the
tokens that change are rewritten. Re-serialising through ElementTree is not
an option: it renames namespace prefixes and drops unused declarations, and
Office rejects files whose ``mc:Ignorable`` list then names undeclared
prefixes.

What is rewritten mirrors what extraction reads:

* paragraph text (``w:p``/``a:p``) and rich-text strings (``si``/``is``),
  joined across formatting runs, so a name split as "Ra" + "hul" is found;
  the replacement goes into the first run, the rest of the value is removed
  from the following runs;
* every other text node;
* attributes that hold human text (authors, alt text, names, link targets);
* numeric spreadsheet cells whose value is protected become text cells;
* numeric pivot-cache items whose value is protected become string items.
"""

from __future__ import annotations

import html
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

from airlock_engine.documents.ooxml.text import SENSITIVE_ATTRS
from airlock_engine.documents.ooxml.xml import family
from airlock_engine.masking.sweep import Sweeper

_TOKEN: Final = re.compile(
    r"<!--.*?-->|<!\[CDATA\[.*?\]\]>|<\?.*?\?>|<!DOCTYPE[^>]*>|<(?:[^>\"']|\"[^\"]*\"|'[^']*')*>",
    re.S,
)
_ATTR: Final = re.compile(r"(\s+)([^\s=/>]+)(\s*=\s*)(\"[^\"]*\"|'[^']*')")
_NAME: Final = re.compile(r"^</?\s*([^\s/>]+)")
_ENCODING: Final = re.compile(rb"^<\?xml[^>]*encoding=[\"']([A-Za-z0-9._-]+)[\"']")

#: Attributes (local names) that can hold user text.
HUMAN_ATTRS: Final = frozenset(SENSITIVE_ATTRS) | {"name", "val", "v", "n", "display", "tooltip"}
#: Containers whose runs are joined before matching, like extraction does.
_PARAGRAPH_FAMILIES: Final = {"p": ("w", "a"), "si": ("s",), "is": ("s",)}
_SKIP: Final = frozenset({"pPr", "rPr", "tabs", "sectPr", "tblPr"})
_FIXED: Final = {"tab": "\t", "ptab": "\t", "br": "\n", "cr": "\n", "noBreakHyphen": "-"}
_DELETED: Final = frozenset({"del", "moveFrom"})


class RewriteError(ValueError):
    """The rewritten part would not be valid XML."""


@dataclass
class _Piece:
    text: str
    out_index: int | None  # None: a fixed character (tab, break) that cannot be edited


@dataclass
class _Paragraph:
    streams: dict[str, list[_Piece]] = field(
        default_factory=lambda: {"body": [], "del": [], "instr": []}
    )


@dataclass
class _Cell:
    tag_index: int
    prefix: str
    has_formula: bool = False
    v_tokens: list[int] = field(default_factory=list)  # start, text, end
    new_text: str | None = None


@dataclass
class _Element:
    qname: str
    local: str
    fam: str
    ns: dict[str, str]
    paragraph: _Paragraph | None = None
    cell: _Cell | None = None
    renamed: str | None = None
    clear: bool = False


def _split(qname: str) -> tuple[str, str]:
    prefix, _, local_name = qname.rpartition(":")
    return prefix, local_name


def _escape_text(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _escape_attr(text: str, quote: str) -> str:
    out = _escape_text(text)
    return out.replace('"', "&quot;") if quote == '"' else out.replace("'", "&apos;")


def decode_part(data: bytes) -> tuple[str, str, bytes]:
    """(text, encoding, bom) of an XML part."""
    if data.startswith(b"\xef\xbb\xbf"):
        return data[3:].decode("utf-8"), "utf-8", b"\xef\xbb\xbf"
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16"), "utf-16", b""
    m = _ENCODING.match(data)
    encoding = m.group(1).decode("ascii").lower() if m else "utf-8"
    return data.decode(encoding), encoding, b""


def rewrite_xml(
    data: bytes,
    sweeper: Sweeper,
    *,
    spreadsheet: bool = False,
    clear_elements: frozenset[str] = frozenset(),
    drop_tag: Callable[[str, Mapping[str, str]], bool] | None = None,
) -> bytes:
    """Return the rewritten part (the input object itself if nothing changed)."""
    text, encoding, bom = decode_part(data)
    out: list[str] = []
    stack: list[_Element] = []
    paragraphs: list[_Paragraph] = []
    changed = False
    skip_depth = 0
    pos = 0

    def ns_of() -> dict[str, str]:
        return stack[-1].ns if stack else {}

    def add_text(raw: str) -> None:
        nonlocal changed
        if not raw:
            return
        parent = stack[-1] if stack else None
        if parent is not None and parent.clear:
            if raw.strip():
                out.append("")
                changed = True
            else:
                out.append(raw)
            return
        value = html.unescape(raw)
        stream = _stream_for(stack) if paragraphs and skip_depth == 0 else None
        if stream is not None:
            out.append(raw)
            paragraphs[-1].streams[stream].append(_Piece(value, len(out) - 1))
            return
        if parent is not None and parent.cell is not None and parent.local == "v":
            cell = parent.cell
            normalized = _normalize_number(value)
            new = sweeper.apply(normalized)
            if new != normalized:
                cell.new_text = new
            out.append(raw)
            cell.v_tokens.append(len(out) - 1)
            return
        new = sweeper.apply(value)
        if new != value:
            out.append(_escape_text(new))
            changed = True
        else:
            out.append(raw)

    for m in _TOKEN.finditer(text):
        add_text(text[pos : m.start()])
        pos = m.end()
        token = m.group()
        if token.startswith("<![CDATA["):
            inner = token[9:-3]
            new_inner = sweeper.apply(inner)
            if new_inner != inner and "]]>" not in new_inner:
                token = f"<![CDATA[{new_inner}]]>"
                changed = True
            out.append(token)
            continue
        if token.startswith(("<!--", "<?", "<!")):
            out.append(token)
            continue
        name_match = _NAME.match(token)
        if name_match is None:
            out.append(token)
            continue
        qname = name_match.group(1)
        if token.startswith("</"):
            element = stack.pop() if stack else None
            if element is not None:
                if element.local in _SKIP and element.fam in ("w", "a"):
                    skip_depth = max(0, skip_depth - 1)
                if element.paragraph is not None:
                    paragraphs.pop()
                    changed |= _finish_paragraph(element.paragraph, out, sweeper)
                if element.renamed is not None:
                    token = f"</{element.renamed}>"
            out.append(token)
            if element is not None and element.cell is not None and element.local == "c":
                changed |= _finish_cell(element.cell, out)
            if element is not None and element.local == "v" and stack and stack[-1].cell:
                stack[-1].cell.v_tokens.append(len(out) - 1)
            continue

        # Start or empty-element tag.
        self_closing = token.endswith("/>")
        attrs = {a.group(2): html.unescape(a.group(4)[1:-1]) for a in _ATTR.finditer(token)}
        ns = dict(ns_of())
        for key, value in attrs.items():
            if key == "xmlns":
                ns[""] = value
            elif key.startswith("xmlns:"):
                ns[key[6:]] = value
        prefix, local_name = _split(qname)
        uri = ns.get(prefix, "")
        fam = family(f"{{{uri}}}{local_name}") if uri else ""

        if drop_tag is not None and self_closing and drop_tag(local_name, attrs):
            changed = True  # e.g. a relationship to a part that was removed
            continue

        new_token, renamed = _rewrite_attrs(token, local_name, fam, attrs, sweeper)
        if new_token != token:
            changed = True
            token = new_token
        out.append(token)

        if self_closing:
            if paragraphs and skip_depth == 0 and local_name in _FIXED and fam in ("w", "a"):
                paragraphs[-1].streams["body"].append(_Piece(_FIXED[local_name], None))
            continue

        element = _Element(qname, local_name, fam, ns, renamed=renamed)
        if local_name in _SKIP and fam in ("w", "a"):
            skip_depth += 1
        if fam in _PARAGRAPH_FAMILIES.get(local_name, ()):
            element.paragraph = _Paragraph()
            paragraphs.append(element.paragraph)
        if local_name in clear_elements:
            element.clear = True
        if spreadsheet and fam == "s":
            if local_name == "c" and attrs.get("t", "n") == "n":
                element.cell = _Cell(len(out) - 1, prefix)
            elif stack and stack[-1].cell is not None:
                cell = stack[-1].cell
                if local_name == "f":
                    cell.has_formula = True
                elif local_name == "v":
                    element.cell = cell
                    cell.v_tokens.append(len(out) - 1)
        stack.append(element)
    add_text(text[pos:])

    if not changed:
        return data
    return bom + "".join(out).encode(encoding)


def _stream_for(stack: list[_Element]) -> str | None:
    """Which joined stream a text node belongs to, or None for leaf text."""
    if not stack:
        return None
    parent = stack[-1].local
    in_deleted = any(e.local in _DELETED for e in stack)
    if parent == "t":
        return "del" if in_deleted else "body"
    if parent == "delText":
        return "del"
    if parent == "instrText":
        return "instr"
    return None


def _finish_paragraph(paragraph: _Paragraph, out: list[str], sweeper: Sweeper) -> bool:
    changed = False
    for pieces in paragraph.streams.values():
        if not pieces:
            continue
        joined = "".join(p.text for p in pieces)
        matches = sweeper.find(joined)
        if not matches:
            continue
        local_edits: dict[int, list[tuple[int, int, str]]] = {}
        offsets = []
        pos = 0
        for p in pieces:
            offsets.append(pos)
            pos += len(p.text)
        for start, end, replacement in matches:
            placed = False
            for i, p in enumerate(pieces):
                ps, pe = offsets[i], offsets[i] + len(p.text)
                if p.out_index is None or pe <= start or ps >= end:
                    continue
                lo, hi = max(start, ps) - ps, min(end, pe) - ps
                local_edits.setdefault(i, []).append((lo, hi, "" if placed else replacement))
                placed = True
        for i, edits in local_edits.items():
            piece = pieces[i]
            new = piece.text
            for lo, hi, rep in sorted(edits, reverse=True):
                new = new[:lo] + rep + new[hi:]
            assert piece.out_index is not None
            out[piece.out_index] = _escape_text(new)
            changed = True
    return changed


def _finish_cell(cell: _Cell, out: list[str]) -> bool:
    """Turn a numeric cell whose value is protected into a text cell."""
    if cell.new_text is None or len(cell.v_tokens) < 2:
        return False
    v_start, *rest = cell.v_tokens
    v_end = rest[-1]
    value_tokens = [i for i in range(v_start + 1, v_end)]
    tag = out[cell.tag_index]
    kind = "str" if cell.has_formula else "inlineStr"
    if re.search(r"\st\s*=", tag):
        tag = re.sub(r"(\st\s*=\s*)(\"[^\"]*\"|'[^']*')", rf'\1"{kind}"', tag, count=1)
    else:
        tag = re.sub(r"^(<[^\s/>]+)", rf'\1 t="{kind}"', tag, count=1)
    out[cell.tag_index] = tag
    p = f"{cell.prefix}:" if cell.prefix else ""
    text = _escape_text(cell.new_text)
    for i in value_tokens:
        out[i] = ""
    if kind == "inlineStr":
        out[v_start] = f'<{p}is><{p}t xml:space="preserve">{text}'
        out[v_end] = f"</{p}t></{p}is>"
    else:
        out[v_start] = f"<{p}v>{text}"
        out[v_end] = f"</{p}v>"
    return True


def _rewrite_attrs(
    token: str, local_name: str, fam: str, attrs: Mapping[str, str], sweeper: Sweeper
) -> tuple[str, str | None]:
    external = local_name == "Relationship" and attrs.get("TargetMode") == "External"
    renamed: str | None = None

    def replace(m: re.Match[str]) -> str:
        nonlocal renamed
        key = m.group(2)
        attr_local = key.rsplit(":", 1)[-1]
        if not (attr_local in HUMAN_ATTRS or (external and attr_local == "Target")):
            return m.group()
        quote = m.group(4)[0]
        value = html.unescape(m.group(4)[1:-1])
        new = sweeper.apply(value)
        if new == value:
            return m.group()
        if local_name == "n" and attr_local == "v" and fam == "s":
            renamed = "s"  # a numeric pivot item that now holds text
        return f"{m.group(1)}{key}{m.group(3)}{quote}{_escape_attr(new, quote)}{quote}"

    new_token = _ATTR.sub(replace, token)
    if renamed is not None:
        qname = _NAME.match(new_token)
        assert qname is not None
        prefix, _ = _split(qname.group(1))
        renamed = f"{prefix}:s" if prefix else "s"
        new_token = f"<{renamed}" + new_token[len(qname.group(0)) :]
    return new_token, renamed


def _normalize_number(value: str) -> str:
    from airlock_engine.documents.xlsx.adapter import _normalize_number as normalize

    return normalize(value)
