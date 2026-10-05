"""Plain text, configuration, source code, CSV and TSV."""

from __future__ import annotations

import codecs
import csv
import io
import re
from collections.abc import Iterator
from typing import Final

from airlock_engine.core.interfaces import DocumentAdapter
from airlock_engine.extraction.context import ExtractionContext

#: Files up to this many characters are a single segment (best detector context).
_SINGLE_SEGMENT_CHARS: Final = 1_000_000
_CHUNK_CHARS: Final = 256_000
_PEM_EXTENSION_LIMIT: Final = 1_000_000
#: Larger delimited files are scanned as plain text to bound memory use.
_MAX_TABLE_CHARS: Final = 50_000_000
_BOMS: Final = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)
_NUMBER: Final = re.compile(r"^[\s$€£₹+\-]*[\d.,]+%?\s*$")


def decode_text(data: bytes) -> tuple[str, str]:
    """Decode with BOM detection, then UTF-8, then Windows-1252, then Latin-1."""
    for bom, encoding in _BOMS:
        if data.startswith(bom):
            return data.decode(encoding), encoding
    for encoding in ("utf-8", "cp1252"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1"), "latin-1"


def column_name(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    name = ""
    index += 1
    while index:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name


def _chunks(text: str) -> Iterator[tuple[int, int]]:
    """Line-aligned chunks that never split a PEM block (private keys span lines)."""
    if len(text) <= _SINGLE_SEGMENT_CHARS:
        yield 0, len(text)
        return
    start = 0
    while start < len(text):
        end = text.find("\n", start + _CHUNK_CHARS)
        end = len(text) if end == -1 else end + 1
        chunk = text[start:end]
        if chunk.rfind("-----BEGIN ") > chunk.rfind("-----END "):
            close = text.find("-----END ", end, end + _PEM_EXTENSION_LIMIT)
            if close != -1:
                line_end = text.find("\n", close)
                end = len(text) if line_end == -1 else line_end + 1
        yield start, end
        start = end


class PlainTextAdapter(DocumentAdapter):
    formats = ("txt", "json", "yaml", "xml", "toml", "ini", "env", "code")

    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        text, encoding = decode_text(data)
        ctx.set_state("encoding", encoding)
        self.extract_text(text, ctx)

    @staticmethod
    def extract_text(text: str, ctx: ExtractionContext) -> None:
        line = 1
        for start, end in _chunks(text):
            chunk = text[start:end]
            lines_in_chunk = chunk.count("\n")
            last = line + max(lines_in_chunk - (1 if chunk.endswith("\n") else 0), 0)
            label = f"Line {line}" if last == line else f"Lines {line}–{last}"
            ctx.add(chunk, "text", f"char/{start}", label=label)
            line += lines_in_chunk
        ctx.count("lines", text.count("\n") + (0 if text.endswith("\n") or not text else 1))


class DelimitedTextAdapter(DocumentAdapter):
    formats = ("csv", "tsv")

    def __init__(self, *, tab_separated: bool = False) -> None:
        self._tab = tab_separated

    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        text, encoding = decode_text(data)
        ctx.set_state("encoding", encoding)
        delimiter = "\t" if self._tab else _sniff_delimiter(text[:65536])
        ctx.set_state("delimiter", delimiter)
        csv.field_size_limit(16 * 1024 * 1024)
        try:
            if len(text) > _MAX_TABLE_CHARS:
                raise csv.Error("too large to parse as a table")
            rows = list(
                csv.reader(io.StringIO(text, newline=""), delimiter=delimiter, strict=False)
            )
        except csv.Error:
            # Unparseable as a table: fall back to scanning it as plain text.
            ctx.set_state("table_fallback", "1")
            PlainTextAdapter.extract_text(text, ctx)
            return

        header: list[str] = []
        if rows and _looks_like_header(rows[0]):
            header = [cell.strip() for cell in rows[0]]
        total = len(rows)
        for r, row in enumerate(rows):
            for c, cell in enumerate(row):
                context = header[c] if header and r > 0 and c < len(header) else ""
                ctx.add(
                    cell,
                    "table",
                    f"r{r + 1}c{c + 1}",
                    label=f"Row {r + 1} · Column {column_name(c)}",
                    context=context,
                )
            if r % 2000 == 0:
                ctx.progress("rows", r, total)
        ctx.progress("rows", total, total)
        ctx.count("rows", total)


def _sniff_delimiter(sample: str) -> str:
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|").delimiter
    except csv.Error:
        return ","


def _looks_like_header(row: list[str]) -> bool:
    cells = [c.strip() for c in row if c.strip()]
    return bool(cells) and not any(_NUMBER.match(c) for c in cells)
