"""Replace every occurrence of a protected value, wherever it is stored.

Detection finds a value in one place; the same value is often stored again
in places a detector could not judge on its own (a pivot cache, an orphaned
shared string, a hidden copy of a sheet). The sweeper replaces all of them.

Short plain words match on word edges only ("Ram" does not hit "Ramesh").
Values that cannot be ordinary words (anything with digits or symbols, or 8+
characters: ids, keys, e-mail addresses, URLs, names with surnames) match
anywhere, even glued to other text. A value that never matches anywhere in
the file is swept a second time without edges, so a detected value cannot
survive because of an edge case.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence

#: Characters a replacement must never contain: they would change the
#: structure of CSV, TSV, INI and similar files around the value.
UNSAFE_REPLACEMENT_CHARS = frozenset(",;\"'\t\r\n|")


def needs_edges(value: str) -> bool:
    """Only short plain words need word edges; everything else matches anywhere."""
    return len(value) < 8 and all(ch.isalpha() or ch == " " for ch in value)


def _bounded(text: str, start: int, end: int) -> bool:
    if start > 0 and text[start].isalnum() and text[start - 1].isalnum():
        return False
    return not (end < len(text) and text[end - 1].isalnum() and text[end].isalnum())


class Sweeper:
    def __init__(self, pairs: Iterable[tuple[str, str]], *, bounded: bool = True) -> None:
        self.replacements: dict[str, str] = {}
        for value, text in pairs:
            if value and value not in self.replacements:
                self.replacements[value] = text
        self.bounded = bounded
        ordered = sorted(self.replacements, key=len, reverse=True)
        self._pattern = re.compile("|".join(re.escape(v) for v in ordered)) if ordered else None
        self._by_length = ordered
        self.hits: Counter[str] = Counter()

    def __bool__(self) -> bool:
        return self._pattern is not None

    def find(self, text: str) -> list[tuple[int, int, str]]:
        """Non-overlapping matches as (start, end, replacement), left to right."""
        if self._pattern is None or not text:
            return []
        out: list[tuple[int, int, str]] = []
        pos = 0
        while pos < len(text):
            m = self._pattern.search(text, pos)
            if m is None:
                break
            start, value = m.start(), m.group()
            if self.bounded and needs_edges(value) and not _bounded(text, start, m.end()):
                # A shorter value may still match on word edges here.
                value = next(
                    (
                        v
                        for v in self._by_length
                        if len(v) < len(m.group())
                        and text.startswith(v, start)
                        and (not needs_edges(v) or _bounded(text, start, start + len(v)))
                    ),
                    "",
                )
                if not value:
                    pos = start + 1
                    continue
            end = start + len(value)
            out.append((start, end, self.replacements[value]))
            self.hits[value] += 1
            pos = end
        return out

    def apply(self, text: str) -> str:
        matches = self.find(text)
        if not matches:
            return text
        return splice(text, matches)

    def missing(self) -> list[tuple[str, str]]:
        """Values that never matched (used for the unbounded second pass)."""
        return [(v, t) for v, t in self.replacements.items() if not self.hits[v]]


def splice(text: str, edits: Sequence[tuple[int, int, str]]) -> str:
    """Apply non-overlapping (start, end, replacement) edits."""
    out: list[str] = []
    pos = 0
    for start, end, replacement in sorted(edits):
        if start < pos:
            continue  # overlapping edit: the earlier one already covers it
        out.append(text[pos:start])
        out.append(replacement)
        pos = end
    out.append(text[pos:])
    return "".join(out)
