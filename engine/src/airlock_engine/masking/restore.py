"""Local restoration of AI responses (Phase 12).

Restores only placeholders recorded in the vault for one scope (a
conversation or a protected copy). Nothing is guessed:

* A placeholder that starts or ends with a letter, digit or underscore must
  stand alone on that side: ``PERSON_001``, ``PERSON_001's``,
  ``(PERSON_001).`` and ``**PERSON_001**`` are restored; ``PERSON_0011``,
  ``XPERSON_001``, ``PERSON_001A`` and ``person_001`` are not.
* Markdown sometimes escapes underscores; ``PERSON\\_001`` is the same
  placeholder.
* Bracketed placeholders from copies made before Phase 12 (``[EMAIL_1]``)
  delimit themselves; synthetic stand-ins (``Alex Example``) follow the edge
  rule above.
* Longer placeholders win where two could match at the same place, and every
  occurrence of a placeholder becomes the same original.
* Placeholder-shaped tokens the scope does not know (``PERSON_999``, or one
  from another conversation) are reported and left exactly as they are.

Nothing here logs or returns a value except the restored text itself, which
only leaves the engine on an explicit restore or review request.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from airlock_engine.masking.replacements import REDACTED, placeholder_labels


def _word(ch: str) -> bool:
    return ch.isalnum() or ch == "_"


def _alone(text: str, start: int, end: int) -> bool:
    token = text[start:end]
    if _word(token[0]) and start > 0 and _word(text[start - 1]):
        return False
    return not (_word(token[-1]) and end < len(text) and _word(text[end]))


def _variants(placeholder: str) -> list[str]:
    escaped = placeholder.replace("_", "\\_")
    return [placeholder] if escaped == placeholder else [placeholder, escaped]


def _shape() -> re.Pattern[str]:
    labels = "|".join(sorted(placeholder_labels(), key=len, reverse=True))
    return re.compile(rf"\[(?:{labels})_\d+\]|(?:{labels})(?:_|\\_)\d+")


_SHAPE = _shape()


@dataclass
class Restoration:
    text: str
    #: Occurrences replaced.
    restored: int = 0
    #: Known placeholder → occurrences in the text.
    found: Counter[str] = field(default_factory=Counter)
    #: Placeholder-shaped tokens this scope does not know, in order of appearance.
    unknown: list[str] = field(default_factory=list)

    def __repr__(self) -> str:  # the text may hold original values
        return f"Restoration(restored={self.restored}, unknown={len(self.unknown)})"


class Restorer:
    def __init__(self, mapping: Mapping[str, str]) -> None:
        """``mapping``: placeholder (or synthetic stand-in) → original value."""
        self._mapping = {p: v for p, v in mapping.items() if p and p != REDACTED}
        self._by_variant: dict[str, str] = {}
        for placeholder in self._mapping:
            for variant in _variants(placeholder):
                self._by_variant.setdefault(variant, placeholder)
        self._ordered = sorted(self._by_variant, key=len, reverse=True)
        self._pattern = (
            re.compile("|".join(re.escape(v) for v in self._ordered)) if self._ordered else None
        )

    def matches(self, text: str) -> list[tuple[int, int, str]]:
        """Known placeholders as (start, end, placeholder), left to right."""
        out: list[tuple[int, int, str]] = []
        if self._pattern is None:
            return out
        pos = 0
        while (m := self._pattern.search(text, pos)) is not None:
            start = m.start()
            # A shorter variant may stand alone where the longest match does not.
            found = next(
                (
                    v
                    for v in self._ordered
                    if len(v) <= len(m.group())
                    and text.startswith(v, start)
                    and _alone(text, start, start + len(v))
                ),
                None,
            )
            if found is None:
                pos = start + 1
                continue
            out.append((start, start + len(found), self._by_variant[found]))
            pos = start + len(found)
        return out

    def unknown(self, text: str, known: Iterable[tuple[int, int, str]] = ()) -> list[str]:
        spans = [(s, e) for s, e, _ in known]
        seen: dict[str, None] = {}
        for m in _SHAPE.finditer(text):
            if not _alone(text, m.start(), m.end()):
                continue
            if any(s < m.end() and m.start() < e for s, e in spans):
                continue
            token = m.group().replace("\\_", "_")
            if token not in self._mapping:
                seen.setdefault(token, None)
        return list(seen)

    def analyze(self, text: str) -> Restoration:
        """What a restore would do, without changing the text."""
        known = self.matches(text)
        return Restoration(
            text,
            0,
            Counter(p for *_, p in known),
            self.unknown(text, known),
        )

    def restore(self, text: str) -> Restoration:
        known = self.matches(text)
        out: list[str] = []
        pos = 0
        for start, end, placeholder in known:
            out.append(text[pos:start])
            out.append(self._mapping[placeholder])
            pos = end
        out.append(text[pos:])
        return Restoration(
            "".join(out),
            len(known),
            Counter(p for *_, p in known),
            self.unknown(text, known),
        )
