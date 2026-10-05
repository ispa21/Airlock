"""Decide whether a protected copy may leave Airlock (Phase 7).

The copy is read again exactly like an original (isolated worker, OCR when
the scan used it), its stored bytes are searched, and every detector runs on
it again. Then:

* **Protected values left behind** (exact text, any letter case for values
  that cannot be ordinary words, the same value written differently, or
  anywhere in the stored bytes) → *failed*. The copy cannot be saved.
* **Content the reader cannot check** (a copy never has any by design) →
  *failed*.
* **New findings** that are not Airlock's own replacements and not values the
  user chose to keep (for example a name the language model only recognises
  now) → *review*. Saving needs an explicit acknowledgement.
* Otherwise → *passed*.

Nothing here logs or returns a value: findings leave as masked previews.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from airlock_engine.core.models import ExtractedDocument, SegmentKind, TextSegment
from airlock_engine.detectors.pipeline import Detected
from airlock_engine.masking.sweep import Sweeper, needs_edges
from airlock_engine.scan.report import EntityInfo, preview
from airlock_engine.verification.raw import outside

#: Rows listed in a response; the counts always cover everything.
MAX_LISTED = 200
#: Normalised protected values at least this long are also searched in
#: normalised text (catches "4111-1111-…" left for "4111 1111 …").
MIN_NORMALIZED = 8

PASSED, REVIEW, FAILED = "passed", "review", "failed"


def normalize(value: str) -> str:
    return "".join(ch for ch in value.casefold() if ch.isalnum())


@dataclass
class CopyCheck:
    """What a copy must not contain, recorded when it is made. Holds original
    values, so it lives only in engine memory next to the copy."""

    #: (original value, entity type) that the copy must not contain.
    protected: list[tuple[str, str]]
    #: Text Airlock inserted (placeholders, fake values, generalised forms).
    replacements: frozenset[str]
    #: Normalised values the user chose to keep.
    kept: frozenset[str]
    use_ner: bool = True
    ocr: bool = True

    def __repr__(self) -> str:
        return f"CopyCheck(protected={len(self.protected)}, kept={len(self.kept)})"


@dataclass(frozen=True)
class Remaining:
    reason: str  # "protected" (left behind) or "new" (not seen before)
    entity_type: str
    entity_label: str
    preview: str
    location_kind: str
    location_label: str
    hidden: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "entity_type": self.entity_type,
            "entity_label": self.entity_label,
            "preview": self.preview,
            "location": {"kind": self.location_kind, "label": self.location_label},
            "hidden": self.hidden,
        }


@dataclass
class Verification:
    status: str
    protected_count: int
    leaks: list[Remaining] = field(default_factory=list)
    new: list[Remaining] = field(default_factory=list)
    unreadable: list[tuple[str, int]] = field(default_factory=list)
    kept_count: int = 0
    replacement_count: int = 0
    segment_count: int = 0
    ocr_used: bool = False

    @property
    def exportable_without_ack(self) -> bool:
        return self.status == PASSED

    def to_json(self) -> dict[str, Any]:
        remaining = (self.leaks + self.new)[:MAX_LISTED]
        return {
            "status": self.status,
            "passed": self.status == PASSED,
            "checked": {
                "protected_values": self.protected_count,
                "segments": self.segment_count,
                "ocr_used": self.ocr_used,
            },
            "remaining_count": len(self.leaks),
            "new_count": len(self.new),
            "remaining": [r.to_json() for r in remaining],
            "unreadable": [{"label": label, "count": n} for label, n in self.unreadable],
            "kept_count": self.kept_count,
            "replacement_count": self.replacement_count,
        }


_VISIBLE = frozenset({SegmentKind.BODY, SegmentKind.HEADER_FOOTER, SegmentKind.OCR})


def _info(entities: Mapping[str, EntityInfo], entity_type: str) -> EntityInfo:
    return entities.get(entity_type) or EntityInfo(entity_type, "OTHER", "company_rule")


def _remaining(
    reason: str,
    entity_type: str,
    value: str,
    segment: TextSegment | None,
    entities: Mapping[str, EntityInfo],
    part: str = "",
) -> Remaining:
    info = _info(entities, entity_type)
    if segment is None:
        kind, label, hidden = "file_data", f"Stored inside the file ({part})", True
    else:
        kind, label = segment.kind.value, segment.label
        hidden = segment.kind not in _VISIBLE
    return Remaining(
        reason,
        entity_type,
        info.label,
        preview(entity_type, info.quality, value),
        kind,
        label,
        hidden,
    )


def evaluate(
    document: ExtractedDocument,
    raw_hits: Sequence[tuple[int, str]],
    detected: Sequence[Detected],
    check: CopyCheck,
    entities: Mapping[str, EntityInfo],
) -> Verification:
    values = [v for v, _ in check.protected]
    segments = {s.segment_id: s for s in document.segments}
    result = Verification(
        PASSED,
        protected_count=len({v for v in values if v}),
        segment_count=len(document.segments),
        ocr_used=document.ocr_used,
    )
    reported: set[str] = set()

    def leak(index: int, segment: TextSegment | None, part: str = "") -> None:
        # One row per value, wherever and however often it is left behind.
        if values[index] in reported:
            return
        reported.add(values[index])
        value, entity_type = check.protected[index]
        result.leaks.append(_remaining("protected", entity_type, value, segment, entities, part))

    # 1. Protected values in the text a reader sees.
    exact = Sweeper((v, str(i)) for i, v in enumerate(values) if v)
    loose = Sweeper(
        (v.casefold(), str(i)) for i, v in enumerate(values) if v and not needs_edges(v)
    )
    long_norms = {
        n: i
        for i, v in enumerate(values)
        if len(n := normalize(v)) >= MIN_NORMALIZED and any(ch.isdigit() for ch in n)
    }
    inserted = Sweeper((r, r) for r in check.replacements if len(r) >= 2)
    inserted_folded = Sweeper((r.casefold(), r) for r in check.replacements if len(r) >= 2)
    for segment in document.segments:
        for _, _, tag in outside(exact, segment.text, inserted):
            leak(int(tag), segment)
        for _, _, tag in outside(loose, segment.text.casefold(), inserted_folded):
            leak(int(tag), segment)
        if long_norms:
            flat = normalize(segment.text)
            for norm, position in long_norms.items():
                if norm in flat:
                    leak(position, segment)

    # 2. Protected values anywhere in the stored bytes.
    for position, part in raw_hits:
        if 0 <= position < len(values):
            leak(position, None, part)

    # 3. Everything the detectors find in the copy.
    norms = {normalize(v): i for i, v in enumerate(values) if len(normalize(v)) >= 3}
    spans_cache: dict[int, list[tuple[int, int]]] = {}
    for item in detected:
        d = item.detection
        where = segments.get(d.segment_id)
        value = d.matched_value.reveal()
        n = normalize(value)
        if n in norms:
            leak(norms[n], where)
            continue
        if n in check.kept:
            result.kept_count += 1
            continue
        if where is not None:
            spans = spans_cache.get(d.segment_id)
            if spans is None:
                spans = [(s, e) for s, e, _ in inserted.find(where.text)]
                spans_cache[d.segment_id] = spans
            if any(s < d.end and d.start < e for s, e in spans):
                result.replacement_count += 1
                continue
        containing = next(
            (i for p, i in norms.items() if len(p) >= MIN_NORMALIZED and p in n), None
        )
        if containing is not None:
            leak(containing, where)
            continue
        result.new.append(_remaining("new", d.entity_type, value, where, entities))

    # 4. Anything the reader could not check. A copy has none by design.
    result.unreadable = sorted(Counter(u.label for u in document.unextracted).items())

    if result.leaks or result.unreadable:
        result.status = FAILED
    elif result.new:
        result.status = REVIEW
    return result


# --- the AI-safe text ---------------------------------------------------------------

#: What a reader of the document sees; comments, properties, tracked
#: deletions and other hidden parts are left out of the text for AI.
_AI_KINDS = frozenset(
    {
        SegmentKind.BODY,
        SegmentKind.HEADER_FOOTER,
        SegmentKind.NOTE,
        SegmentKind.OCR,
        SegmentKind.CHART,
    }
)
_XLSX_REF = re.compile(r"^([A-Z]{1,3})([0-9]{1,7})$")
_CSV_REF = re.compile(r"^r([0-9]+)c([0-9]+)$")


def _column(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _cell(segment: TextSegment) -> tuple[str, int, int] | None:
    path = segment.locator.path
    if m := _XLSX_REF.match(path):
        return segment.locator.part, int(m.group(2)), _column(m.group(1))
    if segment.locator.part == "table" and (m := _CSV_REF.match(path)):
        return "table", int(m.group(1)), int(m.group(2)) - 1
    return None


def ai_text(document: ExtractedDocument) -> str:
    """The copy's readable text, in reading order; table cells as tab-separated rows."""
    blocks: list[str] = []
    row_key: tuple[str, int] | None = None
    row: dict[int, str] = {}
    part = ""

    def flush() -> None:
        nonlocal row
        if row:
            width = max(row) + 1
            blocks.append("\t".join(row.get(c, "") for c in range(width)).rstrip("\t"))
        row = {}

    for segment in document.segments:
        if segment.kind not in _AI_KINDS or not segment.text.strip():
            continue
        cell = _cell(segment)
        if segment.locator.part != part:
            flush()
            if blocks:
                blocks.append("")
            part = segment.locator.part
            if cell is not None and cell[0] != "table" and " · " in segment.label:
                blocks.append(segment.label.split(" · ", 1)[0])
        if cell is None:
            flush()
            row_key = None
            blocks.append(segment.text.strip("\r\n"))
            continue
        key = (cell[0], cell[1])
        if key != row_key:
            flush()
            row_key = key
        row[cell[2]] = " ".join(segment.text.split())
    flush()
    return "\n".join(blocks).strip() + "\n"
