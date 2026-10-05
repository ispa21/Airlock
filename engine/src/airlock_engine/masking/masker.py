"""Turns a policy decision into a sanitize plan.

The plan has three parts:

* ``edits``: exact replacements for each region, by segment and offsets;
* ``sweep``: value → replacement pairs applied to the whole file, so other
  copies of a protected value are replaced too;
* ``paint``: image areas to black out (text found by OCR cannot be edited).

The plan carries original values: it only ever goes to the isolated worker
over its private pipe, never to the UI or a log.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from airlock_engine.core.models import Action, ExtractedDocument, Finding, TextSegment
from airlock_engine.masking.replacements import Replacer
from airlock_engine.policy.engine import PolicyDecision

Box = tuple[float, float, float, float]


class BlockedFindings(Exception):
    """The decision still contains BLOCK regions."""

    def __init__(self, count: int) -> None:
        super().__init__(f"{count} blocked regions")
        self.count = count


@dataclass
class MaskPlan:
    edits: list[tuple[int, int, int, str]] = field(default_factory=list)
    sweep: list[tuple[str, str]] = field(default_factory=list)
    #: (part, path, boxes) — boxes None means the whole image.
    paint: list[tuple[str, str, list[Box] | None]] = field(default_factory=list)
    #: replacement text → (original value, entity type), reversible replacements only.
    reversible: dict[str, tuple[str, str]] = field(default_factory=dict)
    counts: Counter[str] = field(default_factory=Counter)

    def __repr__(self) -> str:  # holds original values
        return f"MaskPlan(edits={len(self.edits)}, sweep={len(self.sweep)})"

    def to_wire(self, document: ExtractedDocument, *, strip_metadata: bool) -> dict[str, Any]:
        segments = {s.segment_id: s for s in document.segments}
        return {
            "edits": [
                [segments[sid].locator.part, segments[sid].locator.path, start, end, text]
                for sid, start, end, text in self.edits
            ],
            "sweep": [[value, text] for value, text in self.sweep],
            "paint": [
                [part, path, None if boxes is None else [list(b) for b in boxes]]
                for part, path, boxes in self.paint
            ],
            "strip_metadata": strip_metadata,
            "adapter_state": dict(document.adapter_state),
        }


def build_plan(document: ExtractedDocument, decision: PolicyDecision) -> MaskPlan:
    if decision.blocked:
        raise BlockedFindings(decision.blocked)
    segments = {s.segment_id: s for s in document.segments}
    findings = {f.finding_id: f for f in decision.findings}
    replacer = Replacer("\n".join(s.text for s in document.segments))
    plan = MaskPlan()
    painted: dict[tuple[str, str], list[Box] | None] = {}

    for region in decision.regions:
        segment = segments[region.segment_id]
        primary = findings[region.primary_id]
        value = segment.text[region.start : region.end]
        text = replacer.text_for(
            primary.detection.entity_type, value, region.action, region.mask_style
        )
        plan.edits.append((region.segment_id, region.start, region.end, text))
        plan.sweep.append((value, text))
        plan.counts[region.action.value] += 1
        # Covered findings: sweep their own values too, wherever else they appear.
        for member_id in region.member_ids:
            member = findings[member_id]
            if member_id == region.primary_id or member.detection.end - member.detection.start < 3:
                continue
            plan.sweep.append(
                _member_sweep(replacer, member, segment, region.action, region.mask_style)
            )
        if segment.boxes or _is_image_text(segment):
            key = (segment.locator.part, segment.locator.path)
            boxes = _boxes_for(segment, region.start, region.end)
            if boxes is None or painted.get(key, []) is None:
                painted[key] = None
            else:
                painted.setdefault(key, [])
                current = painted[key]
                assert current is not None
                current.extend(b for b in boxes if b not in current)

    plan.paint = [(part, path, boxes) for (part, path), boxes in painted.items()]
    plan.reversible = dict(replacer.reversible)
    return plan


def _member_sweep(
    replacer: Replacer, member: Finding, segment: TextSegment, action: Action, style: str
) -> tuple[str, str]:
    d = member.detection
    value = segment.text[d.start : d.end]
    return value, replacer.text_for(d.entity_type, value, action, style)


def _is_image_text(segment: TextSegment) -> bool:
    return segment.kind.value == "ocr"


def _boxes_for(segment: TextSegment, start: int, end: int) -> list[Box] | None:
    """Line boxes overlapping [start, end); None (whole image) if unknown."""
    boxes = [(b.x0, b.y0, b.x1, b.y1) for b in segment.boxes if b.start < end and start < b.end]
    return boxes or None
