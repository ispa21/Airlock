"""Masked page text for the rebuilt PDF (computed in the engine)."""

from __future__ import annotations

from airlock_engine.core.models import ExtractedDocument
from airlock_engine.masking.masker import MaskPlan
from airlock_engine.masking.sweep import Sweeper, splice


def pdf_sections(document: ExtractedDocument, plan: MaskPlan) -> list[tuple[str, str]]:
    """One (heading, text) section per page: page text, then text read from
    its pictures. Hidden PDF content is not carried over at all."""
    sweeper = Sweeper(plan.sweep)
    edits: dict[int, list[tuple[int, int, str]]] = {}
    for segment_id, start, end, text in plan.edits:
        edits.setdefault(segment_id, []).append((start, end, text))
    pages: dict[int, list[str]] = {}
    for segment in document.segments:
        if segment.locator.part != "page":
            continue
        head, _, rest = segment.locator.path.partition("/")
        if not head.isdigit():
            continue
        own = edits.get(segment.segment_id, [])
        for start, end, _ in own:
            sweeper.hits[segment.text[start:end]] += 1
        text = sweeper.apply(splice(segment.text, own))
        if rest:
            text = f"[Text read from a picture on this page]\n{text}"
        pages.setdefault(int(head), []).append(text)
    missing = sweeper.missing()
    second = Sweeper(missing, bounded=False) if missing else None
    sections = []
    for index in sorted(pages):
        text = "\n\n".join(pages[index])
        if second is not None:
            text = second.apply(text)
        sections.append((f"Page {index + 1}", text))
    return sections
