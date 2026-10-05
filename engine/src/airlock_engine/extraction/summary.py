"""Content-free description of what was extracted, for the UI and logs."""

from __future__ import annotations

from collections import Counter
from typing import Any, Final

from airlock_engine.core.models import ExtractedDocument, SegmentKind
from airlock_engine.documents.formats import FormatSpec

_MAX_UNEXTRACTED: Final = 50


def summarize(doc: ExtractedDocument, spec: FormatSpec, duration_ms: float) -> dict[str, Any]:
    segments: Counter[SegmentKind] = Counter()
    chars: Counter[SegmentKind] = Counter()
    words: Counter[SegmentKind] = Counter()
    for segment in doc.segments:
        segments[segment.kind] += 1
        chars[segment.kind] += len(segment.text)
        words[segment.kind] += len(segment.text.split())

    unextracted: list[dict[str, Any]] = []
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for part in doc.unextracted:
        key = (part.kind, part.label)
        if key in seen:
            seen[key]["count"] += 1
        elif len(unextracted) < _MAX_UNEXTRACTED:
            entry = {"kind": part.kind, "label": part.label, "count": 1}
            seen[key] = entry
            unextracted.append(entry)

    return {
        "format": spec.format_id,
        "format_label": spec.label,
        "segment_count": len(doc.segments),
        "char_count": sum(chars.values()),
        "word_count": sum(words.values()),
        "parts": [
            {
                "kind": kind.value,
                "segments": segments[kind],
                "chars": chars[kind],
                "words": words[kind],
            }
            for kind in SegmentKind
            if segments[kind]
        ],
        "counts": dict(doc.counts),
        "ocr_used": doc.ocr_used,
        "unextracted": unextracted,
        "unextracted_total": len(doc.unextracted),
        "duration_ms": round(duration_ms),
    }
