"""JSON wire format between the extraction worker and the engine.

JSON rather than pickle: the worker parses hostile input, so the parent must
never deserialize anything that could execute code.
"""

from __future__ import annotations

from typing import Any

from airlock_engine.core.models import (
    ExtractedDocument,
    Locator,
    SegmentKind,
    TextBox,
    TextSegment,
    UnextractedPart,
)


class WireError(ValueError):
    pass


def document_to_wire(doc: ExtractedDocument) -> dict[str, Any]:
    return {
        "format": doc.format,
        "ocr_used": doc.ocr_used,
        "counts": doc.counts,
        "adapter_state": doc.adapter_state,
        "unextracted": [[u.kind, u.label] for u in doc.unextracted],
        "segments": [
            [
                s.segment_id,
                s.text,
                s.locator.part,
                s.locator.path,
                s.kind.value,
                s.label,
                s.context,
                [[b.start, b.end, b.x0, b.y0, b.x1, b.y1] for b in s.boxes],
            ]
            for s in doc.segments
        ],
    }


def _str(value: object) -> str:
    if not isinstance(value, str):
        raise WireError("expected string")
    return value


def _int(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise WireError("expected int")
    return value


def _num(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise WireError("expected number")
    return float(value)


def document_from_wire(data: object) -> ExtractedDocument:
    if not isinstance(data, dict):
        raise WireError("expected object")
    try:
        segments = []
        for raw in data["segments"]:
            seg_id, text, part, path, kind, label, context, boxes = raw
            segments.append(
                TextSegment(
                    segment_id=_int(seg_id),
                    text=_str(text),
                    locator=Locator(_str(part), _str(path)),
                    kind=SegmentKind(_str(kind)),
                    label=_str(label),
                    context=_str(context),
                    boxes=tuple(
                        TextBox(
                            _int(b[0]), _int(b[1]), _num(b[2]), _num(b[3]), _num(b[4]), _num(b[5])
                        )
                        for b in boxes
                    ),
                )
            )
        counts = {_str(k): _int(v) for k, v in dict(data["counts"]).items()}
        state = {_str(k): _str(v) for k, v in dict(data["adapter_state"]).items()}
        unextracted = tuple(UnextractedPart(_str(k), _str(lbl)) for k, lbl in data["unextracted"])
        ocr_used = data["ocr_used"]
        if not isinstance(ocr_used, bool):
            raise WireError("expected bool")
        return ExtractedDocument(
            format=_str(data["format"]),
            segments=tuple(segments),
            unextracted=unextracted,
            ocr_used=ocr_used,
            counts=counts,
            adapter_state=state,
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise WireError("malformed extraction result") from exc
