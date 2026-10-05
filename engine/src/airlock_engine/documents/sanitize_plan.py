"""The sanitize plan as the worker receives it, and the worker's result."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

Box = tuple[float, float, float, float]
EMBED = "!/"


@dataclass
class SanitizePlan:
    #: (part, path, start, end, replacement) — exact edits, by segment locator.
    edits: list[tuple[str, str, int, int, str]] = field(default_factory=list)
    sweep: list[tuple[str, str]] = field(default_factory=list)
    #: (part, path) → boxes to black out, or None for the whole image.
    paint: dict[tuple[str, str], list[Box] | None] = field(default_factory=dict)
    strip_metadata: bool = True
    adapter_state: dict[str, str] = field(default_factory=dict)
    #: PDF only: (heading, text) per output section, already masked by the engine.
    pdf_pages: list[tuple[str, str]] = field(default_factory=list)

    def __repr__(self) -> str:  # holds original values
        return f"SanitizePlan(edits={len(self.edits)}, sweep={len(self.sweep)})"

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> SanitizePlan:
        return cls(
            edits=[(str(p), str(q), int(s), int(e), str(t)) for p, q, s, e, t in data["edits"]],
            sweep=[(str(v), str(t)) for v, t in data["sweep"]],
            paint={
                (str(part), str(path)): None
                if boxes is None
                else [(float(a), float(b), float(c), float(d)) for a, b, c, d in boxes]
                for part, path, boxes in data["paint"]
            },
            strip_metadata=bool(data.get("strip_metadata", True)),
            adapter_state={str(k): str(v) for k, v in dict(data["adapter_state"]).items()},
            pdf_pages=[(str(h), str(t)) for h, t in data.get("pdf_pages", [])],
        )

    def embedded(self, part: str) -> SanitizePlan:
        """The plan for a file embedded at ``part`` (locators prefixed ``part!/``)."""
        prefix = part + EMBED
        return SanitizePlan(
            edits=[
                (p[len(prefix) :], q, s, e, t)
                for p, q, s, e, t in self.edits
                if p.startswith(prefix)
            ],
            sweep=self.sweep,
            paint={
                (p[len(prefix) :], q): boxes
                for (p, q), boxes in self.paint.items()
                if p.startswith(prefix)
            },
            strip_metadata=self.strip_metadata,
        )

    def without_structure(self) -> SanitizePlan:
        """Second sweep pass: no edits, painting or removals, only the sweep."""
        return SanitizePlan(strip_metadata=False, adapter_state=self.adapter_state)


@dataclass
class SanitizeOutput:
    data: bytes
    #: Hidden or unreadable content removed from the copy: (kind, label).
    removed: list[tuple[str, str]] = field(default_factory=list)
    extension: str = ""
