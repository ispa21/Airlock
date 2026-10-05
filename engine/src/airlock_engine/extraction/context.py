"""Collects extracted text from adapters and enforces extraction limits."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from airlock_engine.core import errors
from airlock_engine.core.models import (
    ExtractedDocument,
    Locator,
    SegmentKind,
    TextBox,
    TextSegment,
    UnextractedPart,
)

if TYPE_CHECKING:
    from PIL import Image

    from airlock_engine.core.interfaces import OcrProvider


@dataclass(frozen=True, slots=True)
class ExtractionOptions:
    ocr: bool = True
    ocr_embedded_images: bool = True
    max_ocr_images: int = 200
    max_pages: int = 5_000
    max_chars: int = 30_000_000
    max_segments: int = 500_000
    max_depth: int = 2
    #: Longest side, in pixels, an image is scaled down to before OCR.
    max_ocr_side: int = 4_000
    #: Images smaller than this on either side (icons, bullets) are not OCR'd.
    min_ocr_side: int = 24
    min_ocr_score: float = 0.5

    def to_wire(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_wire(cls, data: dict[str, Any]) -> ExtractionOptions:
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)


ProgressFn = Callable[[str, int, int], None]
EmbeddedHandler = Callable[["ExtractionContext", bytes, str, str, str], None]


class ExtractionContext:
    def __init__(
        self,
        options: ExtractionOptions | None = None,
        *,
        progress: ProgressFn | None = None,
        ocr_factory: Callable[[], OcrProvider] | None = None,
        embedded_handler: EmbeddedHandler | None = None,
    ) -> None:
        self.options = options or ExtractionOptions()
        self._progress = progress
        self._ocr_factory = ocr_factory
        self._ocr: OcrProvider | None = None
        self._embedded_handler = embedded_handler
        self._segments: list[TextSegment] = []
        self._unextracted: list[UnextractedPart] = []
        self._chars = 0
        self._ocr_images = 0
        self._part_prefix = ""
        self._label_prefix = ""
        self._last_progress = 0.0
        self._adapter_state: dict[str, str] = {}
        self.depth = 0
        self.ocr_used = False
        self.counts: Counter[str] = Counter()

    # ----------------------------------------------------------------- output
    def add(
        self,
        text: str,
        part: str,
        path: str,
        *,
        kind: SegmentKind = SegmentKind.BODY,
        label: str = "",
        context: str = "",
        boxes: tuple[TextBox, ...] = (),
    ) -> None:
        if not text or text.isspace():
            return
        if len(self._segments) >= self.options.max_segments:
            raise errors.content_too_large("too many separate pieces of text")
        self._chars += len(text)
        if self._chars > self.options.max_chars:
            raise errors.content_too_large("too much text")
        self._segments.append(
            TextSegment(
                segment_id=len(self._segments),
                text=text,
                locator=Locator(self._part_prefix + part, path),
                kind=kind,
                label=self._label_prefix + label,
                context=context,
                boxes=boxes,
            )
        )

    def unextracted(self, kind: str, label: str) -> None:
        self._unextracted.append(UnextractedPart(kind=kind, label=self._label_prefix + label))

    def count(self, key: str, n: int = 1) -> None:
        if self.depth == 0:
            self.counts[key] += n

    def set_state(self, key: str, value: str) -> None:
        """Record adapter state for the top-level document (ignored when nested)."""
        if self.depth == 0:
            self._adapter_state[key] = value

    def progress(self, stage: str, done: int, total: int) -> None:
        if self._progress is None or self.depth > 0:
            return
        now = time.monotonic()
        if done in (0, total) or now - self._last_progress >= 0.2:
            self._last_progress = now
            self._progress(stage, done, total)

    # --------------------------------------------------------------- embedded
    @contextmanager
    def nested(self, part: str, label: str) -> Iterator[None]:
        saved = (self._part_prefix, self._label_prefix)
        self._part_prefix = f"{self._part_prefix}{part}!/"
        self._label_prefix = f"{self._label_prefix}{label} · "
        self.depth += 1
        try:
            yield
        finally:
            self.depth -= 1
            self._part_prefix, self._label_prefix = saved

    def embedded(self, data: bytes, name: str, part: str, label: str) -> None:
        """Extract a file embedded in the current document (attachment, OLE package...)."""
        if self.depth == 0:
            self.counts["embedded"] += 1
        if self._embedded_handler is None or self.depth >= self.options.max_depth:
            self.unextracted("embedded_object", label)
            return
        self._embedded_handler(self, data, name, part, label)

    # -------------------------------------------------------------------- OCR
    def ocr_image(
        self,
        image: Image.Image,
        part: str,
        path: str,
        *,
        label: str,
        kind: SegmentKind = SegmentKind.OCR,
        embedded: bool = False,
    ) -> bool:
        """Recognise text in ``image`` and add it as one segment with line boxes."""
        width, height = image.size
        if min(width, height) < self.options.min_ocr_side:
            return False
        if not self.options.ocr or (embedded and not self.options.ocr_embedded_images):
            self.unextracted("image", label)
            return False
        if self._ocr_images >= self.options.max_ocr_images:
            self.unextracted("image_ocr_limit", label)
            return False
        provider = self._ocr_provider()
        if provider is None:
            self.unextracted("image", label)
            return False

        scale = min(1.0, self.options.max_ocr_side / max(width, height))
        prepared = image.convert("RGB")
        if scale < 1.0:
            prepared = prepared.resize((max(1, int(width * scale)), max(1, int(height * scale))))
        lines = [
            line
            for line in provider.recognize(prepared)
            if line.score >= self.options.min_ocr_score and line.text.strip()
        ]
        self._ocr_images += 1
        self.ocr_used = True
        self.count("images_ocr")
        if not lines:
            return True

        parts: list[str] = []
        boxes: list[TextBox] = []
        offset = 0
        for line in lines:
            x0, y0, x1, y1 = (v / scale for v in line.box)
            boxes.append(TextBox(offset, offset + len(line.text), x0, y0, x1, y1))
            parts.append(line.text)
            offset += len(line.text) + 1
        self.add("\n".join(parts), part, path, kind=kind, label=label, boxes=tuple(boxes))
        return True

    def _ocr_provider(self) -> OcrProvider | None:
        if self._ocr is None and self._ocr_factory is not None:
            self._ocr = self._ocr_factory()
        return self._ocr

    # ------------------------------------------------------------------ build
    def build(self, format_id: str) -> ExtractedDocument:
        return ExtractedDocument(
            format=format_id,
            segments=tuple(self._segments),
            unextracted=tuple(self._unextracted),
            ocr_used=self.ocr_used,
            counts=dict(self.counts),
            adapter_state=dict(self._adapter_state),
        )
