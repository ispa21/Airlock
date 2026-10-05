"""Extension points. Each later phase provides implementations of these.

Keeping them abstract here is what lets the NER model, the OCR engine or a
document library be swapped without touching the rest of the pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from airlock_engine.core.models import DetectionResult, ExtractedDocument, TextSegment

if TYPE_CHECKING:
    from PIL import Image

    from airlock_engine.extraction.context import ExtractionContext


@dataclass(frozen=True, slots=True)
class Replacement:
    """A single edit to apply to a segment when producing the safe copy."""

    segment_id: int
    start: int
    end: int
    replacement_text: str


class DocumentAdapter(ABC):
    """One implementation per document family (PDF, OOXML, text, image...).

    Adapters work on bytes: the original file is read once, read-only, and is
    never handed to an adapter as a writable path.
    """

    #: Canonical format ids this adapter handles, e.g. ``("docx", "docm")``.
    formats: tuple[str, ...] = ()

    @abstractmethod
    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        """Emit every text-bearing part of ``data`` into ``ctx``.

        Must include hidden content that could leak: comments, speaker notes,
        hidden sheets, headers/footers, tracked changes, document metadata,
        link targets and text inside images. Anything that cannot be read is
        reported with ``ctx.unextracted`` rather than silently skipped.
        """

    def sanitize(
        self, data: bytes, document: ExtractedDocument, replacements: Sequence[Replacement]
    ) -> bytes:
        """Return a sanitized copy of ``data`` (Phase 5)."""
        raise NotImplementedError


class Detector(ABC):
    """Finds sensitive entities in text. Detectors never decide actions."""

    #: Stable identifier shown in the privacy report, e.g. ``"regex.email"``.
    name: str

    @abstractmethod
    def detect(self, segment: TextSegment) -> Iterable[DetectionResult]: ...


@dataclass(frozen=True, slots=True)
class NerEntity:
    label: str
    start: int
    end: int
    score: float


class NerProvider(ABC):
    """A local NER model. The NER detector adapts its labels to entity types."""

    name: str

    @abstractmethod
    def load(self, model_dir: Path) -> None:
        """Load model weights from local disk. Must not download anything."""

    @abstractmethod
    def entities(self, text: str) -> Sequence[NerEntity]: ...


@dataclass(frozen=True, slots=True)
class OcrLine:
    text: str
    score: float
    #: Axis-aligned bounding box in image pixels: (x0, y0, x1, y1).
    box: tuple[float, float, float, float]


class OcrProvider(ABC):
    """A local OCR engine used for images, scanned PDF pages and embedded pictures."""

    name: str

    @abstractmethod
    def recognize(self, image: Image.Image) -> Sequence[OcrLine]:
        """Return text lines in reading order. Must not use the network."""
