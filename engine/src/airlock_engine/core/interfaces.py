"""Extension points. Each later phase provides implementations of these.

Keeping them abstract here is what lets the NER model, the OCR engine or a
document library be swapped without touching the rest of the pipeline.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

from airlock_engine.core.models import DetectionResult, ExtractedDocument, Locator, TextSegment


@dataclass(frozen=True, slots=True)
class Replacement:
    """A single edit to apply to a segment when producing the safe copy."""

    segment_id: int
    start: int
    end: int
    replacement_text: str


class DocumentAdapter(ABC):
    """One implementation per document family (PDF, DOCX, XLSX, ...)."""

    #: Canonical format ids this adapter handles, e.g. ``("docx",)``.
    formats: tuple[str, ...] = ()

    @abstractmethod
    def extract(self, source: Path) -> ExtractedDocument:
        """Read ``source`` without modifying it and return every text-bearing part.

        Must include hidden content that could leak: comments, speaker notes,
        hidden sheets, headers/footers, tracked changes and document metadata.
        """

    @abstractmethod
    def sanitize(
        self,
        source: Path,
        document: ExtractedDocument,
        replacements: Sequence[Replacement],
        destination: Path,
    ) -> None:
        """Write a sanitized copy to ``destination``. ``source`` is read-only."""


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


class OcrProvider(ABC):
    """A local OCR engine used by the image adapter and for scanned PDFs."""

    name: str

    @abstractmethod
    def recognize(self, image_png: bytes, locator: Locator) -> Sequence[TextSegment]: ...
