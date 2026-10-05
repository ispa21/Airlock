"""Core data model shared by every engine stage.

The pipeline is::

    ExtractedDocument --(Detector)--> DetectionResult
                      --(PolicyEngine)--> Finding (detection + decision)
                      --(Masker)--> Replacement
                      --(DocumentAdapter.sanitize)--> safe artifact
                      --(Verifier)--> VerificationReport

Detection answers "what is this?"; policy answers "what do we do with it?".
They are deliberately separate types.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, StrEnum

from airlock_engine.core.sensitive import SensitiveValue


class Severity(IntEnum):
    """Ordered so that ``max()`` over findings yields the document risk floor."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class Action(StrEnum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    REDACT = "REDACT"
    GENERALIZE = "GENERALIZE"
    BLOCK = "BLOCK"


class Category(StrEnum):
    """Report groupings (PRD §14). Entity types map onto exactly one category."""

    PERSONAL = "PERSONAL"
    GOVERNMENT = "GOVERNMENT"
    FINANCIAL = "FINANCIAL"
    BUSINESS = "BUSINESS"
    CREDENTIALS = "CREDENTIALS"
    INTELLECTUAL_PROPERTY = "INTELLECTUAL_PROPERTY"
    OTHER = "OTHER"


@dataclass(frozen=True, slots=True)
class Locator:
    """Where in the source document a text segment came from.

    Adapters define the meaning of ``part`` and ``path``; the rest of the engine
    treats them as opaque. Examples: ``("page", "3/block/12")`` for PDF,
    ``("sheet", "Payroll!C14")`` for XLSX, ``("notes", "slide/4")`` for PPTX.
    """

    part: str
    path: str


@dataclass(frozen=True, slots=True)
class TextSegment:
    """A contiguous run of extracted text with a stable locator.

    Detectors run per segment; offsets in :class:`DetectionResult` are relative
    to ``text``. Adapters use the locator to write replacements back.
    """

    segment_id: int
    text: str
    locator: Locator

    def __repr__(self) -> str:  # never print document content
        return f"TextSegment(id={self.segment_id}, len={len(self.text)}, locator={self.locator})"


@dataclass(frozen=True, slots=True)
class ExtractedDocument:
    format: str
    segments: tuple[TextSegment, ...]
    # Parts the adapter could not extract (e.g. embedded OLE objects). Their
    # presence forces a warning in the report and is considered by verification.
    unextracted_parts: tuple[str, ...] = ()
    ocr_used: bool = False


@dataclass(frozen=True, slots=True)
class DetectionResult:
    entity_type: str
    matched_value: SensitiveValue
    segment_id: int
    start: int
    end: int
    confidence: float
    detector: str
    rule_id: str
    severity: Severity

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0, 1]")
        if self.start < 0 or self.end <= self.start:
            raise ValueError("invalid span")


@dataclass(frozen=True, slots=True)
class Finding:
    """A detection plus the policy decision applied to it."""

    finding_id: str
    detection: DetectionResult
    category: Category
    action: Action
    policy_reason: str
    # Other detections that overlapped this span and were merged into it.
    corroborating_detectors: tuple[str, ...] = field(default=())
