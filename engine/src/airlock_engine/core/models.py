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


class SegmentKind(StrEnum):
    """Where in a file a piece of text lives.

    The privacy report uses this to show *hidden* exposure, e.g. a customer
    name that only survives in a comment, a tracked deletion or a pivot cache.
    """

    BODY = "body"
    HEADER_FOOTER = "header_footer"
    NOTE = "note"  # footnotes, endnotes, speaker notes
    COMMENT = "comment"
    TRACKED_CHANGE = "tracked_change"  # deleted text still stored in the file
    HIDDEN = "hidden"  # hidden sheets/rows/columns/slides, caches, orphaned text
    METADATA = "metadata"  # document properties, authors, EXIF, XMP
    LINK = "link"  # hyperlink targets, external references, connection strings
    FIELD = "field"  # field codes, formulas with literals
    ALT_TEXT = "alt_text"
    NAME = "name"  # sheet names, defined names, bookmarks, form field names
    TEMPLATE = "template"  # slide masters/layouts, glossary
    CHART = "chart"  # cached chart data
    OCR = "ocr"  # text recognised in images or scanned pages


@dataclass(frozen=True, slots=True)
class Locator:
    """Where in the source document a text segment came from.

    ``part`` names the container (a ZIP part such as ``xl/worksheets/sheet1.xml``,
    ``page``, ``text``...); ``path`` addresses the text inside it (``C14``,
    ``p/12``, ``3``...). Parts of embedded files are prefixed with the
    embedding part and ``!/``. Locators never contain document content.
    """

    part: str
    path: str


@dataclass(frozen=True, slots=True)
class TextBox:
    """Position of ``text[start:end]`` in the rendered page or image, in pixels."""

    start: int
    end: int
    x0: float
    y0: float
    x1: float
    y1: float


@dataclass(frozen=True, slots=True)
class TextSegment:
    """A contiguous run of extracted text with a stable locator.

    Detectors run per segment; offsets in :class:`DetectionResult` are relative
    to ``text``. Adapters use the locator to write replacements back.

    ``label`` is a structural, content-free description for the report
    ("Sheet 2 · C14", "Slide 3 notes"). ``context`` is optional nearby text
    that helps detectors (a spreadsheet column header); it is document
    content and is never logged or shown.
    """

    segment_id: int
    text: str
    locator: Locator
    kind: SegmentKind = SegmentKind.BODY
    label: str = ""
    context: str = ""
    boxes: tuple[TextBox, ...] = ()

    def __repr__(self) -> str:  # never print document content
        return (
            f"TextSegment(id={self.segment_id}, kind={self.kind.value}, "
            f"len={len(self.text)}, locator={self.locator})"
        )


@dataclass(frozen=True, slots=True)
class UnextractedPart:
    """Content Airlock found but could not read (macros, OLE objects, ...).

    Reported to the user; the sanitizer removes such parts from safe copies.
    """

    kind: str
    label: str


@dataclass(frozen=True, slots=True)
class ExtractedDocument:
    format: str
    segments: tuple[TextSegment, ...]
    unextracted: tuple[UnextractedPart, ...] = ()
    ocr_used: bool = False
    #: Structural counts for the report: pages, sheets, slides, images_ocr, embedded.
    counts: dict[str, int] = field(default_factory=dict)
    #: Adapter state needed to write a sanitized copy (text encoding, CSV dialect).
    adapter_state: dict[str, str] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"ExtractedDocument(format={self.format}, segments={len(self.segments)}, "
            f"unextracted={len(self.unextracted)})"
        )


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
