"""Local NER providers behind ``core.interfaces.NerProvider``.

The default provider is spaCy ``en_core_web_sm`` (MIT), loaded from local
disk only: the model ships as a Python package inside the engine bundle.
NER is probabilistic (risk R4): findings carry a confidence below the
deterministic detectors, and company rules remain the guarantee for names
that matter.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from airlock_engine import safelog
from airlock_engine.core.interfaces import Detector, NerEntity, NerProvider
from airlock_engine.core.models import DetectionResult, SegmentKind, TextSegment
from airlock_engine.detectors.base import result

#: spaCy OntoNotes label → (Airlock entity type, confidence).
LABEL_MAP: dict[str, tuple[str, float]] = {
    "PERSON": ("PERSON", 0.75),
    "ORG": ("ORGANIZATION", 0.65),
    "GPE": ("LOCATION", 0.65),
    "LOC": ("LOCATION", 0.6),
    "FAC": ("LOCATION", 0.55),
    "MONEY": ("MONEY", 0.7),
    "PRODUCT": ("PRODUCT", 0.5),
    "EVENT": ("EVENT", 0.5),
}

#: Longest text handed to the model at once; longer segments are split.
_CHUNK_CHARS = 50_000
#: Total characters per document passed to NER; beyond this NER is skipped
#: for the rest of the document and the scan says so.
MAX_NER_CHARS = 3_000_000
_SKIP_KINDS = frozenset({SegmentKind.LINK})
#: Words the small model often tags as organisations: id names and form labels.
_NOT_ENTITIES = frozenset(
    w.casefold()
    for w in (
        "PAN", "Aadhaar", "Aadhar", "UID", "UIDAI", "GST", "GSTIN", "IFSC", "NEFT", "RTGS",
        "IMPS", "UPI", "KYC", "DOB", "IBAN", "SWIFT", "CVV", "OTP", "PIN", "TAN", "CIN",
        "Email", "E-mail", "Phone", "Mobile", "Tel", "Fax", "Account", "A/c", "Card", "Visa",
        "Mastercard", "RuPay", "Amex", "Password", "Token", "API", "URL", "IP", "ID", "Ref",
        "Invoice", "Order", "Status", "Note", "Notes", "Comments", "Customer", "Client",
    )
)


class NerUnavailable(RuntimeError):
    pass


class SpacyNerProvider(NerProvider):
    name = "spacy.en_core_web_sm"

    def __init__(self) -> None:
        self._nlp: Any = None
        # One model instance is shared by the engine's request threads.
        self._lock = threading.Lock()

    @staticmethod
    def default_model_dir() -> Path:
        try:
            import en_core_web_sm
        except ImportError as exc:
            raise NerUnavailable("model package missing") from exc
        base = Path(en_core_web_sm.__file__).parent
        candidates = sorted(p for p in base.glob("en_core_web_sm-*") if p.is_dir())
        if not candidates:
            raise NerUnavailable("model data missing")
        return candidates[-1]

    def load(self, model_dir: Path) -> None:
        try:
            import spacy
        except ImportError as exc:
            raise NerUnavailable("spaCy missing") from exc
        # Only the NER pipe and its own embedding layer are needed.
        self._nlp = spacy.load(
            model_dir, exclude=["parser", "lemmatizer", "attribute_ruler", "tagger", "senter"]
        )
        self._nlp.max_length = _CHUNK_CHARS + 1000

    def entities(self, text: str) -> Sequence[NerEntity]:
        return self.entities_many([text])[0]

    def entities_many(self, texts: Sequence[str]) -> list[list[NerEntity]]:
        if self._nlp is None:
            raise NerUnavailable("model not loaded")
        out: list[list[NerEntity]] = []
        with self._lock:
            for doc in self._nlp.pipe(texts, batch_size=64):
                out.append(
                    [NerEntity(ent.label_, ent.start_char, ent.end_char, 1.0) for ent in doc.ents]
                )
        return out


_provider_lock = threading.Lock()
_shared: NerProvider | None = None
_load_failed = False


def shared_provider() -> NerProvider | None:
    """Load the model once per engine process. Returns None if unavailable."""
    global _shared, _load_failed
    with _provider_lock:
        if _shared is None and not _load_failed:
            provider = SpacyNerProvider()
            try:
                provider.load(provider.default_model_dir())
            except Exception as exc:  # missing or broken model: scan without NER
                _load_failed = True
                safelog.log.warning("ner_unavailable", exception_type=type(exc).__name__)
                return None
            _shared = provider
            safelog.log.info("ner_loaded", detector="ner.spacy")
        return _shared


def _chunks(text: str) -> Iterator[tuple[int, str]]:
    if len(text) <= _CHUNK_CHARS:
        yield 0, text
        return
    start = 0
    while start < len(text):
        end = min(len(text), start + _CHUNK_CHARS)
        if end < len(text):
            cut = text.rfind("\n", start + _CHUNK_CHARS // 2, end)
            if cut == -1:
                cut = text.rfind(" ", start + _CHUNK_CHARS // 2, end)
            end = cut + 1 if cut != -1 else end
        yield start, text[start:end]
        start = end


def _clean_span(text: str, start: int, end: int, label: str) -> tuple[int, int] | None:
    value = text[start:end]
    # Trim possessives and stray punctuation spaCy sometimes includes.
    changed = True
    while changed and value:
        changed = False
        for suffix in ("'s", "’s"):
            if value.endswith(suffix):
                end -= len(suffix)
                value = value[: -len(suffix)]
                changed = True
        if value and value[-1] in ".,;:-–)]\"'’":
            end -= 1
            value = value[:-1]
            changed = True
        if value and value[0] in "(['\"‘-":
            start += 1
            value = value[1:]
            changed = True
    if len(value.strip()) < 2 or value.strip().casefold() in _NOT_ENTITIES:
        return None
    if label in ("PERSON", "ORG", "GPE", "LOC", "FAC", "PRODUCT", "EVENT"):
        if not any(ch.isalpha() for ch in value):
            return None
        if label == "PERSON" and (any(ch.isdigit() for ch in value) or not value[0].isupper()):
            return None
        if "\n" in value:
            return None
    return start, end


class NerDetector(Detector):
    name = "ner.spacy"

    def __init__(self, provider: NerProvider) -> None:
        self._provider = provider
        self.truncated = False

    def detect(self, segment: TextSegment) -> Iterator[DetectionResult]:
        yield from self.detect_many([segment])

    def detect_many(self, segments: Sequence[TextSegment]) -> Iterator[DetectionResult]:
        """Batch segments through the model (much faster than one by one)."""
        jobs: list[tuple[TextSegment, int, str]] = []
        for segment in segments:
            if segment.kind in _SKIP_KINDS or not any(ch.isalpha() for ch in segment.text):
                continue
            for offset, chunk in _chunks(segment.text):
                jobs.append((segment, offset, chunk))
        if not jobs:
            return
        provider = self._provider
        texts = [chunk for _, _, chunk in jobs]
        if isinstance(provider, SpacyNerProvider):
            batches = provider.entities_many(texts)
        else:
            batches = [list(provider.entities(t)) for t in texts]
        for (segment, offset, _), entities in zip(jobs, batches, strict=True):
            for ent in entities:
                mapped = LABEL_MAP.get(ent.label)
                if mapped is None:
                    continue
                span = _clean_span(segment.text, offset + ent.start, offset + ent.end, ent.label)
                if span is None:
                    continue
                entity_type, confidence = mapped
                yield result(segment, entity_type, span[0], span[1], detector=self.name,
                             confidence=round(confidence * ent.score, 3))
