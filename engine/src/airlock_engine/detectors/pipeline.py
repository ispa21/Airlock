"""Runs every detector over an extracted document and merges the results.

Overlap handling here is limited to *detection quality*: duplicate matches of
the same entity are merged, and a weaker guess that overlaps a stronger,
validated match is dropped (a checksum beats a context guess; any
deterministic match beats NER). Deciding what to *do* with overlapping
findings of different types is the policy engine's job (Phase 4).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from airlock_engine.core.interfaces import Detector, NerProvider
from airlock_engine.core.models import DetectionResult, ExtractedDocument, TextSegment
from airlock_engine.detectors.custom import CompanyRule, CompanyRuleDetector
from airlock_engine.detectors.entities import BUILTIN_ENTITIES, QualityClass
from airlock_engine.detectors.ner import MAX_NER_CHARS, NerDetector
from airlock_engine.detectors.regex import builtin_regex_detectors
from airlock_engine.detectors.secrets import builtin_secret_detectors

ProgressFn = Callable[[str, int, int], None]
CancelFn = Callable[[], bool]
#: (entity_type, raw value) -> True if the user marked it "not sensitive".
AllowFn = Callable[[str, str], bool]

_STRENGTH = {
    QualityClass.SECRET: 4,
    QualityClass.CHECKSUMMED_ID: 4,
    QualityClass.COMPANY_RULE: 4,
    QualityClass.CONTEXTUAL_ID: 2,
    QualityClass.CONTACT: 2,
    QualityClass.NER: 1,
}
#: Digit-only entities whose patterns can claim the same number.
_NUMERIC = frozenset({"PHONE", "BANK_ACCOUNT", "DATE_OF_BIRTH", "IP_ADDRESS"})
_BATCH = 256


class DetectionCancelled(Exception):
    pass


@dataclass(frozen=True, slots=True)
class Detected:
    detection: DetectionResult
    corroborating: tuple[str, ...] = ()


@dataclass
class DetectionOutcome:
    detected: list[Detected] = field(default_factory=list)
    ner_used: bool = False
    ner_truncated: bool = False
    rule_timeouts: int = 0
    allowed: int = 0


def _quality(entity_type: str) -> QualityClass:
    known = BUILTIN_ENTITIES.get(entity_type)
    return known.quality if known is not None else QualityClass.COMPANY_RULE


def _overlaps(a: DetectionResult, b: DetectionResult) -> bool:
    return a.start < b.end and b.start < a.end


def _beats(a: DetectionResult, b: DetectionResult) -> bool:
    """True if ``a`` should suppress the overlapping, differently-typed ``b``."""
    qa, qb = _quality(a.entity_type), _quality(b.entity_type)
    sa, sb = _STRENGTH[qa], _STRENGTH[qb]
    if qb is QualityClass.NER and qa is not QualityClass.NER:
        return True
    b_contains_a = b.start <= a.start and a.end <= b.end and (b.end - b.start) > (a.end - a.start)
    if sa > sb and not b_contains_a:
        return True  # e.g. a card number also claimed as a bank account
    a_contains_b = a.start <= b.start and b.end <= a.end and (a.end - a.start) > (b.end - b.start)
    if sa == sb == 4 and a_contains_b and qa is qb:
        return True  # an Aadhaar-shaped run inside a longer card or IBAN
    if sa == sb and a.entity_type in _NUMERIC and b.entity_type in _NUMERIC:
        return (a.confidence, a.end - a.start) > (b.confidence, b.end - b.start)
    return False


def resolve(detections: Sequence[DetectionResult]) -> list[Detected]:
    """Merge duplicates and drop dominated guesses within one segment."""
    ordered = sorted(detections, key=lambda d: (d.start, -(d.end - d.start), -d.confidence))
    # 1. Same entity type, overlapping: keep the longest, note the others.
    merged: list[tuple[DetectionResult, list[str]]] = []
    for d in ordered:
        for i, (kept, extra) in enumerate(merged):
            if kept.entity_type == d.entity_type and _overlaps(kept, d):
                if (d.end - d.start, d.confidence) > (kept.end - kept.start, kept.confidence):
                    merged[i] = (d, [*extra, kept.detector])
                elif d.detector != kept.detector and d.detector not in extra:
                    extra.append(d.detector)
                break
        else:
            merged.append((d, []))
    # 2. Different types: drop dominated detections.
    survivors: list[Detected] = []
    for d, extra in merged:
        if any(
            other is not d
            and other.entity_type != d.entity_type
            and _overlaps(other, d)
            and _beats(other, d)
            for other, _ in merged
        ):
            continue
        corroborating = tuple(dict.fromkeys(x for x in extra if x != d.detector))
        survivors.append(Detected(d, corroborating))
    return survivors


class DetectionEngine:
    def __init__(
        self,
        *,
        rules: Sequence[CompanyRule] = (),
        ner: NerProvider | None = None,
        allow: AllowFn | None = None,
        detectors: Sequence[Detector] | None = None,
    ) -> None:
        self._deterministic: list[Detector] = (
            list(detectors)
            if detectors is not None
            else [*builtin_regex_detectors(), *builtin_secret_detectors()]
        )
        self._rules = CompanyRuleDetector(rules)
        self._ner = NerDetector(ner) if ner is not None else None
        self._allow = allow

    def run(
        self,
        document: ExtractedDocument,
        *,
        progress: ProgressFn | None = None,
        cancelled: CancelFn | None = None,
    ) -> DetectionOutcome:
        outcome = DetectionOutcome(ner_used=self._ner is not None)
        segments = document.segments
        total = len(segments)
        per_segment: dict[int, list[DetectionResult]] = {s.segment_id: [] for s in segments}
        ner_budget = MAX_NER_CHARS
        for batch_start in range(0, total, _BATCH):
            if cancelled is not None and cancelled():
                raise DetectionCancelled
            batch = segments[batch_start : batch_start + _BATCH]
            for segment in batch:
                found = per_segment[segment.segment_id]
                for detector in self._deterministic:
                    found.extend(detector.detect(segment))
                if self._rules:
                    found.extend(self._rules.detect(segment))
            if self._ner is not None:
                ner_batch: list[TextSegment] = []
                for segment in batch:
                    if len(segment.text) > ner_budget:
                        outcome.ner_truncated = True
                        break
                    ner_budget -= len(segment.text)
                    ner_batch.append(segment)
                for d in self._ner.detect_many(ner_batch):
                    per_segment[d.segment_id].append(d)
            if progress is not None:
                progress("detect", min(batch_start + _BATCH, total), total)

        for segment in segments:
            found = per_segment[segment.segment_id]
            if not found:
                continue
            if self._allow is not None:
                allow = self._allow
                kept = [d for d in found if not allow(d.entity_type, d.matched_value.reveal())]
                outcome.allowed += len(found) - len(kept)
                found = kept
            outcome.detected.extend(resolve(found))
        outcome.rule_timeouts = self._rules.timeouts
        return outcome
