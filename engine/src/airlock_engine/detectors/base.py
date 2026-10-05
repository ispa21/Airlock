"""Shared building blocks for pattern detectors."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass

from airlock_engine.core.interfaces import Detector
from airlock_engine.core.models import DetectionResult, TextSegment
from airlock_engine.core.sensitive import SensitiveValue
from airlock_engine.detectors.entities import entity

#: How far before a match to look for context keywords ("PAN:", "A/c no").
CONTEXT_WINDOW = 48


def keywords(*words: str) -> re.Pattern[str]:
    """Case-insensitive whole-word alternation of context keywords."""
    body = "|".join(sorted((re.escape(w) for w in words), key=len, reverse=True))
    return re.compile(rf"(?<![A-Za-z0-9])(?:{body})(?![A-Za-z])", re.IGNORECASE)


def has_context(
    segment: TextSegment,
    start: int,
    end: int,
    pattern: re.Pattern[str],
    *,
    before: int = CONTEXT_WINDOW,
    after: int = 0,
) -> bool:
    """True if a keyword appears just before the match, after it, or in the
    segment's context (a spreadsheet column header)."""
    text = segment.text
    window = text[max(0, start - before) : start]
    if after:
        window += " " + text[end : end + after]
    return bool(pattern.search(window) or (segment.context and pattern.search(segment.context)))


def glued(text: str, start: int, end: int) -> bool:
    """True if the match is part of a longer alphanumeric token or identifier
    such as ``INV-98765432101`` or ``id_4111111111111111``."""
    if start > 0:
        prev = text[start - 1]
        if prev.isalnum():
            return True
        if prev in "-_/#" and start > 1 and text[start - 2].isalnum():
            return True
    if end < len(text):
        nxt = text[end]
        if nxt.isalnum():
            return True
        if nxt in "-_/" and end + 1 < len(text) and text[end + 1].isalnum():
            return True
    return False


def result(
    segment: TextSegment,
    entity_type: str,
    start: int,
    end: int,
    *,
    detector: str,
    confidence: float,
    rule_id: str = "",
) -> DetectionResult:
    return DetectionResult(
        entity_type=entity_type,
        matched_value=SensitiveValue(segment.text[start:end]),
        segment_id=segment.segment_id,
        start=start,
        end=end,
        confidence=confidence,
        detector=detector,
        rule_id=rule_id or detector,
        severity=entity(entity_type).severity,
    )


@dataclass(frozen=True, slots=True)
class Candidate:
    start: int
    end: int
    confidence: float
    entity_type: str = ""


Validator = Callable[[TextSegment, re.Match[str]], Candidate | None]


class PatternDetector(Detector):
    """A regex finds candidates; ``validate`` accepts, rejects or re-scores them."""

    def __init__(
        self,
        name: str,
        entity_type: str,
        pattern: re.Pattern[str],
        validate: Validator,
        *,
        prefilter: Callable[[str], bool] | None = None,
    ) -> None:
        self.name = name
        self.entity_type = entity_type
        self._pattern = pattern
        self._validate = validate
        self._prefilter = prefilter

    def detect(self, segment: TextSegment) -> Iterator[DetectionResult]:
        text = segment.text
        if self._prefilter is not None and not self._prefilter(text):
            return
        for match in self._pattern.finditer(text):
            candidate = self._validate(segment, match)
            if candidate is None:
                continue
            yield result(
                segment,
                candidate.entity_type or self.entity_type,
                candidate.start,
                candidate.end,
                detector=self.name,
                confidence=candidate.confidence,
            )


def has_digit(text: str) -> bool:
    return any(ch.isdigit() for ch in text)


def digits_only(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def run_all(detectors: Iterable[Detector], segment: TextSegment) -> list[DetectionResult]:
    out: list[DetectionResult] = []
    for detector in detectors:
        out.extend(detector.detect(segment))
    return out
