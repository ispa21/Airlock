"""Company rules: dictionaries, aliases, normalized and regex matches.

Rules are company-confidential themselves ("Project Phoenix"), so they are
never logged, and the detector reports only the rule id.

Match kinds:

* ``exact``: case-sensitive, whole-word.
* ``case_insensitive``: whole-word, any letter case.
* ``normalized``: ignores case, accents, full-width forms and separators, so
  ``Project Phoenix`` also matches ``PROJECT-PHOENIX``, ``project_phoenix``,
  ``ProjectPhoenix`` and ``Prøject Phoenix``'s accented variants.
* ``regex``: a user pattern, run with a per-segment timeout (ReDoS-safe).

Aliases are extra terms for the same rule, matched with the rule's kind
(``normalized`` for regex rules).
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import regex

from airlock_engine.core.interfaces import Detector
from airlock_engine.core.models import DetectionResult, Severity, TextSegment
from airlock_engine.core.sensitive import SensitiveValue

RULE_KINDS = ("exact", "case_insensitive", "normalized", "regex")
MAX_PATTERN_CHARS = 500
MAX_ALIASES = 50
REGEX_TIMEOUT_S = 0.25
#: After this many timeouts a regex rule is skipped for the rest of the document.
MAX_RULE_TIMEOUTS = 3


@dataclass(frozen=True, slots=True)
class CompanyRule:
    id: str
    kind: str
    pattern: str
    category_id: str
    severity: Severity
    aliases: tuple[str, ...] = ()
    enabled: bool = True

    def __repr__(self) -> str:  # patterns are confidential
        return f"CompanyRule(id={self.id}, kind={self.kind}, aliases={len(self.aliases)})"


class RuleError(ValueError):
    """A rule pattern is invalid. The message never contains the pattern."""


# --- Normalization with an offset map ---------------------------------------

_SEPARATORS = frozenset(" \t\r\n   -_./\\·•,:;'’\"`|+&")


def normalize_with_map(text: str) -> tuple[str, list[int]]:
    """Fold case, accents, compatibility forms and drop separators.

    Returns the normalized string and, for each of its characters, the index
    of the original character it came from.
    """
    out: list[str] = []
    index: list[int] = []
    for i, ch in enumerate(text):
        if ch in _SEPARATORS:
            continue
        if ch.isascii():
            if ch.isalnum():
                out.append(ch.lower())
                index.append(i)
            elif not ch.isspace():
                out.append(ch)
                index.append(i)
            continue
        decomposed = unicodedata.normalize("NFKD", ch)
        for d in decomposed:
            if unicodedata.combining(d) or d in _SEPARATORS or d.isspace():
                continue
            for folded in d.casefold():
                out.append(folded)
                index.append(i)
    return "".join(out), index


def normalize(text: str) -> str:
    return normalize_with_map(text)[0]


def _word_char(ch: str) -> bool:
    return ch.isalnum()


def _bounded(text: str, start: int, end: int) -> bool:
    """Whole-word check on the original text."""
    if start > 0 and _word_char(text[start]) and _word_char(text[start - 1]):
        return False
    return not (end < len(text) and _word_char(text[end - 1]) and _word_char(text[end]))


# --- Validation --------------------------------------------------------------


def validate_rule_terms(kind: str, pattern: str, aliases: Sequence[str]) -> None:
    if kind not in RULE_KINDS:
        raise RuleError("Choose one of: exact, case-insensitive, normalized or pattern.")
    if not pattern.strip():
        raise RuleError("The rule text is empty.")
    if len(pattern) > MAX_PATTERN_CHARS or any(len(a) > MAX_PATTERN_CHARS for a in aliases):
        raise RuleError(f"Rule text is limited to {MAX_PATTERN_CHARS} characters.")
    if len(aliases) > MAX_ALIASES:
        raise RuleError(f"A rule can have at most {MAX_ALIASES} aliases.")
    if any(not a.strip() for a in aliases):
        raise RuleError("An alias is empty.")
    if kind == "normalized" and len(normalize(pattern)) < 2:
        raise RuleError("The rule needs at least two letters or digits.")
    if kind == "regex":
        try:
            compiled = regex.compile(pattern, regex.V1)
        except (regex.error, OverflowError, RecursionError) as exc:
            raise RuleError("The pattern is not a valid regular expression.") from exc
        try:
            if compiled.fullmatch("", timeout=REGEX_TIMEOUT_S) is not None:
                raise RuleError("The pattern matches empty text, so it would match everywhere.")
        except TimeoutError as exc:
            raise RuleError("The pattern is too complex to run safely.") from exc


# --- Detector ----------------------------------------------------------------


@dataclass
class _LiteralIndex:
    """One alternation per kind; term → rule lookup."""

    terms: dict[str, CompanyRule] = field(default_factory=dict)
    pattern: re.Pattern[str] | None = None

    def add(self, key: str, rule: CompanyRule) -> None:
        current = self.terms.get(key)
        if current is None or rule.severity > current.severity:
            self.terms[key] = rule

    def compile(self, flags: int = 0) -> None:
        if self.terms:
            body = "|".join(re.escape(t) for t in sorted(self.terms, key=len, reverse=True))
            self.pattern = re.compile(body, flags)


class CompanyRuleDetector(Detector):
    name = "custom"

    def __init__(self, rules: Sequence[CompanyRule]) -> None:
        self.rules = [r for r in rules if r.enabled]
        self.timeouts = 0
        self._rule_timeouts: dict[str, int] = {}
        self._exact = _LiteralIndex()
        self._ci = _LiteralIndex()
        self._norm = _LiteralIndex()
        self._regex: list[tuple[CompanyRule, regex.Pattern[str]]] = []
        for rule in self.rules:
            if rule.kind == "exact":
                for term in (rule.pattern, *rule.aliases):
                    self._exact.add(term, rule)
            elif rule.kind == "case_insensitive":
                for term in (rule.pattern, *rule.aliases):
                    self._ci.add(term.casefold(), rule)
            elif rule.kind == "normalized":
                for term in (rule.pattern, *rule.aliases):
                    if key := normalize(term):
                        self._norm.add(key, rule)
            elif rule.kind == "regex":
                self._regex.append((rule, regex.compile(rule.pattern, regex.V1)))
                for alias in rule.aliases:
                    if key := normalize(alias):
                        self._norm.add(key, rule)
        self._exact.compile()
        self._ci.compile(re.IGNORECASE)
        self._norm.compile()

    def __bool__(self) -> bool:
        return bool(self.rules)

    def _emit(
        self, segment: TextSegment, rule: CompanyRule, start: int, end: int
    ) -> DetectionResult:
        return DetectionResult(
            entity_type=rule.category_id,
            matched_value=SensitiveValue(segment.text[start:end]),
            segment_id=segment.segment_id,
            start=start,
            end=end,
            confidence=1.0,
            detector=f"custom.{rule.kind}",
            rule_id=rule.id,
            severity=rule.severity,
        )

    def detect(self, segment: TextSegment) -> Iterator[DetectionResult]:
        text = segment.text
        found: set[tuple[str, int, int]] = set()

        def emit(rule: CompanyRule, start: int, end: int) -> Iterator[DetectionResult]:
            key = (rule.id, start, end)
            if end > start and key not in found:
                found.add(key)
                yield self._emit(segment, rule, start, end)

        if self._exact.pattern is not None:
            for m in _overlapping(self._exact.pattern, text):
                if _bounded(text, m.start(), m.end()):
                    yield from emit(self._exact.terms[m.group()], m.start(), m.end())
        if self._ci.pattern is not None:
            for m in _overlapping(self._ci.pattern, text):
                rule = self._ci.terms.get(m.group().casefold())
                if rule is not None and _bounded(text, m.start(), m.end()):
                    yield from emit(rule, m.start(), m.end())
        if self._norm.pattern is not None:
            norm, index = normalize_with_map(text)
            for m in _overlapping(self._norm.pattern, norm):
                start, end = index[m.start()], index[m.end() - 1] + 1
                if _bounded(text, start, end):
                    yield from emit(self._norm.terms[m.group()], start, end)
        for rule, compiled in self._regex:
            if self._rule_timeouts.get(rule.id, 0) >= MAX_RULE_TIMEOUTS:
                continue  # too slow on this document: stop paying for it
            try:
                for rm in compiled.finditer(text, timeout=REGEX_TIMEOUT_S):
                    yield from emit(rule, rm.start(), rm.end())
            except TimeoutError:
                self.timeouts += 1
                self._rule_timeouts[rule.id] = self._rule_timeouts.get(rule.id, 0) + 1


def _overlapping(pattern: re.Pattern[str], text: str) -> Iterator[re.Match[str]]:
    """Leftmost-longest matches, then retry one character later so a shorter
    term inside a rejected longer match (failed word boundary) is still found."""
    pos = 0
    while pos < len(text):
        m = pattern.search(text, pos)
        if m is None:
            return
        yield m
        pos = m.start() + 1 if m.end() > m.start() else m.end() + 1
