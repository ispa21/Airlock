"""Company rules: every match kind, aliases, safety limits and the 1.00 gate."""

from __future__ import annotations

import time

import pytest

from airlock_engine.core.models import ExtractedDocument, Locator, Severity, TextSegment
from airlock_engine.detectors.custom import (
    CompanyRule,
    CompanyRuleDetector,
    RuleError,
    normalize_with_map,
    validate_rule_terms,
)
from airlock_engine.detectors.pipeline import DetectionEngine


def rule(
    kind: str, pattern: str, *aliases: str, rid: str = "r1", category: str = "INTERNAL_PROJECT"
) -> CompanyRule:
    validate_rule_terms(kind, pattern, aliases)
    return CompanyRule(rid, kind, pattern, category, Severity.HIGH, tuple(aliases))


def matches(rules: list[CompanyRule], text: str) -> list[str]:
    seg = TextSegment(0, text, Locator("t", "0"))
    return [text[d.start : d.end] for d in CompanyRuleDetector(rules).detect(seg)]


def test_exact_is_case_sensitive_and_whole_word() -> None:
    r = [rule("exact", "Phoenix")]
    assert matches(r, "Project Phoenix ships.") == ["Phoenix"]
    assert matches(r, "phoenix and PHOENIX") == []
    assert matches(r, "Phoenixville") == []


def test_case_insensitive() -> None:
    r = [rule("case_insensitive", "Project Phoenix")]
    assert matches(r, "PROJECT PHOENIX and project phoenix") == [
        "PROJECT PHOENIX",
        "project phoenix",
    ]
    assert matches(r, "Project Phoenixes") == []


@pytest.mark.parametrize(
    "variant",
    [
        "Project Phoenix",
        "PROJECT-PHOENIX",
        "project_phoenix",
        "ProjectPhoenix",
        "Project  Phoenix",
        "project.phoenix",
        "Prōject Phœnix".replace("œ", "oe"),
        "ＰＲＯＪＥＣＴ　ＰＨＯＥＮＩＸ",
    ],
)
def test_normalized_variants(variant: str) -> None:
    r = [rule("normalized", "Project Phoenix")]
    text = f"Status of {variant} is green."
    assert matches(r, text) == [variant]


def test_normalized_respects_word_edges() -> None:
    r = [rule("normalized", "Ram")]
    assert matches(r, "Ram, R.A.M. and Ramesh") == ["Ram", "R.A.M"]


def test_aliases_match_with_the_rule_kind() -> None:
    r = [rule("case_insensitive", "Acme Holdings", "ACME", "Acme Corp", rid="client")]
    assert matches(r, "acme corp signed; ACME paid; Acme Holdings Ltd") == [
        "acme corp",
        "ACME",
        "Acme Holdings",
    ]


def test_overlapping_terms_from_different_rules() -> None:
    r = [rule("exact", "Phoenix", rid="a"), rule("exact", "Project Phoenix", rid="b")]
    got = matches(r, "Project Phoenix")
    assert "Project Phoenix" in got and "Phoenix" in got


def test_regex_rules() -> None:
    r = [rule("regex", r"EMP-\d{5}", category="EMPLOYEE_ID")]
    assert matches(r, "Owners: EMP-00421, EMP-99812; ref EMP-12") == ["EMP-00421", "EMP-99812"]


def test_regex_rule_validation() -> None:
    with pytest.raises(RuleError):
        validate_rule_terms("regex", "(unclosed", ())
    with pytest.raises(RuleError):
        validate_rule_terms("regex", "a*", ())  # matches empty text
    with pytest.raises(RuleError):
        validate_rule_terms("exact", "   ", ())
    with pytest.raises(RuleError):
        validate_rule_terms("normalized", "-", ())
    with pytest.raises(RuleError):
        validate_rule_terms("fuzzy", "x", ())
    with pytest.raises(RuleError):
        validate_rule_terms("exact", "x" * 501, ())


def test_rule_errors_never_echo_the_pattern() -> None:
    secret = "Project Zebra Unicorn"
    for kind, pattern in (("regex", secret + "("), ("exact", secret * 30)):
        with pytest.raises(RuleError) as info:
            validate_rule_terms(kind, pattern, ())
        assert "Zebra" not in str(info.value)


def test_catastrophic_regex_times_out_without_hanging() -> None:
    r = [CompanyRule("evil", "regex", r"(a|aa)+$", "INTERNAL_PROJECT", Severity.HIGH)]
    detector = CompanyRuleDetector(r)
    seg = TextSegment(0, "a" * 60 + "!", Locator("t", "0"))
    started = time.perf_counter()
    assert list(detector.detect(seg)) == []
    assert time.perf_counter() - started < 3
    assert detector.timeouts == 1


def test_disabled_rules_do_not_match() -> None:
    r = CompanyRule("r", "exact", "Phoenix", "INTERNAL_PROJECT", Severity.HIGH, enabled=False)
    assert matches([r], "Phoenix") == []


def test_rule_repr_hides_pattern() -> None:
    assert "Phoenix" not in repr(rule("exact", "Phoenix"))


def test_normalize_map_points_into_original() -> None:
    text = "Ｐro-ject"
    norm, index = normalize_with_map(text)
    assert norm == "project"
    assert text[index[0]] == "Ｐ"


def test_company_rules_gate_is_perfect() -> None:
    """Company rules (exact / normalized) must have recall and precision 1.00."""
    terms = ["Project Phoenix", "Blue Falcon", "Acme Holdings", "Orion-7", "Kestrel"]
    rules = [rule("normalized", t, rid=f"r{i}") for i, t in enumerate(terms)]
    rules.append(rule("exact", "HELIX", rid="exact"))
    variants = {
        "Project Phoenix": ["Project Phoenix", "PROJECT-PHOENIX", "project_phoenix"],
        "Blue Falcon": ["Blue Falcon", "blue  falcon", "BlueFalcon"],
        "Acme Holdings": ["Acme Holdings", "ACME HOLDINGS"],
        "Orion-7": ["Orion-7", "orion 7", "ORION7"],
        "Kestrel": ["Kestrel", "KESTREL"],
        "HELIX": ["HELIX"],
    }
    negatives = [
        "Phoenix project",
        "Blue Falcons",
        "Acme",
        "Orion-77",
        "Kestrels",
        "Helix",
        "phoenixproject",
        "falcon blue",
    ]
    segments, expected = [], set()
    i = 0
    for term_variants in variants.values():
        for v in term_variants:
            text = f"Update on {v} for the board."
            segments.append(TextSegment(i, text, Locator("t", str(i))))
            expected.add((i, 10, 10 + len(v)))
            i += 1
    for neg in negatives:
        segments.append(TextSegment(i, f"Update on {neg} for the board.", Locator("t", str(i))))
        i += 1
    doc = ExtractedDocument("txt", tuple(segments))
    outcome = DetectionEngine(rules=rules, detectors=[]).run(doc)
    got = {(d.detection.segment_id, d.detection.start, d.detection.end) for d in outcome.detected}
    assert got == expected


def test_company_rule_beats_ner_and_coexists_with_regex() -> None:
    from airlock_engine.core.interfaces import NerEntity, NerProvider

    class FakeNer(NerProvider):
        name = "fake"

        def load(self, model_dir):  # type: ignore[no-untyped-def]
            pass

        def entities(self, text: str):  # type: ignore[no-untyped-def]
            i = text.find("Blue Falcon")
            return [NerEntity("ORG", i, i + len("Blue Falcon"), 1.0)] if i >= 0 else []

    text = "Blue Falcon contact: a.b@example.invalid"
    doc = ExtractedDocument("txt", (TextSegment(0, text, Locator("t", "0")),))
    outcome = DetectionEngine(
        rules=[rule("normalized", "Blue Falcon", category="CLIENT_NAME")], ner=FakeNer()
    ).run(doc)
    got = {(i.detection.entity_type, i.detection.detector) for i in outcome.detected}
    assert got == {("CLIENT_NAME", "custom.normalized"), ("EMAIL", "regex.email")}


def test_slow_rule_is_dropped_after_repeated_timeouts() -> None:
    r = [CompanyRule("evil", "regex", r"(a|aa)+$", "INTERNAL_PROJECT", Severity.HIGH)]
    detector = CompanyRuleDetector(r)
    started = time.perf_counter()
    for i in range(20):
        list(detector.detect(TextSegment(i, "a" * 60 + "!", Locator("t", str(i)))))
    assert detector.timeouts == 3
    assert time.perf_counter() - started < 5
