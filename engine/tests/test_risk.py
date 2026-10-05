"""Risk score, detector explanations and partial masking (Phase 6)."""

from __future__ import annotations

import pytest

from airlock_engine.core.models import Action, Category, DetectionResult, Finding, Severity
from airlock_engine.core.sensitive import SensitiveValue
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.detectors.explain import _REASONS, detector_name, explain
from airlock_engine.masking.replacements import Replacer, partial, partial_allowed
from airlock_engine.policy.profiles import COMPANY_DEFAULT, MASK_STYLES
from airlock_engine.risk.scorer import (
    FACTORS,
    VOLUME_THRESHOLD,
    RiskScorer,
    level_for,
    residual,
)

_n = 0


def finding(
    entity_type: str,
    value: str = "v",
    *,
    detector: str = "regex.x",
    action: Action = Action.MASK,
    category: Category | None = None,
) -> Finding:
    global _n
    _n += 1
    entity = BUILTIN_ENTITIES.get(entity_type)
    return Finding(
        f"f{_n}",
        DetectionResult(
            entity_type,
            SensitiveValue(value),
            0,
            0,
            max(1, len(value)),
            0.9,
            detector,
            detector,
            entity.severity if entity else Severity.HIGH,
        ),
        category or (entity.category if entity else Category.OTHER),
        action,
        "",
    )


def score(findings: list[Finding], **kw: object):  # type: ignore[no-untyped-def]
    return RiskScorer().score(
        findings, value_key=lambda f: f.detection.matched_value.reveal(), **kw
    )  # type: ignore[arg-type]


def points(report) -> dict[str, int]:  # type: ignore[no-untyped-def]
    return {f.id: f.points for f in report.factors}


def test_empty_document_scores_zero() -> None:
    report = score([])
    assert (report.score, report.level, report.factors) == (0, "none", [])


@pytest.mark.parametrize(
    ("value", "level"),
    [(0, "none"), (1, "low"), (24, "low"), (25, "medium"), (50, "high"), (75, "critical")],
)
def test_levels(value: int, level: str) -> None:
    assert level_for(value) == level


def test_one_credential_alone_is_high_risk() -> None:
    report = score([finding("API_KEY", "ghp_x")])
    assert points(report) == {"credentials": 40}
    assert report.level == "medium"
    assert report.factors[0].detail == "1 distinct value found 1 time"


def test_repeats_of_a_value_count_once_and_factors_are_capped() -> None:
    same = [finding("EMAIL", "a@b.example") for _ in range(5)]
    assert points(score(same)) == {"personal": 8}
    many = [finding("EMAIL", f"p{i}@b.example") for i in range(40)]
    assert points(score(many)) == {"personal": 20}
    keys = [finding("API_KEY", f"k{i}") for i in range(10)]
    assert points(score(keys)) == {"credentials": 60}


def test_score_is_the_sum_of_factors_and_never_above_100() -> None:
    mixed = [
        finding("API_KEY", "k1"),
        finding("PAN", "p1"),
        finding("CREDIT_CARD", "c1"),
        finding("EMAIL", "e1"),
    ]
    report = score(mixed)
    assert report.score == sum(points(report).values()) == 40 + 25 + 20 + 8
    huge = [finding("API_KEY", f"k{i}") for i in range(20)] + [
        finding("PAN", f"p{i}") for i in range(20)
    ]
    assert score(huge).score == 100


def test_company_rules_and_language_model_have_their_own_factors() -> None:
    rule = finding("INTERNAL_PROJECT", "Nightjar", detector="custom.normalized")
    names = [finding("PERSON", f"Name {i}", detector="ner.spacy") for i in range(30)]
    report = score([rule, *names])
    assert points(report) == {"company_terms": 15, "names": 10}
    # A company rule in the CREDENTIALS group still counts as a company term once.
    secret_rule = finding(
        "SECRET_TERM", "x", detector="custom.exact", category=Category.CREDENTIALS
    )
    assert points(score([secret_rule])) == {"company_terms": 15}


def test_hidden_volume_and_unreadable_add_points() -> None:
    emails = [finding("EMAIL", f"p{i}@b.example") for i in range(VOLUME_THRESHOLD)]
    report = score(emails, hidden_ids={emails[0].finding_id}, unreadable=2)
    assert points(report) == {"personal": 20, "hidden": 10, "volume": 10, "unreadable": 5}
    assert "1 finding in comments" in report.factors[1].detail
    assert report.factors[3].detail.startswith("2 items")


def test_residual_keeps_allowed_and_blocked_findings() -> None:
    kept = finding("EMAIL", action=Action.ALLOW)
    blocked = finding("API_KEY", action=Action.BLOCK)
    masked = finding("PAN", action=Action.MASK)
    covered = Finding(
        "fc",
        kept.detection,
        kept.category,
        Action.ALLOW,
        "",
        effective_action=Action.MASK,
    )
    assert residual([kept, blocked, masked, covered]) == [kept, blocked]


def test_scores_are_deterministic() -> None:
    items = [finding("EMAIL", "a@b.example"), finding("PAN", "p"), finding("API_KEY", "k")]
    assert score(items).to_json() == score(list(reversed(items))).to_json()


def test_every_factor_is_reachable_and_labelled() -> None:
    assert len({f.id for f in FACTORS}) == len(FACTORS)
    assert all(f.label and f.first <= f.cap for f in FACTORS)


def test_explanations_name_the_rule_not_the_value() -> None:
    assert "Luhn" in explain("regex.card", "Card number")
    assert "Verhoeff" in explain("regex.aadhaar", "Aadhaar number")
    assert explain("ner.spacy", "Person name") == (
        "The on-device language model recognised this as a person name."
    )
    assert explain("custom.normalized", "Internal project") == _REASONS["custom.normalized"]
    both = explain("regex.email", "E-mail address", ("regex.email", "ner.spacy", "ner.spacy"))
    assert both.endswith("Also found by: language model.")
    assert explain("regex.unknown_thing", "Widget id") == "Matches the known format of a widget id."


def test_every_builtin_pattern_detector_has_a_reason() -> None:
    import re
    from pathlib import Path

    import airlock_engine.detectors as package

    root = Path(package.__file__).parent
    sources = "".join(
        p.read_text(encoding="utf-8")
        for folder in ("regex", "secrets", "custom")
        for p in (root / folder).glob("*.py")
    )
    detector_ids = set(re.findall(r'"((?:regex|secret|custom)\.[a-z0-9_]+)"', sources))
    assert len(detector_ids) > 30
    assert detector_ids <= set(_REASONS), detector_ids - set(_REASONS)
    assert detector_name("custom.regex") == "company rule"
    assert detector_name("secret.jwt") == "secret pattern"
    assert detector_name("regex.bank_account") == "bank account pattern"


@pytest.mark.parametrize(
    ("entity_type", "value", "expected"),
    [
        ("EMAIL", "priya.r@example.invalid", "pXXXXXX@example.invalid"),
        ("EMAIL", "ab@x.example", "aXXX@x.example"),
        ("PERSON", "Priya  Raghavan", "P. R."),
        ("ORGANIZATION", "acme corp", "A. C."),
        ("CREDIT_CARD", "4111 1111 1111 1234", "XXXX XXXX XXXX 1234"),
        ("PHONE", "+91 98765 43210", "+XX XXXXX X3210"),
        ("PAN", "ABCDE1234F", "XXXXXX234F"),
        ("IFSC", "ab1", "XXX"),
        ("INTERNAL_PROJECT", "Project Nightjar", "P. N."),
        ("INTERNAL_CODE", "NJ-2041", "XX-2041"),
    ],
)
def test_partial_masking(entity_type: str, value: str, expected: str) -> None:
    assert partial(entity_type, value) == expected


def test_partial_masking_is_never_offered_for_credentials() -> None:
    assert not partial_allowed("API_KEY")
    assert not partial_allowed("PASSWORD")
    assert partial_allowed("EMAIL") and partial_allowed("INTERNAL_PROJECT")
    replacer = Replacer()
    # Asked for partial on a credential, the replacer falls back to a placeholder.
    assert replacer.text_for("API_KEY", "ghp_secret", Action.MASK, "partial") == "[API_KEY_1]"
    assert "ghp_secret" in {v for v, _ in replacer.reversible.values()}


def test_partial_masks_are_not_kept_in_the_vault() -> None:
    replacer = Replacer()
    text = replacer.text_for("CREDIT_CARD", "4111 1111 1111 1234", Action.MASK, "partial")
    assert text == "XXXX XXXX XXXX 1234"
    assert replacer.reversible == {}


def test_profile_styles_per_entity() -> None:
    assert "partial" in MASK_STYLES
    profile = COMPANY_DEFAULT.with_changes(styles={"CREDIT_CARD": "partial"})
    assert profile.style_for("CREDIT_CARD") == "partial"
    assert profile.style_for("EMAIL") == COMPANY_DEFAULT.mask_style
