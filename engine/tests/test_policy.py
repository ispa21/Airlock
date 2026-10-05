"""Policy: profile resolution, defaults, confidence, overlaps, overrides."""

from __future__ import annotations

import pytest

from airlock_engine.core.models import Action, Category, DetectionResult, Severity
from airlock_engine.core.sensitive import SensitiveValue
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.detectors.pipeline import Detected
from airlock_engine.policy.engine import PolicyEngine, Region
from airlock_engine.policy.profiles import (
    BUILTIN_PROFILES,
    COMPANY_DEFAULT,
    SECRETS_AND_IDS,
    STRICT,
)

CATEGORIES = {e.id: e.category for e in BUILTIN_ENTITIES.values()}
CATEGORIES["INTERNAL_PROJECT"] = Category.INTELLECTUAL_PROPERTY
LABELS = {e.id: e.label for e in BUILTIN_ENTITIES.values()}
LABELS["INTERNAL_PROJECT"] = "Internal project"


def det(
    entity_type: str,
    start: int = 0,
    end: int = 5,
    *,
    seg: int = 0,
    conf: float = 0.95,
    detector: str = "regex.x",
    rule_id: str = "",
) -> Detected:
    severity = (
        BUILTIN_ENTITIES[entity_type].severity if entity_type in BUILTIN_ENTITIES else Severity.HIGH
    )
    return Detected(
        DetectionResult(
            entity_type,
            SensitiveValue("x" * (end - start)),
            seg,
            start,
            end,
            conf,
            detector,
            rule_id or detector,
            severity,
        )
    )


def engine(**kw: object) -> PolicyEngine:
    return PolicyEngine(categories=CATEGORIES, labels=LABELS, **kw)  # type: ignore[arg-type]


def decide(items: list[Detected], profile=COMPANY_DEFAULT, overrides=None, **kw):  # type: ignore[no-untyped-def]
    numbered = [(f"f{i}", d) for i, d in enumerate(items, start=1)]
    return engine(**kw).decide(numbered, profile, overrides)


def actions(items: list[Detected], profile=COMPANY_DEFAULT) -> list[str]:  # type: ignore[no-untyped-def]
    return [f.action.value for f in decide(items, profile).findings]


@pytest.mark.parametrize("profile", list(BUILTIN_PROFILES.values()), ids=lambda p: p.id)
def test_credentials_are_blocked_by_every_builtin_profile(profile) -> None:  # type: ignore[no-untyped-def]
    secrets = [e.id for e in BUILTIN_ENTITIES.values() if e.category is Category.CREDENTIALS]
    assert len(secrets) >= 5
    for entity_type in secrets:
        assert actions([det(entity_type)], profile) == ["BLOCK"], entity_type


def test_company_default_table() -> None:
    expected = {
        "EMAIL": "MASK",
        "PHONE": "MASK",
        "PAN": "MASK",
        "AADHAAR": "MASK",
        "CREDIT_CARD": "MASK",
        "BANK_ACCOUNT": "MASK",
        "DATE_OF_BIRTH": "GENERALIZE",
        "LOCATION": "ALLOW",
        "MONEY": "ALLOW",
        "IFSC": "ALLOW",
        "URL": "MASK",
        "IP_ADDRESS": "MASK",
        "PERSON": "MASK",
        "ORGANIZATION": "MASK",
    }
    for entity_type, action in expected.items():
        assert actions([det(entity_type, conf=0.9)]) == [action], entity_type


def test_strict_and_secrets_only_differ_as_documented() -> None:
    assert actions([det("AADHAAR")], STRICT) == ["REDACT"]
    assert actions([det("LOCATION", conf=0.9)], STRICT) == ["MASK"]
    assert actions([det("EMAIL")], SECRETS_AND_IDS) == ["ALLOW"]
    assert actions([det("PAN")], SECRETS_AND_IDS) == ["MASK"]


def test_company_rules_are_enforced_in_every_profile() -> None:
    rule = det("INTERNAL_PROJECT", detector="custom.exact", rule_id="rule_1", conf=1.0)
    assert actions([rule], COMPANY_DEFAULT) == ["MASK"]
    assert actions([rule], STRICT) == ["REDACT"]
    assert actions([rule], SECRETS_AND_IDS) == ["MASK"]


def test_rule_action_overrides_profile() -> None:
    rule = det("INTERNAL_PROJECT", detector="custom.exact", rule_id="rule_1", conf=1.0)
    d = decide([rule], rule_actions={"rule_1": Action.BLOCK})
    assert d.findings[0].action is Action.BLOCK
    assert "company rule" in d.findings[0].policy_reason


def test_low_confidence_is_kept_with_explanation() -> None:
    d = decide([det("PERSON", conf=0.4, detector="ner.spacy")])
    f = d.findings[0]
    assert f.action is Action.ALLOW
    assert "40%" in f.policy_reason and "60%" in f.policy_reason
    # ...but credentials and company rules are never dropped on confidence.
    assert actions([det("PASSWORD", conf=0.3)]) == ["BLOCK"]
    assert actions([det("INTERNAL_PROJECT", conf=0.1, detector="custom.regex")]) == ["MASK"]


def test_generalize_falls_back_to_mask() -> None:
    profile = COMPANY_DEFAULT.with_changes(actions={"PAN": Action.GENERALIZE})
    f = decide([det("PAN")], profile).findings[0]
    assert f.action is Action.MASK
    assert "cannot be generalised" in f.policy_reason


def test_reasons_are_content_free_and_name_the_profile() -> None:
    d = decide([det("EMAIL"), det("API_KEY", 10, 20), det("PERSON", 30, 40, conf=0.75)])
    reasons = [f.policy_reason for f in d.findings]
    assert reasons[0] == "Company Default masks personal data."
    assert reasons[1] == "Company Default blocks credentials such as passwords and keys."
    dob = decide([det("DATE_OF_BIRTH")]).findings[0].policy_reason
    assert dob == "Company Default generalises each date of birth."
    assert all("x" * 5 not in r for r in reasons)


def test_overlaps_form_one_region_with_the_strongest_action() -> None:
    url = det("URL", 0, 60)
    secret = det("CONNECTION_STRING", 20, 30)
    ip = det("IP_ADDRESS", 35, 45)
    d = decide([url, secret, ip])
    assert d.regions == [
        Region(0, 0, 60, Action.BLOCK, "f2", ("f1", "f2", "f3"), "typed_placeholder")
    ]
    by_id = {f.finding_id: f for f in d.findings}
    assert by_id["f2"].covered_by is None
    assert by_id["f1"].covered_by == "f2" and by_id["f1"].effective_action is Action.BLOCK
    assert by_id["f1"].action is Action.MASK  # its own decision is still visible
    assert d.blocked == 1


def test_partial_and_chained_overlaps_merge_into_the_union() -> None:
    d = decide([det("EMAIL", 0, 10), det("PERSON", 8, 20, conf=0.9), det("PHONE", 18, 30)])
    assert [(r.start, r.end) for r in d.regions] == [(0, 30)]


def test_non_overlapping_findings_stay_separate_and_allow_makes_no_region() -> None:
    d = decide(
        [
            det("EMAIL", 0, 5),
            det("EMAIL", 5, 10),
            det("LOCATION", 20, 25, conf=0.9),
            det("EMAIL", 0, 5, seg=1),
        ]
    )
    assert [(r.segment_id, r.start, r.end) for r in d.regions] == [(0, 0, 5), (0, 5, 10), (1, 0, 5)]
    assert d.counts()["ALLOW"] == 1


def test_allowed_finding_inside_masked_one_is_covered() -> None:
    d = decide([det("LOCATION", 5, 10, conf=0.9), det("EMAIL", 0, 20)])
    loc = d.findings[0]
    assert loc.action is Action.ALLOW and loc.effective_action is Action.MASK
    assert loc.covered_by == "f2"


def test_overrides_win_and_are_marked() -> None:
    d = decide(
        [det("EMAIL"), det("API_KEY", 10, 20)], overrides={"f1": Action.ALLOW, "f2": Action.REDACT}
    )
    assert [f.action for f in d.findings] == [Action.ALLOW, Action.REDACT]
    assert all(f.overridden and f.policy_reason == "Changed by you." for f in d.findings)
    assert d.blocked == 0


def test_resolution_order_on_profile() -> None:
    p = COMPANY_DEFAULT
    assert p.resolve("EMAIL", Category.PERSONAL, company_rule=False) == (Action.MASK, "category")
    assert p.resolve("LOCATION", Category.PERSONAL, company_rule=False) == (Action.ALLOW, "entity")
    assert p.resolve("X", Category.BUSINESS, company_rule=True) == (Action.MASK, "company_rule")
    assert SECRETS_AND_IDS.resolve("X", Category.OTHER, company_rule=False) == (
        Action.ALLOW,
        "default",
    )
