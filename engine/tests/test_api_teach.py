"""Phase 6 over RPC: risk, explanations, mask styles, teaching, refresh."""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import Any

import pytest

from airlock_engine import safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc.server import MethodRegistry
from synthetic import Synth
from test_api_policy import error_of
from test_api_sanitize import copy_path
from test_api_scan import call, req, result_of

pytestmark = pytest.mark.subprocess

S = Synth(606)
EMAIL = S.email()
PW = S.password()
NAME = "Priya Raghavan"
IP = "10.20.30.40"


@pytest.fixture
def note(tmp_path: Path) -> Path:
    path = tmp_path / "note.txt"
    path.write_text(
        f"Customer {NAME} wrote from {EMAIL} about the renewal.\n"
        f"Server {IP} hosts the billing service. Reply to {EMAIL}.\n"
        f"password: {PW}\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def log_capture(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    stream = io.StringIO()
    monkeypatch.setattr(safelog, "log", safelog.SafeLogger(stream, level="debug"))
    return stream


def scan(registry: MethodRegistry, path: Path, ner: bool = False) -> dict[str, Any]:
    return result_of(call(registry, req(1, "scan.start", path=str(path), ner=ner)), 1)


def first(result: dict[str, Any], entity_type: str) -> dict[str, Any]:
    return next(f for f in result["findings"] if f["entity_type"] == entity_type)


def types(result: dict[str, Any]) -> set[str]:
    return {f["entity_type"] for f in result["findings"]}


def test_report_explains_each_finding_and_groups_categories(note: Path) -> None:
    result = scan(build_registry(), note)
    email = first(result, "EMAIL")
    assert email["explanation"].startswith("Has the form of an e-mail address")
    assert email["mask_style"] == "typed_placeholder" and email["partial_available"] is True
    assert first(result, "PASSWORD")["partial_available"] is False
    personal = next(c for c in result["summary"]["by_category"] if c["category"] == "PERSONAL")
    assert personal == {
        "category": "PERSONAL",
        "count": 2,
        "distinct": 1,
        "max_severity": "medium",
        "actions": {"MASK": 2},
    }
    risk = result["risk"]
    assert [f["id"] for f in risk["before"]["factors"]] == ["credentials", "personal", "business"]
    # Only the blocked password still counts once the copy is protected.
    assert [f["id"] for f in risk["after"]["factors"]] == ["credentials"]
    assert EMAIL not in json.dumps(result) and PW not in json.dumps(result)


def test_partial_mask_style_override_reaches_the_protected_copy(note: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    registry = build_registry(data)
    result = scan(registry, note)
    scan_id = result["scan_id"]
    email, password = first(result, "EMAIL"), first(result, "PASSWORD")
    rs = call(
        registry,
        req(
            2,
            "scan.override",
            scan_id=scan_id,
            overrides=[
                {"value_group": email["value_group"], "action": "MASK", "mask_style": "partial"},
                {"finding_id": password["id"], "action": "REDACT"},
            ],
        ),
    )
    updated = result_of(rs, 2)
    assert {f["mask_style"] for f in updated["findings"] if f["entity_type"] == "EMAIL"} == {
        "partial"
    }
    rs = call(
        registry,
        req(
            3,
            "scan.override",
            scan_id=scan_id,
            overrides=[{"finding_id": password["id"], "action": "MASK", "mask_style": "partial"}],
        ),
        req(
            4,
            "scan.override",
            scan_id=scan_id,
            overrides=[{"finding_id": email["id"], "action": "REDACT", "mask_style": "partial"}],
        ),
        req(
            5,
            "scan.override",
            scan_id=scan_id,
            overrides=[{"finding_id": email["id"], "action": "MASK", "mask_style": "fancy"}],
        ),
    )
    for i in (3, 4, 5):
        assert error_of(rs, i)["code"] == -32602

    rs = call(registry, req(6, "sanitize.run", scan_id=scan_id))
    artifact = result_of(rs, 6)
    text = copy_path(data, artifact["artifact_id"]).read_text(encoding="utf-8")
    local, _, domain = EMAIL.rpartition("@")
    assert EMAIL not in text and PW not in text
    assert text.count(f"{local[0]}{'X' * max(3, len(local) - 1)}@{domain}") == 2
    # Partial masks are not reversible, so nothing for the e-mail goes to the vault.
    assert "[EMAIL_" not in text


def test_teach_not_sensitive_then_clear(
    note: Path, tmp_path: Path, log_capture: io.StringIO
) -> None:
    data = tmp_path / "data"
    registry = build_registry(data)
    result = scan(registry, note)
    scan_id = result["scan_id"]
    email = first(result, "EMAIL")
    rs = call(
        registry,
        req(2, "scan.teach", scan_id=scan_id, finding_id=email["id"], kind="not_sensitive"),
    )
    taught = result_of(rs, 2)
    assert taught["scan_id"] == scan_id
    assert "EMAIL" not in types(taught)
    assert taught["summary"]["allowed"] == 2
    assert result_of(call(registry, req(3, "allowlist.status")), 3) == {"count": 1}
    # Remembered for every later scan.
    assert "EMAIL" not in types(scan(registry, note))

    rs = call(registry, req(4, "allowlist.clear"))
    assert result_of(rs, 4) == {"ok": True, "count": 0}
    refreshed = result_of(call(registry, req(5, "scan.refresh", scan_id=scan_id)), 5)
    assert "EMAIL" in types(refreshed)

    log_text = log_capture.getvalue()
    assert '"event":"airlock_taught"' in log_text and '"status":"not_sensitive"' in log_text
    assert '"event":"allowlist_cleared"' in log_text
    for value in (EMAIL, PW, NAME, IP):
        assert value not in log_text
    db = (data / "airlock.db").read_bytes()
    assert EMAIL.encode() not in db


def test_credentials_cannot_be_taught(note: Path, tmp_path: Path) -> None:
    registry = build_registry(tmp_path / "data")
    result = scan(registry, note)
    password = first(result, "PASSWORD")
    rs = call(
        registry,
        req(
            2,
            "scan.teach",
            scan_id=result["scan_id"],
            finding_id=password["id"],
            kind="not_sensitive",
        ),
        req(
            3,
            "scan.teach",
            scan_id=result["scan_id"],
            finding_id=password["id"],
            kind="company_rule",
        ),
        req(4, "scan.teach", scan_id=result["scan_id"], finding_id="f_nope", kind="not_sensitive"),
        req(
            5,
            "scan.teach",
            scan_id=result["scan_id"],
            finding_id=first(result, "EMAIL")["id"],
            kind="forget",
        ),
        req(6, "scan.refresh", scan_id="scan_nope"),
    )
    assert error_of(rs, 2)["data"]["kind"] == "cannot_teach_credential"
    assert error_of(rs, 3)["data"]["kind"] == "cannot_teach_credential"
    assert error_of(rs, 4)["data"]["kind"] == "finding_not_found"
    assert error_of(rs, 5)["code"] == -32602
    assert error_of(rs, 6)["data"]["kind"] == "scan_not_found"
    assert result_of(call(registry, req(7, "allowlist.status")), 7) == {"count": 0}
    assert result_of(call(registry, req(8, "rules.list")), 8)["rules"] == []


def test_teach_company_rule_and_decisions_carry_over(note: Path, tmp_path: Path) -> None:
    registry = build_registry(tmp_path / "data")
    result = scan(registry, note, ner=True)
    scan_id = result["scan_id"]
    person = first(result, "PERSON")
    assert person["detector"].startswith("ner.")
    email = first(result, "EMAIL")
    call(
        registry,
        req(
            2,
            "scan.override",
            scan_id=scan_id,
            overrides=[{"value_group": email["value_group"], "action": "REDACT"}],
        ),
    )
    rs = call(
        registry,
        req(
            3,
            "scan.teach",
            scan_id=scan_id,
            finding_id=person["id"],
            kind="company_rule",
            match="exact",
        ),
    )
    taught = result_of(rs, 3)
    rule_hit = first(taught, "CONFIDENTIAL_TERM")
    assert rule_hit["detector"] == "custom.exact" and rule_hit["rule_id"]
    assert "PERSON" not in types(taught)
    # The user's earlier choice for the e-mail survives the refresh.
    assert {
        (f["action"], f["overridden"]) for f in taught["findings"] if f["entity_type"] == "EMAIL"
    } == {("REDACT", True)}
    assert "company_terms" in {f["id"] for f in taught["risk"]["before"]["factors"]}
    # A rule match is managed through the rule itself, not taught again.
    rs = call(
        registry,
        req(
            5,
            "scan.teach",
            scan_id=scan_id,
            finding_id=rule_hit["id"],
            kind="not_sensitive",
        ),
    )
    assert error_of(rs, 5)["data"]["kind"] == "cannot_teach_rule_match"
    rules = result_of(call(registry, req(4, "rules.list")), 4)["rules"]
    assert [(r["kind"], r["category_id"]) for r in rules] == [("exact", "CONFIDENTIAL_TERM")]
    assert NAME not in json.dumps(taught)


def test_profile_styles_apply_to_new_scans(note: Path, tmp_path: Path) -> None:
    registry = build_registry(tmp_path / "data")
    rs = call(registry, req(1, "profiles.create", name="Readable", base_id="company-default"))
    profile_id = result_of(rs, 1)["profile"]["id"]
    rs = call(
        registry,
        req(2, "profiles.update", id=profile_id, styles={"EMAIL": "partial"}),
    )
    entry = result_of(rs, 2)["profile"]["actions"]["EMAIL"]
    assert entry["style"] == "partial"
    rs = call(
        registry,
        req(3, "profiles.update", id=profile_id, styles={"PASSWORD": "partial"}),
        req(4, "profiles.update", id=profile_id, styles={"EMAIL": "fancy"}),
        req(5, "profiles.update", id="company-default", styles={"EMAIL": "partial"}),
    )
    for i in (3, 4, 5):
        assert error_of(rs, i)["data"]["kind"] == "invalid_profile"
    result = result_of(
        call(registry, req(6, "scan.start", path=str(note), ner=False, profile_id=profile_id)), 6
    )
    assert first(result, "EMAIL")["mask_style"] == "partial"
    assert first(result, "IP_ADDRESS")["mask_style"] == "typed_placeholder"
    rs = call(registry, req(7, "profiles.update", id=profile_id, styles={"EMAIL": None}))
    entry = result_of(rs, 7)["profile"]["actions"]["EMAIL"]
    assert entry["style"] == "typed_placeholder"


def test_refresh_applies_the_edited_profile(note: Path, tmp_path: Path) -> None:
    registry = build_registry(tmp_path / "data")
    rs = call(registry, req(1, "profiles.create", name="Mine", base_id="company-default"))
    profile_id = result_of(rs, 1)["profile"]["id"]
    result = result_of(
        call(registry, req(2, "scan.start", path=str(note), ner=False, profile_id=profile_id)), 2
    )
    assert first(result, "IP_ADDRESS")["action"] == "MASK"
    call(registry, req(3, "profiles.update", id=profile_id, actions={"IP_ADDRESS": "REDACT"}))
    rs = call(registry, req(4, "scan.refresh", scan_id=result["scan_id"]))
    assert first(result_of(rs, 4), "IP_ADDRESS")["action"] == "REDACT"
    # A deleted profile falls back to the default one.
    call(registry, req(5, "profiles.delete", id=profile_id))
    rs = call(registry, req(6, "scan.refresh", scan_id=result["scan_id"]))
    assert result_of(rs, 6)["policy"]["profile"]["id"] == "company-default"
