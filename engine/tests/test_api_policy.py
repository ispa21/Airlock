"""Policy over RPC: actions in scan results, overrides, profiles."""

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
from test_api_scan import call, req, result_of

pytestmark = pytest.mark.subprocess

S = Synth(404)
PW = S.password()
TOKEN = S.github_token()
EMAIL = S.email()
AADHAAR = S.aadhaar()


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / "service.env"
    path.write_text(
        f"OWNER_EMAIL={EMAIL}\nOWNER_AADHAAR_UID={AADHAAR}\nDB_PASSWORD={PW}\n"
        f"GITHUB_TOKEN={TOKEN}\nNOTIFY={EMAIL}\n",
        encoding="utf-8",
    )
    return path


def error_of(rs: list[dict[str, Any]], i: int) -> dict[str, Any]:
    (r,) = [r for r in rs if r.get("id") == i]
    assert "error" in r, r
    return r["error"]  # type: ignore[no-any-return]


def scan(registry: MethodRegistry, path: Path, **params: Any) -> dict[str, Any]:
    return result_of(call(registry, req(1, "scan.start", path=str(path), ner=False, **params)), 1)


def by_type(result: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    out: dict[str, list[dict[str, Any]]] = {}
    for f in result["findings"]:
        out.setdefault(f["entity_type"], []).append(f)
    return out


def test_default_profile_blocks_credentials_and_masks_the_rest(env_file: Path) -> None:
    result = scan(build_registry(), env_file)
    found = by_type(result)
    assert {f["action"] for f in found["PASSWORD"] + found["API_KEY"]} == {"BLOCK"}
    assert {f["action"] for f in found["EMAIL"]} == {"MASK"}
    assert found["AADHAAR"][0]["action"] == "MASK"
    assert found["API_KEY"][0]["reason"] == (
        "Company Default blocks credentials such as passwords and keys."
    )
    policy = result["policy"]
    assert policy["profile"] == {"id": "company-default", "name": "Company Default",
                                 "builtin": True}
    assert policy["blocked"] == 2 and policy["ready"] is False
    assert policy["actions"]["BLOCK"] == 2 and policy["actions"]["MASK"] == 3
    # The same e-mail appears twice: one value group.
    assert len({f["value_group"] for f in found["EMAIL"]}) == 1


def test_overrides_by_value_group_and_risk_acknowledgement(env_file: Path) -> None:
    registry = build_registry()
    result = scan(registry, env_file)
    scan_id = result["scan_id"]
    found = by_type(result)
    token, email = found["API_KEY"][0], found["EMAIL"][0]

    # Keeping a credential needs explicit acknowledgement; nothing is applied otherwise.
    rs = call(registry, req(2, "scan.override", scan_id=scan_id, overrides=[
        {"value_group": email["value_group"], "action": "ALLOW"},
        {"finding_id": token["id"], "action": "ALLOW"},
    ]))
    assert error_of(rs, 2)["data"]["kind"] == "confirmation_required"

    rs = call(registry, req(3, "scan.override", scan_id=scan_id, overrides=[
        {"value_group": email["value_group"], "action": "ALLOW"},
        {"finding_id": token["id"], "action": "REDACT"},
        {"finding_id": found["PASSWORD"][0]["id"], "action": "REDACT"},
    ]))
    after = result_of(rs, 3)
    now = by_type(after)
    assert {f["action"] for f in now["EMAIL"]} == {"ALLOW"}
    assert all(f["overridden"] and f["reason"] == "Changed by you." for f in now["EMAIL"])
    assert after["policy"]["blocked"] == 0 and after["policy"]["ready"] is True
    assert after["policy"]["overridden"] == 4

    rs = call(registry, req(4, "scan.override", scan_id=scan_id, acknowledge_risk=True,
                            overrides=[{"finding_id": token["id"], "action": "ALLOW"}]))
    assert by_type(result_of(rs, 4))["API_KEY"][0]["action"] == "ALLOW"

    # null returns a finding to the profile's decision.
    rs = call(registry, req(5, "scan.override", scan_id=scan_id,
                            overrides=[{"value_group": email["value_group"], "action": None}]))
    assert {f["action"] for f in by_type(result_of(rs, 5))["EMAIL"]} == {"MASK"}

    rs = call(registry,
              req(6, "scan.override", scan_id=scan_id, overrides=[{"finding_id": "f999",
                                                                   "action": "MASK"}]),
              req(7, "scan.override", scan_id=scan_id, overrides=[{"finding_id": "f1",
                                                                   "action": "DELETE"}]),
              req(8, "scan.override", scan_id="scan_gone", overrides=[{"finding_id": "f1",
                                                                       "action": "MASK"}]))
    assert error_of(rs, 6)["data"]["kind"] == "finding_not_found"
    assert error_of(rs, 7)["code"] == -32602
    assert error_of(rs, 8)["data"]["kind"] == "scan_not_found"


def test_switching_profile_keeps_user_decisions(env_file: Path) -> None:
    registry = build_registry()
    result = scan(registry, env_file)
    email = by_type(result)["EMAIL"][0]
    call(registry, req(2, "scan.override", scan_id=result["scan_id"],
                       overrides=[{"value_group": email["value_group"], "action": "REDACT"}]))
    rs = call(registry, req(3, "scan.set_profile", scan_id=result["scan_id"], profile_id="strict"))
    strict = by_type(result_of(rs, 3))
    assert strict["AADHAAR"][0]["action"] == "REDACT"  # strict removes government ids
    assert {f["action"] for f in strict["EMAIL"]} == {"REDACT"}  # user's choice kept
    assert result_of(rs, 3)["policy"]["profile"]["id"] == "strict"
    rs = call(registry, req(4, "scan.set_profile", scan_id=result["scan_id"], profile_id="nope"))
    assert error_of(rs, 4)["data"]["kind"] == "profile_not_found"


def test_custom_profile_and_rule_action_over_rpc(
    env_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    log = io.StringIO()
    monkeypatch.setattr(safelog, "log", safelog.SafeLogger(log, level="debug"))
    registry = build_registry(tmp_path / "data")
    rs = call(registry, req(1, "profiles.create", name="Payroll Confidential",
                            base_id="company-default"))
    profile = result_of(rs, 1)["profile"]
    assert profile["builtin"] is False and profile["actions"]["EMAIL"]["action"] == "MASK"

    rs = call(registry,
              req(2, "profiles.update", id=profile["id"],
                  actions={"EMAIL": "ALLOW", "AADHAAR": "REDACT"}, min_confidence=0.9),
              req(3, "profiles.update", id="strict", name="Mine"),
              req(4, "profiles.update", id=profile["id"], actions={"PAN": "GENERALIZE"}))
    updated = result_of(rs, 2)["profile"]
    assert updated["actions"]["EMAIL"] == {"action": "ALLOW", "source": "entity"}
    assert error_of(rs, 3)["data"]["kind"] == "invalid_profile"
    assert error_of(rs, 4)["data"]["kind"] == "invalid_profile"

    rs = call(registry, req(5, "profiles.set_default", id=profile["id"]))
    assert result_of(rs, 5)["default_id"] == profile["id"]
    listing = result_of(call(registry, req(6, "profiles.list")), 6)
    assert [p["id"] for p in listing["profiles"]][:3] == ["company-default", "strict",
                                                          "secrets-and-ids"]
    assert listing["default_id"] == profile["id"]
    assert any(t["id"] == "INTERNAL_PROJECT" and t["company_rule"]
               for t in listing["entity_types"])

    # The default profile applies when scan.start names none.
    found = by_type(scan(registry, env_file))
    assert {f["action"] for f in found["EMAIL"]} == {"ALLOW"}
    assert found["AADHAAR"][0]["action"] == "REDACT"

    # A company rule with its own action beats the profile.
    call(registry, req(7, "rules.create", kind="exact", pattern="OWNER_EMAIL",
                       category_id="INTERNAL_SYSTEM", action="BLOCK"))
    found = by_type(scan(registry, env_file, profile_id="company-default"))
    assert found["INTERNAL_SYSTEM"][0]["action"] == "BLOCK"
    assert "company rule" in found["INTERNAL_SYSTEM"][0]["reason"]

    rs = call(registry, req(8, "profiles.delete", id=profile["id"]))
    assert result_of(rs, 8)["default_id"] == "company-default"
    assert "Payroll" not in log.getvalue()


def test_policy_results_never_carry_raw_values(env_file: Path) -> None:
    registry = build_registry()
    result = scan(registry, env_file)
    rs = call(registry, req(2, "scan.set_profile", scan_id=result["scan_id"],
                            profile_id="strict"))
    text = json.dumps(result) + json.dumps(result_of(rs, 2))
    for value in (PW, TOKEN, EMAIL, AADHAAR):
        assert value not in text
