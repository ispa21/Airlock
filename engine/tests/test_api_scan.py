"""scan.* and rules.* end to end: real worker, real detectors, no leaks."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from airlock_engine import safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc.server import MethodRegistry, StdioServer
from conftest import frames, responses
from synthetic import Synth

pytestmark = pytest.mark.subprocess

S = Synth(77)
EMAIL = S.email()
PAN = S.pan()
AADHAAR = S.aadhaar()
_CARD_DIGITS = next(c for c in iter(S.card, None) if len(c.replace(" ", "").replace("-", "")) == 16)
CARD = " ".join(_CARD_DIGITS.replace(" ", "").replace("-", "")[i : i + 4] for i in (0, 4, 8, 12))
GH_TOKEN = S.github_token()
NAME = "Priya Raghavan"
RAW_VALUES = [EMAIL, PAN, AADHAAR, GH_TOKEN, "Project Nightjar", NAME]


def call(registry: MethodRegistry, *messages: dict[str, Any]) -> list[dict[str, Any]]:
    out = io.BytesIO()
    StdioServer(registry, frames(*messages), out).serve_forever()
    return responses(out)


def req(i: int, method: str, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


def result_of(rs: list[dict[str, Any]], i: int) -> dict[str, Any]:
    (r,) = [r for r in rs if r.get("id") == i]
    assert "result" in r, r
    return r["result"]  # type: ignore[no-any-return]


def build_docx(path: Path) -> Path:
    import docx

    document = docx.Document()
    body = document.add_paragraph(f"Customer {NAME} can be reached at {EMAIL}.")
    document.add_paragraph(f"Card on file: {CARD}. Status of Project Nightjar: green.")
    document.add_comment(body.runs, text=f"PAN {PAN}, Aadhaar {AADHAAR}", author="Reviewer")
    document.core_properties.comments = f"deploy token {GH_TOKEN}"
    document.save(str(path))
    return path


@pytest.fixture
def docx_path(tmp_path: Path) -> Path:
    return build_docx(tmp_path / "customer.docx")


@pytest.fixture
def log_capture(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    stream = io.StringIO()
    monkeypatch.setattr(safelog, "log", safelog.SafeLogger(stream, level="debug"))
    return stream


def test_scan_finds_entities_everywhere_without_leaking(
    docx_path: Path, tmp_path: Path, log_capture: io.StringIO
) -> None:
    before = hashlib.sha256(docx_path.read_bytes()).hexdigest()
    registry = build_registry(tmp_path / "data")
    # Requests in one batch run concurrently: dependent calls go in separate batches.
    call(registry, req(1, "rules.create", kind="normalized", pattern="Project Nightjar",
                       category_id="INTERNAL_PROJECT"))
    rs = call(registry, req(2, "scan.start", path=str(docx_path), ocr=False))
    result = result_of(rs, 2)
    findings = result["findings"]
    by_type = {f["entity_type"] for f in findings}
    assert {"EMAIL", "PAN", "AADHAAR", "CREDIT_CARD", "API_KEY", "INTERNAL_PROJECT",
            "PERSON"} <= by_type

    hidden = {f["entity_type"]: f["location"]["kind"] for f in findings if f["hidden"]}
    assert hidden.get("PAN") == "comment"
    assert hidden.get("AADHAAR") == "comment"
    assert hidden.get("API_KEY") == "metadata"

    card = next(f for f in findings if f["entity_type"] == "CREDIT_CARD")
    digits = CARD.replace(" ", "")
    assert card["preview"].endswith(digits[-4:]) and digits[:6] not in card["preview"]
    token = next(f for f in findings if f["entity_type"] == "API_KEY")
    assert token["preview"].startswith(GH_TOKEN[:4]) and GH_TOKEN[5:] not in token["preview"]
    rule_hit = next(f for f in findings if f["entity_type"] == "INTERNAL_PROJECT")
    assert rule_hit["detector"] == "custom.normalized" and rule_hit["rule_id"]

    summary = result["summary"]
    assert summary["total"] == len(findings)
    assert summary["hidden"] >= 3
    assert summary["max_severity"] == "critical"
    assert summary["detectors"]["ner"] == "used"
    assert summary["detectors"]["company_rules"] == 1
    assert result["extraction"]["segment_count"] > 0
    assert result["risk"] is None

    # Nothing raw crosses IPC (the rule text came from the user, in request 1 only).
    serialized = json.dumps(result)
    for value in RAW_VALUES:
        assert value not in serialized, value
    assert "".join(ch for ch in CARD if ch.isdigit()) not in serialized
    # ...or reaches the log.
    log_text = log_capture.getvalue()
    for value in [*RAW_VALUES, "Nightjar", "internal_project"]:
        assert value.lower() not in log_text.lower(), value
    assert '"event":"scan_completed"' in log_text
    assert hashlib.sha256(docx_path.read_bytes()).hexdigest() == before


def test_scan_discard_and_session_ids(docx_path: Path) -> None:
    registry = build_registry()
    rs = call(registry, req(1, "scan.start", path=str(docx_path), ocr=False, ner=False))
    scan_id = result_of(rs, 1)["scan_id"]
    assert scan_id.startswith("scan_")
    assert result_of(rs, 1)["summary"]["detectors"]["ner"] == "disabled"
    rs = call(registry, req(2, "scan.discard", scan_id=scan_id))
    rs += call(registry, req(3, "scan.discard", scan_id=scan_id))
    assert result_of(rs, 2) == {"ok": True, "discarded": True}
    assert result_of(rs, 3) == {"ok": True, "discarded": False}


def test_scan_of_env_file_flags_credentials(tmp_path: Path) -> None:
    env = tmp_path / "prod.env"
    pw = S.password()
    env.write_text(f"DB_HOST=10.20.30.40\nDB_PASSWORD={pw}\nAPI_TOKEN={GH_TOKEN}\n"
                   "LOG_LEVEL=info\n", encoding="utf-8")
    rs = call(build_registry(), req(1, "scan.start", path=str(env), ner=False))
    findings = result_of(rs, 1)["findings"]
    assert {(f["entity_type"], f["severity"]) for f in findings} >= {
        ("PASSWORD", "critical"), ("API_KEY", "critical"), ("IP_ADDRESS", "medium"),
    }
    assert pw not in json.dumps(findings)


def test_scan_errors_are_actionable(tmp_path: Path) -> None:
    rs = call(build_registry(), req(1, "scan.start", path=str(tmp_path / "missing.pdf")),
              req(2, "scan.start", path=str(tmp_path), ner="yes"))
    errors = {r["id"]: r["error"] for r in rs if "error" in r}
    assert errors[1]["data"]["kind"] == "file_not_found"
    assert errors[2]["code"] == -32602


def test_rules_rpc_crud_and_validation(tmp_path: Path, log_capture: io.StringIO) -> None:
    registry = build_registry(tmp_path)
    rs = call(registry, req(1, "rules.add_category", label="Codenames",
                            group="INTELLECTUAL_PROPERTY", severity=4))
    assert result_of(rs, 1)["category"]["id"] == "CODENAMES"
    rs = call(
        registry,
        req(2, "rules.create", kind="exact", pattern="Falconer", category_id="CODENAMES",
            aliases=["FLC"]),
        req(3, "rules.create", kind="regex", pattern="Secretive(", category_id="CODENAMES"),
        req(4, "rules.create", kind="exact", pattern="x", category_id="NOPE"),
    )
    rule = result_of(rs, 2)["rule"]
    assert rule["aliases"] == ["FLC"]
    errors = {r["id"]: r["error"] for r in rs if "error" in r}
    assert errors[3]["data"]["kind"] == "invalid_rule"
    assert "Secretive" not in errors[3]["message"]
    assert errors[4]["data"]["kind"] == "invalid_rule"
    listing = result_of(call(registry, req(5, "rules.list")), 5)
    assert [r["id"] for r in listing["rules"]] == [rule["id"]]
    assert "regex" in listing["kinds"] and "BLOCK" in listing["actions"]

    rs = call(registry, req(6, "rules.update", id=rule["id"], enabled=False),
              req(7, "rules.update", id="rule_nope", enabled=False))
    assert result_of(rs, 6)["rule"]["enabled"] is False
    rs += call(registry, req(8, "rules.delete", id=rule["id"]))
    rs += call(registry, req(9, "rules.delete", id=rule["id"]),
               req(10, "rules.update", id=rule["id"], enabled="no"))
    errors = {r["id"]: r["error"] for r in rs if "error" in r}
    assert errors[7]["data"]["kind"] == "rule_not_found"
    assert errors[9]["data"]["kind"] == "rule_not_found"
    assert errors[10]["code"] == -32602
    assert "Falconer" not in log_capture.getvalue()
    assert "codenames" not in log_capture.getvalue().lower()


def test_allow_listed_values_are_not_reported(tmp_path: Path, docx_path: Path) -> None:
    from airlock_engine.storage import Storage

    Storage(tmp_path).allow_list.add("EMAIL", EMAIL)
    rs = call(build_registry(tmp_path), req(1, "scan.start", path=str(docx_path), ocr=False,
                                            ner=False))
    result = result_of(rs, 1)
    assert "EMAIL" not in {f["entity_type"] for f in result["findings"]}
    assert result["summary"]["allowed"] == 1


def test_scan_cancellation(tmp_path: Path) -> None:
    big = tmp_path / "big.txt"
    big.write_text(("Contact a.b@example.invalid or +91 98765 43210. " * 40 + "\n") * 4000,
                   encoding="utf-8")
    rs = call(
        build_registry(),
        req(1, "scan.start", path=str(big), ner=False),
        {"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 1}},
    )
    (r,) = [r for r in rs if r.get("id") == 1]
    # Either the cancel landed (preferred) or the scan was already finished.
    assert r.get("error", {}).get("code") == -32001 or "result" in r
