"""Conversations, privacy modes, the outbound check and response restoration
(Phase 12) over RPC."""

from __future__ import annotations

import io
import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from airlock_engine import safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc.server import MethodRegistry
from synthetic import Synth
from test_api_scan import call, req, result_of

S = Synth(1212)
EMAIL = S.email()
EMAIL_2 = S.email()
PAN = S.pan()
PROJECT = "Project Phoenix"
VALUES = (EMAIL, EMAIL_2, PAN, PROJECT)


def error_of(rs: list[dict[str, Any]], i: int) -> dict[str, Any]:
    (r,) = [r for r in rs if r.get("id") == i]
    assert "error" in r, r
    return r["error"]  # type: ignore[no-any-return]


@pytest.fixture
def log() -> Iterator[io.StringIO]:
    stream = io.StringIO()
    original = safelog.log
    safelog.log = safelog.SafeLogger(stream, level="debug")
    try:
        yield stream
    finally:
        safelog.log = original


@pytest.fixture
def registry(tmp_path: Path) -> MethodRegistry:
    registry = build_registry(tmp_path / "data")
    call(
        registry,
        req(1, "rules.create", kind="exact", pattern=PROJECT, category_id="INTERNAL_PROJECT"),
    )
    return registry


def start(registry: MethodRegistry) -> str:
    conversation_id: str = result_of(call(registry, req(1, "conversation.start")), 1)[
        "conversation_id"
    ]
    return conversation_id


def protect(registry: MethodRegistry, text: str, **params: Any) -> dict[str, Any]:
    rs = call(registry, req(1, "text.protect", text=text, ner=False, **params))
    return result_of(rs, 1)


def test_placeholders_stay_stable_across_turns_and_responses_are_restored(
    registry: MethodRegistry, log: io.StringIO
) -> None:
    cid = start(registry)
    assert re.fullmatch(r"AIRLOCK-\d{4}-\d{6}", cid)

    first = protect(registry, f"Write to {EMAIL} about {PROJECT}, PAN {PAN}.", conversation_id=cid)
    assert first["text"] == "Write to EMAIL_001 about INTERNAL_PROJECT_001, PAN PAN_001."
    assert first["check"]["status"] == "safe" and first["placeholders"] == 3
    second = protect(registry, f"Copy {EMAIL_2} and {EMAIL} on {PROJECT}.", conversation_id=cid)
    assert second["text"] == "Copy EMAIL_002 and EMAIL_001 on INTERNAL_PROJECT_001."

    status = result_of(call(registry, req(2, "conversation.status", conversation_id=cid)), 2)
    assert status["placeholders"] == 4
    assert status["types"] == {"EMAIL": 2, "INTERNAL_PROJECT": 1, "PAN": 1}

    reply = (
        "Draft: Hi EMAIL_001's team, INTERNAL_PROJECT_001 is on track. "
        "Loop in EMAIL_002 and PERSON_009. Not EMAIL_0011."
    )
    analysis = result_of(
        call(registry, req(3, "response.analyze", conversation_id=cid, text=reply)), 3
    )
    assert analysis == {
        "placeholders": 3,
        "occurrences": 3,
        "types": {"EMAIL": 2, "INTERNAL_PROJECT": 1},
        "unknown": ["PERSON_009", "EMAIL_0011"],
        "unknown_count": 2,
    }
    review = result_of(
        call(registry, req(4, "response.review", conversation_id=cid, text=reply)), 4
    )
    assert {(i["placeholder"], i["original"]) for i in review["items"]} == {
        ("EMAIL_001", EMAIL),
        ("EMAIL_002", EMAIL_2),
        ("INTERNAL_PROJECT_001", PROJECT),
    }
    restored = result_of(
        call(registry, req(5, "response.restore", conversation_id=cid, text=reply)), 5
    )
    assert restored["text"] == (
        f"Draft: Hi {EMAIL}'s team, {PROJECT} is on track. "
        f"Loop in {EMAIL_2} and PERSON_009. Not EMAIL_0011."
    )
    assert restored["restored"] == 3

    for value in VALUES:
        assert value not in log.getvalue()
        assert value not in json.dumps(first) + json.dumps(second)
        assert value not in json.dumps(status) + json.dumps(analysis)
    events = log.getvalue()
    assert '"event":"conversation_started"' in events
    assert '"event":"response_restored"' in events


def test_values_from_earlier_turns_stay_protected_without_detection(
    registry: MethodRegistry,
) -> None:
    cid = start(registry)
    protect(registry, f"Status of {PROJECT}?", conversation_id=cid)
    rules = result_of(call(registry, req(2, "rules.list")), 2)["rules"]
    call(registry, req(3, "rules.delete", id=rules[0]["id"]))
    # The rule is gone, but the conversation still knows the value.
    later = protect(registry, f"And the budget for {PROJECT}?", conversation_id=cid)
    assert later["text"] == "And the budget for INTERNAL_PROJECT_001?"
    assert later["check"]["status"] == "safe"
    # Written differently, it is not replaced, and the outbound check stops it.
    shouted = protect(registry, f"Is {PROJECT.upper()} late?", conversation_id=cid)
    assert shouted["check"]["status"] == "blocked"
    assert shouted["check"]["remaining_count"] == 1
    assert PROJECT.upper() not in json.dumps(shouted["check"])


def test_privacy_modes(registry: MethodRegistry) -> None:
    text = f"Mail {EMAIL} about {PROJECT}."
    cid = start(registry)
    redacted = protect(registry, text, conversation_id=cid, mode="redact")
    assert redacted["text"] == "Mail [REDACTED] about [REDACTED]."
    assert redacted["placeholders"] == 0 and redacted["check"]["status"] == "safe"
    status = result_of(call(registry, req(2, "conversation.status", conversation_id=cid)), 2)
    assert status["placeholders"] == 0  # nothing to restore, nothing stored

    synthetic = protect(registry, text, conversation_id=cid, mode="synthetic")
    assert synthetic["text"] == "Mail person1@example.invalid about INTERNAL_PROJECT_001."
    reply = "Sure, I'll mail person1@example.invalid."
    restored = result_of(
        call(registry, req(3, "response.restore", conversation_id=cid, text=reply)), 3
    )
    assert restored["text"] == f"Sure, I'll mail {EMAIL}."

    blocked = protect(registry, text, mode="block")
    assert blocked["text"] is None and blocked["withheld"] is True
    assert blocked["blocked"] == 2 and blocked["check"] is None
    clean = protect(registry, "Nothing sensitive here.", mode="block")
    assert clean["text"] == "Nothing sensitive here." and clean["withheld"] is False


def test_credentials_are_removed_and_never_restorable(registry: MethodRegistry) -> None:
    cid = start(registry)
    password = S.password()
    result = protect(registry, f"db_password = {password}", conversation_id=cid)
    assert password not in result["text"] and "[REDACTED]" in result["text"]
    assert result["blocked"] == 1
    status = result_of(call(registry, req(2, "conversation.status", conversation_id=cid)), 2)
    assert status["placeholders"] == 0


def test_unknown_and_forgotten_conversations(registry: MethodRegistry) -> None:
    rs = call(registry, req(1, "text.protect", text="x", conversation_id="AIRLOCK-2026-000000"))
    assert error_of(rs, 1)["data"]["kind"] == "conversation_not_found"
    rs = call(registry, req(2, "response.restore", conversation_id="../vault.key", text="x"))
    assert error_of(rs, 2)["data"]["kind"] == "conversation_not_found"
    rs = call(registry, req(3, "response.restore", text="x"))
    assert error_of(rs, 3)["code"] == -32602

    cid = start(registry)
    protect(registry, f"Mail {EMAIL}", conversation_id=cid)
    listing = result_of(call(registry, req(4, "conversation.list")), 4)
    assert [c["conversation_id"] for c in listing["conversations"]] == [cid]
    assert EMAIL not in json.dumps(listing)
    forgotten = result_of(call(registry, req(5, "conversation.forget", conversation_id=cid)), 5)
    assert forgotten == {"ok": True, "deleted": True}
    rs = call(registry, req(6, "response.restore", conversation_id=cid, text="EMAIL_001"))
    assert error_of(rs, 6)["data"]["kind"] == "conversation_not_found"


def test_conversation_records_are_encrypted_on_disk(tmp_path: Path) -> None:
    registry = build_registry(tmp_path / "data")
    cid = start(registry)
    protect(registry, f"Mail {EMAIL}", conversation_id=cid)
    record = tmp_path / "data" / "vault" / f"{cid}.bin"
    assert record.exists() and EMAIL.encode() not in record.read_bytes()
    assert b"EMAIL_001" not in record.read_bytes()


def test_a_protected_copy_can_share_a_conversation(
    registry: MethodRegistry, tmp_path: Path
) -> None:
    """The opt-in privacy workspace: a document and the prompts about it use
    the same placeholders."""
    cid = start(registry)
    protect(registry, f"Mail {EMAIL_2}, then {EMAIL}.", conversation_id=cid)
    source = tmp_path / "notes.txt"
    source.write_text(f"Owner {EMAIL}; new contact {S.email()}\n", encoding="utf-8")
    scan = result_of(call(registry, req(2, "scan.start", path=str(source), ocr=False)), 2)
    copy = result_of(
        call(registry, req(3, "sanitize.run", scan_id=scan["scan_id"], conversation_id=cid)), 3
    )
    text = result_of(
        call(registry, req(4, "verify.run", artifact_id=copy["artifact_id"])),
        4,
    )
    assert text["status"] == "passed"
    exported = result_of(call(registry, req(5, "export.text", artifact_id=copy["artifact_id"])), 5)[
        "text"
    ]
    assert exported == "Owner EMAIL_002; new contact EMAIL_003\n"
    status = result_of(call(registry, req(6, "conversation.status", conversation_id=cid)), 6)
    assert status["placeholders"] == 3
    # The copy's own record restores its placeholders too.
    restored = result_of(
        call(
            registry,
            req(
                7, "response.restore", artifact_id=copy["artifact_id"], text="EMAIL_002 / EMAIL_001"
            ),
        ),
        7,
    )
    assert restored["text"] == f"{EMAIL} / EMAIL_001"
