"""verify.run and export.* end to end: real worker, every format, no leaks."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from airlock_engine.api import build_registry
from airlock_engine.ipc.server import MethodRegistry
from synthetic import Synth
from test_api_sanitize import _CANARY, CASES, copy_path, error_of, log, protect, registry
from test_api_scan import call, req, result_of

pytestmark = pytest.mark.subprocess

__all__ = ["log", "registry"]  # fixtures shared with test_api_sanitize

S = Synth(707)
EMAIL = S.email()
PW = S.password()


def verify(reg: MethodRegistry, artifact_id: str) -> dict[str, Any]:
    return result_of(call(reg, req(20, "verify.run", artifact_id=artifact_id)), 20)


def save(reg: MethodRegistry, artifact_id: str, destination: Path, **params: Any) -> dict[str, Any]:
    (r,) = call(
        reg,
        req(21, "export.save", artifact_id=artifact_id, destination=str(destination), **params),
    )
    return r


@pytest.mark.parametrize(("name", "build", "ocr"), CASES, ids=[c[0] for c in CASES])
def test_every_format_verifies_and_exports(
    name: str,
    build: Any,
    ocr: bool,
    registry: MethodRegistry,
    tmp_path: Path,
    log: io.StringIO,
) -> None:
    source = tmp_path / name
    source.write_bytes(build())
    before = hashlib.sha256(source.read_bytes()).hexdigest()
    _, artifact, _ = protect(registry, source, ocr=ocr)
    artifact_id = artifact["artifact_id"]

    result = verify(registry, artifact_id)
    assert result["status"] == "passed", result
    assert result["remaining"] == [] and result["unreadable"] == []
    assert result["checked"]["protected_values"] >= 1

    out = tmp_path / "out"
    out.mkdir()
    prepared = result_of(call(registry, req(22, "export.prepare", artifact_id=artifact_id)), 22)
    destination = out / prepared["file_name"]
    saved = save(registry, artifact_id, destination)
    assert saved["result"]["file_name"] == destination.name
    assert destination.read_bytes() == copy_path(tmp_path / "data", artifact_id).read_bytes()

    text = result_of(call(registry, req(23, "export.text", artifact_id=artifact_id)), 23)["text"]
    assert not _CANARY.search(text.encode())
    as_text = out / prepared["file_name"].rsplit(".", 1)[0]
    saved = save(registry, artifact_id, as_text.with_suffix(".txt"), as_text=True)
    assert as_text.with_suffix(".txt").read_text(encoding="utf-8") == text

    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    log_text = log.getvalue()
    assert '"event":"verify_completed"' in log_text and '"status":"passed"' in log_text
    assert '"event":"export_completed"' in log_text
    assert not _CANARY.search(log_text.encode())
    assert str(tmp_path) not in log_text


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    path = tmp_path / "service.env"
    path.write_text(f"OWNER={EMAIL}\nDB_PASSWORD={PW}\nNOTIFY={EMAIL}\n", encoding="utf-8")
    return path


def test_nothing_leaves_before_a_check(env_file: Path, tmp_path: Path) -> None:
    reg = build_registry(tmp_path / "data")
    _, artifact, _ = protect(reg, env_file, ocr=False)
    artifact_id = artifact["artifact_id"]
    rs = call(
        reg,
        req(1, "export.text", artifact_id=artifact_id),
        req(2, "export.prepare", artifact_id=artifact_id),
        req(3, "export.save", artifact_id=artifact_id, destination=str(tmp_path / "x.env")),
        req(4, "verify.run", artifact_id="art_0000000000000000"),
    )
    for i in (1, 2, 3):
        assert error_of(rs, i)["data"]["kind"] == "copy_not_verified"
    assert error_of(rs, 4)["data"]["kind"] == "copy_not_found"
    assert not (tmp_path / "x.env").exists()


def test_a_value_left_in_the_copy_blocks_every_export(
    env_file: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import airlock_engine.api.sanitize as sanitize_api
    from airlock_engine.masking import masker

    def leaky(document: Any, decision: Any) -> masker.MaskPlan:
        # Simulate a sanitizer bug: the e-mail is recorded as protected but never replaced.
        plan = masker.build_plan(document, decision)
        segments = {s.segment_id: s for s in document.segments}
        plan.edits = [e for e in plan.edits if segments[e[0]].text[e[1] : e[2]] != EMAIL]
        plan.sweep = [(v, t) for v, t in plan.sweep if v != EMAIL]
        return plan

    monkeypatch.setattr(sanitize_api, "build_plan", leaky)
    reg = build_registry(tmp_path / "data")
    _, artifact, _ = protect(reg, env_file, ocr=False)
    artifact_id = artifact["artifact_id"]
    result = verify(reg, artifact_id)
    assert result["status"] == "failed" and result["remaining_count"] == 1
    (row,) = result["remaining"]
    assert row["reason"] == "protected" and row["entity_type"] == "EMAIL"
    assert EMAIL not in json.dumps(result)

    destination = tmp_path / "out.env"
    rs = call(
        reg,
        req(1, "export.text", artifact_id=artifact_id, acknowledge_review=True),
        req(2, "export.save", artifact_id=artifact_id, destination=str(destination)),
    )
    assert error_of(rs, 1)["data"]["kind"] == "verification_failed"
    assert error_of(rs, 2)["data"]["kind"] == "verification_failed"
    assert not destination.exists()


def test_new_findings_need_an_acknowledgement(env_file: Path, tmp_path: Path) -> None:
    from airlock_engine.storage import Storage

    data = tmp_path / "data"
    Storage(data).allow_list.add("EMAIL", EMAIL)
    reg = build_registry(data)
    _, artifact, _ = protect(reg, env_file, ocr=False)
    artifact_id = artifact["artifact_id"]
    # The user forgets the "not sensitive" decision before the copy is checked.
    call(reg, req(1, "allowlist.clear"))
    result = verify(reg, artifact_id)
    assert result["status"] == "review" and result["new_count"] == 2
    assert {r["entity_type"] for r in result["remaining"]} == {"EMAIL"}

    destination = tmp_path / "out.env"
    r = save(reg, artifact_id, destination)
    assert r["error"]["data"]["kind"] == "review_required"
    r = save(reg, artifact_id, destination, acknowledge_review=True)
    assert r["result"]["ok"] is True
    assert PW not in destination.read_text(encoding="utf-8")


def test_export_guards(env_file: Path, tmp_path: Path) -> None:
    data = tmp_path / "data"
    reg = build_registry(data)
    _, artifact, _ = protect(reg, env_file, ocr=False)
    artifact_id = artifact["artifact_id"]
    assert verify(reg, artifact_id)["status"] == "passed"

    assert (
        save(reg, artifact_id, env_file)["error"]["data"]["kind"]
        == "export_would_overwrite_original"
    )
    assert save(reg, artifact_id, tmp_path / "out.txt")["error"]["data"]["kind"] == (
        "export_wrong_extension"
    )
    assert save(reg, artifact_id, data / "out.env")["error"]["data"]["kind"] == (
        "export_destination_invalid"
    )
    assert env_file.read_text(encoding="utf-8").count(EMAIL) == 2

    # The copy changed after the check: it can no longer leave.
    copy = copy_path(data, artifact_id)
    copy.chmod(0o600)
    copy.write_bytes(copy.read_bytes() + b"\nX=1\n")
    r = save(reg, artifact_id, tmp_path / "out.env")
    assert r["error"]["data"]["kind"] == "copy_changed"
    assert not (tmp_path / "out.env").exists()

    # A discarded copy is gone for good.
    call(reg, req(5, "sanitize.discard", artifact_id=artifact_id))
    rs = call(reg, req(6, "verify.run", artifact_id=artifact_id))
    assert error_of(rs, 6)["data"]["kind"] == "copy_not_found"
