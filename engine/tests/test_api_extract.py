"""document.extract end to end: validation, isolated worker, summary, logs."""

from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
from typing import Any

import pytest

import builders
from airlock_engine.api import build_registry
from airlock_engine.ipc import protocol
from airlock_engine.ipc.server import StdioServer
from conftest import frames, responses

pytestmark = pytest.mark.subprocess


def call(*messages: dict[str, Any]) -> list[dict[str, Any]]:
    out = io.BytesIO()
    StdioServer(build_registry(), frames(*messages), out).serve_forever()
    return responses(out)


def req(i: int, method: str, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


def fingerprint(path: Path) -> tuple[str, int]:
    return hashlib.sha256(path.read_bytes()).hexdigest(), path.stat().st_mtime_ns


@pytest.fixture
def documents(tmp_path: Path) -> dict[str, Path]:
    files = {
        "contract.docx": builders.build_docx(),
        "payroll.xlsx": builders.build_xlsx(),
        "board.pptx": builders.build_pptx(),
        "report.pdf": builders.build_pdf(),
        "clients.csv": b"name,pan\nCANARY_CSV_NAME,ABCDE1234F\n",
        "settings.env": b"API_TOKEN=CANARY_ENV_TOKEN\n",
        "locked.pdf": builders.build_encrypted_pdf(),
    }
    paths = {}
    for name, data in files.items():
        path = tmp_path / name
        path.write_bytes(data)
        paths[name] = path
    return paths


def test_extract_every_format_and_leave_originals_untouched(
    documents: dict[str, Path], capfd: pytest.CaptureFixture[str]
) -> None:
    names = [n for n in documents if n != "locked.pdf"]
    before = {n: fingerprint(documents[n]) for n in names}
    results = {
        r["id"]: r
        for r in call(
            *(
                req(i, "document.extract", path=str(documents[n]), ocr=False)
                for i, n in enumerate(names)
            )
        )
        if "id" in r
    }
    for i, name in enumerate(names):
        assert "result" in results[i], (name, results[i])
        summary = results[i]["result"]
        assert summary["segment_count"] > 0
        assert summary["word_count"] > 0
        assert {p["kind"] for p in summary["parts"]} >= {"body"} or name.endswith(".env")
        # The summary is content-free: no extracted text crosses IPC.
        assert "CANARY" not in repr(summary), name
    for name in names:
        assert fingerprint(documents[name]) == before[name], f"{name} was modified"

    docx = results[names.index("contract.docx")]["result"]
    kinds = {p["kind"] for p in docx["parts"]}
    assert {"body", "comment", "tracked_change", "header_footer", "metadata", "alt_text"} <= kinds
    assert docx["unextracted"][0]["kind"] in ("image", "macro")

    # Neither the engine nor the worker logged any content or file names.
    err = capfd.readouterr().err
    assert "CANARY" not in err
    assert "contract" not in err and str(documents["clients.csv"].parent) not in err
    assert '"event":"extraction_completed"' in err


def test_progress_notifications_are_emitted(documents: dict[str, Path]) -> None:
    messages = call(req(1, "document.extract", path=str(documents["report.pdf"]), ocr=False))
    progress = [m for m in messages if m.get("method") == "$/progress"]
    assert progress and all(m["params"]["request_id"] == 1 for m in progress)
    assert {m["params"]["stage"] for m in progress} == {"pages"}
    assert progress[-1]["params"]["done"] == progress[-1]["params"]["total"] == 2


def test_errors_are_actionable(documents: dict[str, Path], tmp_path: Path) -> None:
    corrupt = tmp_path / "broken.docx"
    corrupt.write_bytes(documents["contract.docx"].read_bytes()[:3000])
    results = {
        r["id"]: r
        for r in call(
            req(1, "document.extract", path=str(documents["locked.pdf"])),
            req(2, "document.extract", path=str(corrupt)),
        )
        if "id" in r
    }
    locked = results[1]["error"]
    assert locked["code"] == protocol.AIRLOCK_ERROR
    assert locked["data"]["kind"] == "encrypted_document"
    broken = results[2]["error"]["data"]
    assert broken["kind"] in ("format_mismatch", "extraction_failed")
    assert broken["original_affected"] is False and broken["next_step"]


def test_file_changed_after_validation_is_detected(
    documents: dict[str, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from airlock_engine.security import input_files

    real = input_files.validate_input_file

    def validate_then_modify(raw: object, **kw: Any) -> input_files.ValidatedFile:
        validated = real(raw, **kw)
        with open(validated.path, "ab") as handle:
            handle.write(b"tampered")
        return validated

    monkeypatch.setattr("airlock_engine.api.documents.validate_input_file", validate_then_modify)
    (result,) = [
        r for r in call(req(1, "document.extract", path=str(documents["clients.csv"]))) if "id" in r
    ]
    assert result["error"]["data"]["kind"] == "file_changed"
    assert os.path.getsize(documents["clients.csv"]) > 0
