"""Protected copies end to end, and the leak tests of docs/TESTING.md.

A canary is planted in every hidden location of each format, detected by a
company rule, and protected. Afterwards the canaries must not appear in the
copy (decompressed, and re-extracted with OCR), the log, the IPC responses,
the database or the work folder, and the original must be unchanged.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

import pytest

import builders
from airlock_engine import safelog
from airlock_engine.api import build_registry
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.pipeline import extract_bytes
from airlock_engine.ipc.server import MethodRegistry
from test_api_scan import call, req, result_of

pytestmark = pytest.mark.subprocess

CANARY_RULE = r"CANARY[_ A-Z0-9]*[A-Z0-9]"
_CANARY = re.compile(rb"canary", re.IGNORECASE)


def error_of(rs: list[dict[str, Any]], i: int) -> dict[str, Any]:
    (r,) = [r for r in rs if r.get("id") == i]
    assert "error" in r, r
    return r["error"]  # type: ignore[no-any-return]


@pytest.fixture
def log(monkeypatch: pytest.MonkeyPatch) -> io.StringIO:
    stream = io.StringIO()
    monkeypatch.setattr(safelog, "log", safelog.SafeLogger(stream, level="debug"))
    return stream


@pytest.fixture
def registry(tmp_path: Path) -> MethodRegistry:
    registry = build_registry(tmp_path / "data")
    result_of(
        call(
            registry,
            req(
                1,
                "rules.create",
                kind="regex",
                pattern=CANARY_RULE,
                category_id="CONFIDENTIAL_TERM",
            ),
        ),
        1,
    )
    return registry


def protect(
    registry: MethodRegistry, path: Path, *, ocr: bool
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]]]:
    responses: list[dict[str, Any]] = []
    rs = call(registry, req(2, "scan.start", path=str(path), ocr=ocr, ner=False))
    responses += rs
    scan = result_of(rs, 2)
    blocked = [f["id"] for f in scan["findings"] if f["effective_action"] == "BLOCK"]
    if blocked:
        rs = call(
            registry,
            req(
                3,
                "scan.override",
                scan_id=scan["scan_id"],
                overrides=[{"finding_id": i, "action": "REDACT"} for i in blocked],
            ),
        )
        responses += rs
    rs = call(registry, req(4, "sanitize.run", scan_id=scan["scan_id"]))
    responses += rs
    return scan, result_of(rs, 4), responses


def copy_path(data_dir: Path, artifact_id: str) -> Path:
    (path,) = (data_dir / "work").glob(f"{artifact_id}.*")
    return path


def all_bytes(data: bytes) -> bytes:
    """The file, plus every ZIP part decompressed (recursively for embeddings)."""
    out = data
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                out += all_bytes(z.read(name))
    return out


CASES = [
    ("contract.docx", lambda: builders.build_docx(with_ocr_image=True), True),
    ("payroll.xlsx", builders.build_xlsx, False),
    ("board.pptx", builders.build_pptx, False),
    ("report.pdf", lambda: builders.build_pdf(scanned_page=True), True),
    ("scan.png", lambda: builders.png_bytes(builders.text_image("CANARY PNG TEXT")), True),
    ("clients.csv", lambda: b'name,note\n"CANARY_CSV, quoted",ok\nx,CANARY_CSV_2\n', False),
    ("prod.env", lambda: b"API_TOKEN=CANARY_ENV_TOKEN\nHOST=10.1.2.3\n", False),
]


@pytest.mark.parametrize(("name", "build", "ocr"), CASES, ids=[c[0] for c in CASES])
def test_no_canary_survives_anywhere(
    name: str,
    build: Any,
    ocr: bool,
    registry: MethodRegistry,
    tmp_path: Path,
    log: io.StringIO,
    ocr_provider: Any,
) -> None:
    source = tmp_path / name
    source.write_bytes(build())
    before = hashlib.sha256(source.read_bytes()).hexdigest()

    scan, result, responses = protect(registry, source, ocr=ocr)
    assert scan["summary"]["total"] > 0
    copy = copy_path(tmp_path / "data", result["artifact_id"])
    data = copy.read_bytes()

    # 1. Not in the output bytes, including every decompressed ZIP part.
    assert not _CANARY.search(all_bytes(data)), name
    # 2. Not in what Airlock (or an AI) would read back, OCR included.
    fmt = scan["extraction"]["format"]
    doc = extract_bytes(data, fmt, ExtractionOptions(ocr=ocr), ocr_factory=lambda: ocr_provider)
    readable = "\n".join(s.text for s in doc.segments)
    assert not re.search("canary", readable, re.IGNORECASE), name
    # 3. Not in the log, any IPC response, or the database.
    assert "canary" not in log.getvalue().lower()
    assert "canary" not in json.dumps([r.get("result") for r in responses]).lower()
    db = b"".join(p.read_bytes() for p in (tmp_path / "data").glob("airlock.db*"))
    # The company rule's own text is stored on purpose; no document value may be.
    assert not _CANARY.search(db.replace(CANARY_RULE.encode(), b""))
    # 4. The original is untouched; the copy is user-only.
    assert hashlib.sha256(source.read_bytes()).hexdigest() == before
    if hasattr(copy.stat(), "st_mode") and __import__("os").name == "posix":
        assert copy.stat().st_mode & 0o077 == 0
    # 5. Discarding the scan removes the copy from the work folder.
    call(registry, req(9, "scan.discard", scan_id=scan["scan_id"]))
    assert not list((tmp_path / "data" / "work").iterdir())


def test_copy_opens_and_keeps_its_structure(registry: MethodRegistry, tmp_path: Path) -> None:
    import docx

    source = tmp_path / "contract.docx"
    source.write_bytes(builders.build_docx())
    _, result, _ = protect(registry, source, ocr=False)
    assert result["file_name"] == "contract (Airlock protected).docx"
    assert result["replaced"]["MASK"] > 10
    assert {r["label"] for r in result["removed"]} >= {"Macros (VBA project)", "Document thumbnail"}
    assert result["vault"]["stored"] and result["vault"]["entries"] > 10
    assert result["verified"] is False
    copy = docx.Document(str(copy_path(tmp_path / "data", result["artifact_id"])))
    assert copy.paragraphs[0].text.startswith("Customer Rahul Sharma [CONFIDENTIAL_TERM_")


def test_restore_puts_originals_back_only_for_known_placeholders(
    registry: MethodRegistry, tmp_path: Path, log: io.StringIO
) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("Owner CANARY_OWNER, mail owner@example.invalid\n", encoding="utf-8")
    _, result, _ = protect(registry, source, ocr=False)
    copy = copy_path(tmp_path / "data", result["artifact_id"]).read_text(encoding="utf-8")
    placeholders = re.findall(r"\[[A-Z_]+_\d+\]", copy)
    assert len(placeholders) == 2
    ai_reply = f"{placeholders[0]} should email {placeholders[1]}. Ask [PERSON_77]."
    rs = call(registry, req(5, "vault.restore", artifact_id=result["artifact_id"], text=ai_reply))
    restored = result_of(rs, 5)
    assert restored == {
        "text": "CANARY_OWNER should email owner@example.invalid. Ask [PERSON_77].",
        "restored": 2,
    }
    assert "canary" not in log.getvalue().lower()
    rs = call(
        registry, req(6, "vault.forget", artifact_id=result["artifact_id"]), req(7, "vault.status")
    )
    assert result_of(rs, 6) == {"ok": True, "deleted": True}
    assert result_of(rs, 7)["protection"] in ("file", "dpapi")
    rs = call(registry, req(8, "vault.restore", artifact_id=result["artifact_id"], text="x"))
    assert error_of(rs, 8)["data"]["kind"] == "vault_record_not_found"


def test_blocked_findings_stop_the_copy(registry: MethodRegistry, tmp_path: Path) -> None:
    source = tmp_path / "prod.env"
    source.write_text("DB_PASSWORD=Xk9#mQ2!vL7p\n", encoding="utf-8")
    scan = result_of(call(registry, req(1, "scan.start", path=str(source), ner=False)), 1)
    rs = call(registry, req(2, "sanitize.run", scan_id=scan["scan_id"]))
    error = error_of(rs, 2)["data"]
    assert (
        error["kind"] == "blocked_findings" and "1 item is still set to Block" in error["message"]
    )
    assert not list((tmp_path / "data" / "work").iterdir())


def test_file_changed_after_scan_is_refused(registry: MethodRegistry, tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("mail owner@example.invalid\n", encoding="utf-8")
    scan = result_of(call(registry, req(1, "scan.start", path=str(source), ner=False)), 1)
    source.write_text("mail owner@example.invalid and more\n", encoding="utf-8")
    rs = call(registry, req(2, "sanitize.run", scan_id=scan["scan_id"]))
    assert error_of(rs, 2)["data"]["kind"] == "file_changed"
    assert not list((tmp_path / "data" / "work").iterdir())


def test_discard_and_unknown_ids(registry: MethodRegistry, tmp_path: Path) -> None:
    source = tmp_path / "notes.txt"
    source.write_text("mail owner@example.invalid\n", encoding="utf-8")
    _, result, _ = protect(registry, source, ocr=False)
    rs = call(
        registry,
        req(5, "sanitize.discard", artifact_id=result["artifact_id"]),
        req(6, "sanitize.run", scan_id="scan_missing"),
    )
    assert result_of(rs, 5) == {"ok": True, "discarded": True}
    assert error_of(rs, 6)["data"]["kind"] == "scan_not_found"
    assert not list((tmp_path / "data" / "work").iterdir())


def test_leftovers_are_swept_at_start_up(tmp_path: Path) -> None:
    work = tmp_path / "data" / "work"
    work.mkdir(parents=True)
    (work / "art_0000000000000000.docx").write_bytes(b"left behind by a crash")
    build_registry(tmp_path / "data")
    assert not list(work.iterdir())
