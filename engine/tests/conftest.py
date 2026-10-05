from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path
from typing import Any

import pytest


def frames(*messages: dict[str, Any] | bytes) -> io.BytesIO:
    out = bytearray()
    for m in messages:
        out += m if isinstance(m, bytes) else json.dumps(m).encode() + b"\n"
    return io.BytesIO(bytes(out))


def responses(buffer: io.BytesIO) -> list[dict[str, Any]]:
    return [json.loads(line) for line in buffer.getvalue().splitlines() if line]


def make_ooxml(path: Path, main_part: str) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr(main_part, "<root/>")
    return path


@pytest.fixture
def sample_files(tmp_path: Path) -> dict[str, Path]:
    files = {
        "pdf": tmp_path / "report.pdf",
        "csv": tmp_path / "customers.csv",
        "txt": tmp_path / "notes.txt",
        "png": tmp_path / "scan.png",
        "env": tmp_path / ".env",
    }
    files["pdf"].write_bytes(b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n")
    files["csv"].write_text("name,email\nTest User,test.user@example.invalid\n", encoding="utf-8")
    files["txt"].write_text("Synthetic note. No real data.\n", encoding="utf-8")
    files["png"].write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    files["env"].write_text("API_TOKEN=synthetic-not-real\n", encoding="utf-8")
    files["docx"] = make_ooxml(tmp_path / "contract.docx", "word/document.xml")
    files["xlsx"] = make_ooxml(tmp_path / "payroll.xlsx", "xl/workbook.xml")
    files["pptx"] = make_ooxml(tmp_path / "board.pptx", "ppt/presentation.xml")
    return files


# ---------------------------------------------------------------- Phase 2
import re as _re  # noqa: E402

from airlock_engine.core.models import ExtractedDocument, SegmentKind  # noqa: E402

CANARY = _re.compile(r"CANARY[_ A-Z0-9]*[A-Z0-9]")


@pytest.fixture(scope="session")
def ocr_provider():  # type: ignore[no-untyped-def]
    """One OCR model per test session (loading it takes about a second)."""
    from airlock_engine.extraction.ocr import RapidOcrProvider

    return RapidOcrProvider()


def canaries(doc: ExtractedDocument, kind: SegmentKind | None = None) -> set[str]:
    return {
        match
        for segment in doc.segments
        if kind is None or segment.kind is kind
        for match in CANARY.findall(segment.text)
    }


def kinds_of(doc: ExtractedDocument, needle: str) -> set[SegmentKind]:
    return {s.kind for s in doc.segments if needle in s.text}
