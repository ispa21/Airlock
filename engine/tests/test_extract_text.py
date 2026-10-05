from __future__ import annotations

import pytest

from airlock_engine.core.errors import AirlockError
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.pipeline import extract_bytes


def extract(data: bytes, fmt: str, **options):  # type: ignore[no-untyped-def]
    return extract_bytes(data, fmt, ExtractionOptions(**options), ocr_factory=None)


@pytest.mark.parametrize(
    ("encoding", "expected"),
    [("utf-8", "utf-8"), ("utf-8-sig", "utf-8-sig"), ("utf-16", "utf-16"), ("cp1252", "cp1252")],
)
def test_encodings(encoding: str, expected: str) -> None:
    text = "Café ₹12,47,382 — naïve" if encoding != "cp1252" else "Café — naïve €5"
    doc = extract(text.encode(encoding), "txt")
    assert doc.segments[0].text == text
    assert doc.adapter_state["encoding"] == expected


def test_unknown_bytes_fall_back_to_latin1() -> None:
    doc = extract(b"abc \x81\x8d def", "txt")
    assert doc.adapter_state["encoding"] == "latin-1"


def test_small_file_is_one_segment_with_line_label() -> None:
    doc = extract(b"DB_PASSWORD=hunter2\nAPI_KEY=abc\n", "env")
    (segment,) = doc.segments
    assert segment.label == "Lines 1–2"
    assert segment.locator.path == "char/0"
    assert doc.counts["lines"] == 2


def test_large_file_is_chunked_on_line_boundaries_and_reassembles() -> None:
    line = "x" * 99 + "\n"
    text = line * 15_000  # 1.5 MB
    doc = extract(text.encode(), "txt")
    assert len(doc.segments) > 1
    assert "".join(s.text for s in doc.segments) == text
    assert all(s.text.endswith("\n") for s in doc.segments)
    starts = [int(s.locator.path.split("/")[1]) for s in doc.segments]
    assert starts == sorted(starts) and starts[0] == 0


def test_pem_block_is_never_split_across_chunks() -> None:
    filler = ("y" * 99 + "\n") * 2_560  # chunk boundary falls inside the key
    key = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        + ("A" * 64 + "\n") * 40
        + "-----END RSA PRIVATE KEY-----\n"
    )
    text = ("z" * 99 + "\n") * 8_000 + filler[: 256_000 - 50] + "\n" + key + filler
    doc = extract(text.encode(), "txt")
    holders = [s for s in doc.segments if "BEGIN RSA PRIVATE KEY" in s.text]
    assert len(holders) == 1 and "END RSA PRIVATE KEY" in holders[0].text


def test_csv_cells_header_context_and_labels() -> None:
    doc = extract(b"Name;PAN;Phone\nRahul;ABCDE1234F;9876543210\n", "csv")
    assert doc.adapter_state["delimiter"] == ";"
    pan = next(s for s in doc.segments if s.text == "ABCDE1234F")
    assert (pan.label, pan.context, pan.locator.path) == ("Row 2 · Column B", "PAN", "r2c2")


def test_csv_quoted_multiline_cell() -> None:
    doc = extract(b'name,address\nRahul,"12 MG Road\nPune 411001"\n', "csv")
    assert any(s.text == "12 MG Road\nPune 411001" and s.context == "address" for s in doc.segments)


def test_tsv_and_numeric_first_row_has_no_header() -> None:
    doc = extract(b"1\t2\n3\t4\n", "tsv")
    assert all(s.context == "" for s in doc.segments)


def test_cell_limit_is_enforced_not_truncated() -> None:
    rows = "\n".join(",".join(["x"] * 10) for _ in range(200)).encode()
    with pytest.raises(AirlockError) as info:
        extract(rows, "csv", max_segments=1_000)
    assert info.value.kind == "content_too_large"


def test_character_limit_is_enforced() -> None:
    with pytest.raises(AirlockError) as info:
        extract(b"a" * 5_000, "txt", max_chars=1_000)
    assert info.value.kind == "content_too_large"
