from __future__ import annotations

import io
import json

from airlock_engine.safelog import SafeLogger


def _lines(buf: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(x) for x in buf.getvalue().splitlines()]


def test_allowed_fields_are_written() -> None:
    buf = io.StringIO()
    SafeLogger(buf).info("scan_completed", file_type="pdf", entity_count=27, duration_ms=2400.5)
    (rec,) = _lines(buf)
    assert rec["event"] == "scan_completed"
    assert rec["file_type"] == "pdf"
    assert rec["entity_count"] == 27
    assert "dropped_fields" not in rec


def test_sensitive_values_are_structurally_rejected() -> None:
    buf = io.StringIO()
    logger = SafeLogger(buf)
    logger.info(
        "scan_completed",
        file_type="Rahul Sharma",  # spaces/uppercase: not a token
        entity_type="rahul@company.com",  # '@' not allowed
        detector="ABCDE1234F",  # uppercase not allowed
        method="/home/user/secret.pdf",  # '/' not allowed
        content="any text at all",  # not an allowlisted field
        entity_count=True,  # bool is not an int here
    )
    text = buf.getvalue()
    for leaked in ("Rahul", "rahul@company.com", "ABCDE1234F", "secret.pdf", "any text"):
        assert leaked not in text
    (rec,) = _lines(buf)
    assert rec["dropped_fields"] == 6
    assert logger.dropped_fields == 6


def test_event_name_must_be_token() -> None:
    buf = io.StringIO()
    SafeLogger(buf).info("user typed: password123!")
    (rec,) = _lines(buf)
    assert rec["event"] == "invalid_event"
    assert "password123" not in buf.getvalue()


def test_level_filtering() -> None:
    buf = io.StringIO()
    logger = SafeLogger(buf, level="warning")
    logger.info("scan_started")
    logger.warning("scan_failed")
    assert [r["event"] for r in _lines(buf)] == ["scan_failed"]
