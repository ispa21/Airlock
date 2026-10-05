from __future__ import annotations

import json
import logging
import pickle

import pytest

from airlock_engine.core.models import DetectionResult, Severity
from airlock_engine.core.sensitive import SensitiveValue, mask_preview

SECRET = "rahul.sharma@example.invalid"


def test_value_never_leaks_through_string_conversion() -> None:
    v = SensitiveValue(SECRET)
    percent = "%s" % v  # noqa: UP031 - %-formatting must be covered too
    for rendered in (str(v), repr(v), f"{v}", f"{v!r}", percent, format(v, ">40")):
        assert SECRET not in rendered
    assert v.reveal() == SECRET


def test_value_cannot_be_serialised() -> None:
    v = SensitiveValue(SECRET)
    with pytest.raises(TypeError):
        json.dumps({"v": v})
    with pytest.raises(TypeError):
        pickle.dumps(v)


def test_detection_result_repr_hides_value(caplog: pytest.LogCaptureFixture) -> None:
    result = DetectionResult(
        entity_type="EMAIL",
        matched_value=SensitiveValue(SECRET),
        segment_id=0,
        start=0,
        end=len(SECRET),
        confidence=1.0,
        detector="regex.email",
        rule_id="email_v1",
        severity=Severity.MEDIUM,
    )
    with caplog.at_level(logging.INFO):
        logging.getLogger("t").info("found %s / %r", result, result)
    assert SECRET not in caplog.text
    assert SECRET not in repr(result)


def test_detection_result_validates_span_and_confidence() -> None:
    kwargs = dict(
        entity_type="EMAIL",
        matched_value=SensitiveValue("x"),
        segment_id=0,
        confidence=1.0,
        detector="d",
        rule_id="r",
        severity=Severity.LOW,
    )
    with pytest.raises(ValueError):
        DetectionResult(start=3, end=3, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        DetectionResult(start=0, end=1, **{**kwargs, "confidence": 1.5})  # type: ignore[arg-type]


def test_equality_and_fingerprint() -> None:
    a, b = SensitiveValue(SECRET), SensitiveValue(SECRET)
    assert a == b and hash(a) == hash(b)
    assert a.fingerprint(b"k1") == b.fingerprint(b"k1")
    assert a.fingerprint(b"k1") != a.fingerprint(b"k2")
    assert SECRET not in a.fingerprint(b"k1")


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("rahul@company.com", "r••••@company.com"),
        ("ABCDE1234F", "AB••••••4F"),
        ("1234", "••••"),
        ("secret", "s••••t"),
    ],
)
def test_preview(raw: str, expected: str) -> None:
    assert mask_preview(raw) == expected
    assert SensitiveValue(raw).preview() == expected
