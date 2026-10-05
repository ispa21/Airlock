"""The worker process boundary: crashes, hangs, memory, network, cancellation."""

from __future__ import annotations

import time

import pytest

from airlock_engine.core.errors import AirlockError
from airlock_engine.extraction.isolation import JobCancelled, run_job
from airlock_engine.extraction.worker import TEST_OPS_ENV

pytestmark = pytest.mark.subprocess


@pytest.fixture(autouse=True)
def _test_ops(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(TEST_OPS_ENV, "1")


def _kind(job: dict, **kw) -> str:  # type: ignore[type-arg, no-untyped-def]
    with pytest.raises(AirlockError) as info:
        run_job(job, **kw)
    return info.value.kind


def test_result_is_returned() -> None:
    assert run_job({"op": "test.sleep", "seconds": 0.05}) == "slept"


def test_hang_times_out_and_worker_is_killed() -> None:
    started = time.monotonic()
    assert _kind({"op": "test.sleep", "seconds": 30}, timeout_s=1.0) == "extraction_timeout"
    assert time.monotonic() - started < 8


@pytest.mark.parametrize("op", ["test.exit", "test.segfault"])
def test_crash_becomes_actionable_error(op: str) -> None:
    assert _kind({"op": op}) == "extraction_crashed"


def test_memory_blowup_is_contained() -> None:
    assert _kind({"op": "test.alloc", "megabytes": 2048}, memory_limit_mb=768) == "resource_limit"


def test_network_is_blocked_inside_worker() -> None:
    assert run_job({"op": "test.network"}) == "blocked"


def test_cancellation_kills_the_worker() -> None:
    started = time.monotonic()
    with pytest.raises(JobCancelled):
        run_job(
            {"op": "test.sleep", "seconds": 30},
            is_cancelled=lambda: time.monotonic() - started > 0.5,
        )
    assert time.monotonic() - started < 5


def test_unknown_operation_without_test_flag(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(TEST_OPS_ENV)
    assert _kind({"op": "test.sleep", "seconds": 0}) == "extraction_failed"
