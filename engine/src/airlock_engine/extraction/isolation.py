"""Runs a worker job in a separate process with a timeout, memory cap and cancellation."""

from __future__ import annotations

import json
import multiprocessing
import time
from collections.abc import Callable
from typing import Any, Final

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.extraction import winjob
from airlock_engine.extraction.worker import worker_entry

DEFAULT_TIMEOUT_S: Final = 900.0
DEFAULT_MEMORY_LIMIT_MB: Final = 3072
_MAX_MESSAGE_BYTES: Final = 768 * 1024 * 1024
_POLL_S: Final = 0.1


class JobCancelled(Exception):
    pass


ProgressCallback = Callable[[str, int, int], None]


def run_job(
    job: dict[str, Any],
    *,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    memory_limit_mb: int = DEFAULT_MEMORY_LIMIT_MB,
    on_progress: ProgressCallback | None = None,
    is_cancelled: Callable[[], bool] = lambda: False,
) -> Any:
    """Run ``job`` in a fresh worker and return its result.

    Raises :class:`AirlockError` for worker-reported errors, crashes, timeouts
    and memory exhaustion, or :class:`JobCancelled`.
    """
    ctx = multiprocessing.get_context("spawn")
    reader, writer = ctx.Pipe(duplex=False)
    job = {**job, "memory_limit_mb": memory_limit_mb}
    process = ctx.Process(target=worker_entry, args=(writer, job), daemon=True)
    started = time.monotonic()
    process.start()
    writer.close()  # only the child writes
    job_handle = winjob.limit_process(process.pid or 0, memory_limit_mb)
    deadline = started + timeout_s
    try:
        while True:
            if is_cancelled():
                raise JobCancelled
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                safelog.log.warning("worker_timeout")
                raise errors.extraction_timeout()
            if reader.poll(min(_POLL_S, remaining)):
                try:
                    message = json.loads(reader.recv_bytes(_MAX_MESSAGE_BYTES))
                except (EOFError, OSError, ValueError):
                    raise _crash_error(process) from None
                kind = message.get("type") if isinstance(message, dict) else None
                if kind == "progress":
                    if on_progress is not None:
                        on_progress(
                            str(message.get("stage", "")),
                            int(message.get("done", 0)),
                            int(message.get("total", 0)),
                        )
                elif kind == "result":
                    return message.get("document")
                elif kind == "error":
                    raise _error_from(message.get("error"))
                else:
                    raise errors.extraction_crashed()
            elif not process.is_alive():
                if reader.poll(0):
                    continue  # drain the final message
                raise _crash_error(process)
    finally:
        if process.is_alive():
            process.kill()
        process.join(timeout=5)
        reader.close()
        if job_handle is not None:
            winjob.close(job_handle)


def _crash_error(process: multiprocessing.process.BaseProcess) -> errors.AirlockError:
    process.join(timeout=2)
    safelog.log.warning(
        "worker_crashed", status=f"exit{process.exitcode}".replace("-", "sig").lower()
    )
    return errors.extraction_crashed()


def _error_from(data: object) -> errors.AirlockError:
    if isinstance(data, dict) and all(isinstance(data.get(k), str) for k in ("kind", "message")):
        return errors.AirlockError(
            kind=str(data["kind"]),
            message=str(data["message"]),
            next_step=str(data.get("next_step") or ""),
            original_affected=False,
        )
    return errors.extraction_crashed()
