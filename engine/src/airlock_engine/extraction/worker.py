"""Entry point of the disposable extraction worker process.

Each document is parsed in a fresh interpreter started with the ``spawn``
method. If a parser crashes, hangs or balloons in memory on a hostile file,
only this process dies; the engine reports an actionable error and carries on.
The worker installs the network guard before touching any input.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any

#: Test-only operations (crash, hang, allocate) are enabled by this variable.
TEST_OPS_ENV = "AIRLOCK_ENGINE_TEST_WORKER_OPS"


def _send(conn: Connection, message: dict[str, Any]) -> None:
    conn.send_bytes(json.dumps(message, ensure_ascii=False).encode("utf-8"))


def _apply_posix_memory_limit(limit_mb: int) -> None:
    if sys.platform.startswith("linux") and limit_mb > 0:
        import resource

        limit = limit_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))


def worker_entry(conn: Connection, job: dict[str, Any]) -> None:
    from airlock_engine.security import network_guard

    network_guard.install()

    from airlock_engine import safelog

    safelog.configure(str(job.get("log_level", "info")))
    _apply_posix_memory_limit(int(job.get("memory_limit_mb", 0)))

    from airlock_engine.core import errors

    try:
        _send(conn, {"type": "result", "document": _run(conn, job)})
    except errors.AirlockError as exc:
        _send(conn, {"type": "error", "error": exc.to_data()})
    except MemoryError:
        _send(conn, {"type": "error", "error": errors.resource_limit().to_data()})
    except Exception as exc:
        safelog.log.error("extraction_exception", exception_type=type(exc).__name__)
        label = str(job.get("format_label", "file"))
        _send(conn, {"type": "error", "error": errors.extraction_failed(label).to_data()})
    finally:
        conn.close()


def _run(conn: Connection, job: dict[str, Any]) -> Any:
    op = job.get("op")
    if op == "extract":
        return _extract(conn, job)
    if os.environ.get(TEST_OPS_ENV) == "1":
        return _test_op(op, job)
    raise ValueError("unknown worker operation")


def _extract(conn: Connection, job: dict[str, Any]) -> dict[str, Any]:
    from airlock_engine.core import errors
    from airlock_engine.documents import formats
    from airlock_engine.extraction.context import ExtractionOptions
    from airlock_engine.extraction.pipeline import extract_bytes
    from airlock_engine.extraction.wire import document_to_wire

    path = Path(job["path"])
    data = path.read_bytes()  # read-only; the original is never written
    if len(data) != job["size_bytes"]:
        # The file changed after validation: re-validate rather than trust it.
        raise errors.AirlockError(
            kind="file_changed",
            message="This file changed while Airlock was reading it.",
            next_step="Wait until the file is saved and closed, then scan it again.",
        )
    spec = formats.spec_for_extension(job["extension"])
    if spec is None or spec.format_id != job["format"]:
        raise errors.unsupported_format(job["extension"])
    formats.sniff_stream(io.BytesIO(data), spec, job["extension"])

    def progress(stage: str, done: int, total: int) -> None:
        _send(conn, {"type": "progress", "stage": stage, "done": done, "total": total})

    document = extract_bytes(
        data,
        spec.format_id,
        ExtractionOptions.from_wire(job.get("options", {})),
        progress=progress,
    )
    return document_to_wire(document)


def _test_op(op: object, job: dict[str, Any]) -> Any:
    if op == "test.sleep":
        time.sleep(float(job["seconds"]))
        return "slept"
    if op == "test.exit":
        os._exit(int(job.get("code", 3)))
    if op == "test.segfault":
        import ctypes

        ctypes.string_at(0)
    if op == "test.alloc":
        block = bytearray(int(job["megabytes"]) * 1024 * 1024)
        return len(block)
    if op == "test.network":
        import socket

        try:
            socket.create_connection(("1.1.1.1", 443), timeout=2)
        except PermissionError:
            return "blocked"
        return "connected"
    raise ValueError("unknown test operation")
