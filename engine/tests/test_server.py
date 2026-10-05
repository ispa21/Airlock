from __future__ import annotations

import io
import os
import threading
import time
from pathlib import Path
from typing import Any

from airlock_engine.api import build_registry
from airlock_engine.core.errors import AirlockError
from airlock_engine.ipc import protocol
from airlock_engine.ipc.server import MethodRegistry, RequestContext, StdioServer
from conftest import frames, responses


def serve(
    registry: MethodRegistry, *messages: dict[str, Any] | bytes, **kw: Any
) -> list[dict[str, Any]]:
    out = io.BytesIO()
    StdioServer(registry, frames(*messages), out, **kw).serve_forever()
    return responses(out)


def by_id(items: list[dict[str, Any]]) -> dict[Any, dict[str, Any]]:
    return {r["id"]: r for r in items if "id" in r}


def req(i: int | str, method: str, **params: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": i, "method": method, "params": params}


def test_hello_handshake() -> None:
    res = by_id(serve(build_registry(), req(1, "system.hello", protocol_version="1.0")))
    result = res[1]["result"]
    assert result["protocol_version"] == protocol.PROTOCOL_VERSION
    assert result["compatible"] is True
    assert "document.inspect" in result["methods"]


def test_hello_reports_incompatible_major() -> None:
    res = by_id(serve(build_registry(), req(1, "system.hello", protocol_version="2.0")))
    assert res[1]["result"]["compatible"] is False


def test_inspect_success_and_structured_error(
    sample_files: dict[str, Path], tmp_path: Path
) -> None:
    res = by_id(
        serve(
            build_registry(),
            req(1, "document.inspect", path=str(sample_files["docx"])),
            req(2, "document.inspect", path=str(tmp_path / "missing.pdf")),
            req(3, "document.inspect"),
        )
    )
    assert res[1]["result"]["format"] == "docx"
    assert res[1]["result"]["family"] == "document"
    err = res[2]["error"]
    assert err["code"] == protocol.AIRLOCK_ERROR
    assert err["data"]["kind"] == "file_not_found"
    assert err["data"]["original_affected"] is False
    assert res[3]["error"]["code"] == protocol.INVALID_PARAMS


def test_unknown_method_and_garbage_do_not_stop_server() -> None:
    res = serve(
        build_registry(),
        b"{oops\n",
        req(1, "nope"),
        b"\n",
        req(2, "system.health"),
    )
    assert res[0]["error"]["code"] == protocol.PARSE_ERROR
    ids = by_id(res)
    assert ids[1]["error"]["code"] == protocol.METHOD_NOT_FOUND
    assert ids[2]["result"]["status"] == "ok"


def test_oversized_frame_is_rejected_and_stream_recovers() -> None:
    huge = (
        b'{"jsonrpc":"2.0","id":1,"method":"system.health","params":{"x":"' + b"a" * 5000 + b'"}}\n'
    )
    res = serve(build_registry(), huge, req(2, "system.health"), max_message_bytes=1024)
    assert res[0]["error"]["code"] == protocol.MESSAGE_TOO_LARGE
    assert by_id(res)[2]["result"]["status"] == "ok"


def test_handler_exception_becomes_internal_error_without_details() -> None:
    reg = MethodRegistry()

    def boom(params: dict[str, Any], ctx: RequestContext) -> None:
        raise RuntimeError("Rahul Sharma ABCDE1234F")

    reg.register("test.boom", boom)
    res = by_id(serve(reg, req(1, "test.boom")))
    err = res[1]["error"]
    assert err["code"] == protocol.INTERNAL_ERROR
    assert "Rahul" not in str(err) and "ABCDE1234F" not in str(err)
    assert err["data"]["kind"] == "internal_error"


def test_airlock_error_passes_structured_data() -> None:
    reg = MethodRegistry()

    def fail(params: dict[str, Any], ctx: RequestContext) -> None:
        raise AirlockError("x_kind", "What happened.", "What to do.")

    reg.register("test.fail", fail)
    err = by_id(serve(reg, req(1, "test.fail")))[1]["error"]
    assert err["data"] == {
        "kind": "x_kind",
        "message": "What happened.",
        "next_step": "What to do.",
        "original_affected": False,
    }


def test_shutdown_stops_reading() -> None:
    res = serve(build_registry(), req(1, "system.shutdown"), req(2, "system.health"))
    ids = by_id(res)
    assert ids[1]["result"] == {"ok": True}
    assert 2 not in ids


def test_cancel_and_progress_over_real_pipes() -> None:
    """Long request is cancelled while the server keeps serving others."""
    reg = MethodRegistry()
    started = threading.Event()

    def slow(params: dict[str, Any], ctx: RequestContext) -> str:
        ctx.progress("extract", 0, 1)
        started.set()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            ctx.raise_if_cancelled()
            time.sleep(0.01)
        return "finished"

    reg.register("test.slow", slow)
    reg.register("test.ping", lambda p, c: "pong")

    r_in, w_in = os.pipe()
    r_out, w_out = os.pipe()
    host_in = os.fdopen(w_in, "wb")
    host_out = os.fdopen(r_out, "rb")
    server = StdioServer(reg, os.fdopen(r_in, "rb"), os.fdopen(w_out, "wb"))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    import json

    def send(obj: dict[str, Any]) -> None:
        host_in.write(json.dumps(obj).encode() + b"\n")
        host_in.flush()

    def recv() -> dict[str, Any]:
        return json.loads(host_out.readline())

    send(req(1, "test.slow"))
    progress = recv()
    assert progress["method"] == "$/progress"
    assert progress["params"]["request_id"] == 1
    assert started.wait(5)
    send(req(2, "test.ping"))
    assert recv() == {"jsonrpc": "2.0", "id": 2, "result": "pong"}
    send({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": 1}})
    cancelled = recv()
    assert cancelled["id"] == 1
    assert cancelled["error"]["code"] == protocol.REQUEST_CANCELLED
    host_in.close()
    thread.join(5)
    assert not thread.is_alive()
