"""Airlock engine IPC protocol: JSON-RPC 2.0, one JSON object per line, over stdio.

Why stdio and not a localhost HTTP server:

* No listening socket exists, so other local processes and web pages (DNS
  rebinding, CSRF against 127.0.0.1) cannot reach the engine at all.
* Only the process that spawned the engine holds its pipes; that *is* the
  authentication, with no token to leak.
* The engine stays network-free, so the network guard can block every socket.
* Chrome/Edge native messaging (V2 browser extension) is also stdio-based.

See docs/IPC.md for the full specification.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Final

PROTOCOL_VERSION: Final = "1.0"
MAX_MESSAGE_BYTES: Final = 16 * 1024 * 1024

# JSON-RPC 2.0 reserved codes
PARSE_ERROR: Final = -32700
INVALID_REQUEST: Final = -32600
METHOD_NOT_FOUND: Final = -32601
INVALID_PARAMS: Final = -32602
INTERNAL_ERROR: Final = -32603
# Application codes (-32000..-32099)
AIRLOCK_ERROR: Final = -32000
REQUEST_CANCELLED: Final = -32001
MESSAGE_TOO_LARGE: Final = -32002

RequestId = int | str


class ProtocolError(Exception):
    def __init__(self, code: int, message: str, request_id: RequestId | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.request_id = request_id


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    params: dict[str, Any]
    request_id: RequestId | None  # None => notification

    @property
    def is_notification(self) -> bool:
        return self.request_id is None


def parse_message(line: bytes) -> Request:
    try:
        obj = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError(PARSE_ERROR, "Parse error") from exc
    if not isinstance(obj, dict):
        raise ProtocolError(INVALID_REQUEST, "Request must be a JSON object")

    raw_id = obj.get("id")
    request_id: RequestId | None
    valid_int = isinstance(raw_id, int) and not isinstance(raw_id, bool)
    valid_str = isinstance(raw_id, str) and len(raw_id) <= 128
    if raw_id is None or valid_int or valid_str:
        request_id = raw_id
    else:
        raise ProtocolError(INVALID_REQUEST, "Invalid request id")

    if obj.get("jsonrpc") != "2.0":
        raise ProtocolError(INVALID_REQUEST, "jsonrpc must be '2.0'", request_id)
    method = obj.get("method")
    if not isinstance(method, str) or not method or len(method) > 128:
        raise ProtocolError(INVALID_REQUEST, "method must be a non-empty string", request_id)
    params = obj.get("params", {})
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ProtocolError(INVALID_PARAMS, "params must be an object", request_id)
    return Request(method=method, params=params, request_id=request_id)


def encode(obj: dict[str, Any]) -> bytes:
    # ensure_ascii keeps every frame pure ASCII: no encoding ambiguity on Windows
    # pipes, and JSON escaping guarantees a frame never contains a raw newline.
    return json.dumps(obj, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def result_message(request_id: RequestId, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def error_message(
    request_id: RequestId | None, code: int, message: str, data: Any = None
) -> dict[str, Any]:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": error}


def notification_message(method: str, params: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "method": method, "params": params}
