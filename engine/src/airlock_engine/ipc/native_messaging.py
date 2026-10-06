"""Browser-extension bridge: Chrome/Edge native messaging (Phase 11).

When the browser starts the engine for the Airlock extension, it passes the
extension's origin (``chrome-extension://<id>/``) as the first argument and
speaks native messaging on stdin/stdout: each message is a 32-bit
little-endian length followed by that many bytes of UTF-8 JSON.

The same JSON-RPC dispatch serves these messages, but only a short list of
methods is reachable, and only from the Airlock extension's own origin
(checked here as well as by the browser's host manifest). No file can be
read through the bridge; text sent by the extension is protected and
returned, never stored.
"""

from __future__ import annotations

import json
import struct
from typing import Any, BinaryIO, Final

from airlock_engine import safelog
from airlock_engine.ipc.server import MethodRegistry, StdioServer

#: Methods the extension may call.
METHODS: Final = ("system.hello", "system.health", "profiles.list", "text.protect")
#: Extension origins allowed to start the bridge. The development ID comes
#: from the public key in apps/extension/manifest.json; release IDs are added
#: here and in the host manifest when the extension is published.
ALLOWED_ORIGINS: Final = frozenset({"chrome-extension://cbihflandcpahjbogbficbpidmpdgcce/"})
#: Browsers refuse messages from a host larger than 1 MB.
MAX_OUTGOING: Final = 1024 * 1024
MAX_INCOMING: Final = 4 * 1024 * 1024


def is_extension_origin(arg: str) -> bool:
    return arg.startswith("chrome-extension://")


def restricted(registry: MethodRegistry) -> MethodRegistry:
    allowed = MethodRegistry()
    for name in METHODS:
        handler = registry.get(name)
        if handler is not None:
            allowed.register(name, handler)
    return allowed


def encode(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack("<I", len(body)) + body


class NativeMessagingServer(StdioServer):
    """StdioServer with native-messaging framing and size limits."""

    def __init__(self, registry: MethodRegistry, reader: BinaryIO, writer: BinaryIO) -> None:
        super().__init__(restricted(registry), reader, writer, max_message_bytes=MAX_INCOMING)

    def _send(self, message: dict[str, Any]) -> None:
        data = encode(message)
        if len(data) - 4 > MAX_OUTGOING:
            request_id = message.get("id")
            data = encode(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32002, "message": "Result too large for the browser"},
                }
            )
        with self._write_lock:
            try:
                self._writer.write(data)
                self._writer.flush()
            except (BrokenPipeError, OSError, ValueError):
                self._stopping = True

    def _read_exact(self, n: int) -> bytes | None:
        chunks, remaining = [], n
        while remaining:
            chunk = self._reader.read(remaining)
            if not chunk:
                return None
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _read_frame(self) -> bytes | None:
        header = self._read_exact(4)
        if header is None:
            return None
        (length,) = struct.unpack("<I", header)
        if length > self._max:
            # Discard the oversized message in pieces, then report it.
            while length:
                step = min(length, 1 << 20)
                if self._read_exact(step) is None:
                    return None
                length -= step
            return b""
        return self._read_exact(length)


def serve(registry: MethodRegistry, origin: str, reader: BinaryIO, writer: BinaryIO) -> int:
    if origin not in ALLOWED_ORIGINS:
        safelog.log.warning("bridge_origin_refused")
        return 2
    safelog.log.info("bridge_started")
    return NativeMessagingServer(registry, reader, writer).serve_forever()
