"""Line-delimited JSON-RPC server over a pair of binary streams."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any, BinaryIO

from airlock_engine import safelog
from airlock_engine.core.errors import AirlockError, internal_error
from airlock_engine.ipc import protocol
from airlock_engine.ipc.protocol import ProtocolError, Request, RequestId


class InvalidParams(Exception):
    """Raised by handlers when params are missing or of the wrong type."""


class RequestCancelled(Exception):
    pass


class RequestContext:
    def __init__(self, request_id: RequestId, server: StdioServer) -> None:
        self.request_id = request_id
        self._server = server
        self._cancelled = threading.Event()

    def cancel(self) -> None:
        self._cancelled.set()

    @property
    def cancelled(self) -> bool:
        return self._cancelled.is_set()

    def raise_if_cancelled(self) -> None:
        if self._cancelled.is_set():
            raise RequestCancelled

    def progress(self, stage: str, done: int, total: int) -> None:
        """Send a ``$/progress`` notification for this request."""
        self._server.notify(
            "$/progress",
            {"request_id": self.request_id, "stage": stage, "done": done, "total": total},
        )


Handler = Callable[[dict[str, Any], RequestContext], Any]


class MethodRegistry:
    def __init__(self) -> None:
        self._handlers: dict[str, Handler] = {}

    def register(self, name: str, handler: Handler) -> None:
        if name in self._handlers or name.startswith(("$/", "rpc.")):
            raise ValueError(f"cannot register method {name!r}")
        self._handlers[name] = handler

    def method(self, name: str) -> Callable[[Handler], Handler]:
        def decorator(handler: Handler) -> Handler:
            self.register(name, handler)
            return handler

        return decorator

    def get(self, name: str) -> Handler | None:
        return self._handlers.get(name)

    def names(self) -> list[str]:
        return sorted(self._handlers)


def require_str(params: dict[str, Any], key: str, *, max_len: int = 32_767) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value or len(value) > max_len:
        raise InvalidParams(f"'{key}' must be a non-empty string")
    return value


SHUTDOWN_METHOD = "system.shutdown"
CANCEL_METHOD = "$/cancelRequest"


class StdioServer:
    def __init__(
        self,
        registry: MethodRegistry,
        reader: BinaryIO,
        writer: BinaryIO,
        *,
        max_workers: int = 4,
        max_message_bytes: int = protocol.MAX_MESSAGE_BYTES,
    ) -> None:
        self._registry = registry
        self._reader = reader
        self._writer = writer
        self._write_lock = threading.Lock()
        self._inflight: dict[RequestId, RequestContext] = {}
        self._inflight_lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rpc")
        self._max = max_message_bytes
        self._stopping = False

    # ----------------------------------------------------------------- output
    def _send(self, message: dict[str, Any]) -> None:
        data = protocol.encode(message)
        with self._write_lock:
            try:
                self._writer.write(data)
                self._writer.flush()
            except (BrokenPipeError, OSError, ValueError):
                # Host went away; the read loop will see EOF and stop.
                self._stopping = True

    def notify(self, method: str, params: dict[str, Any]) -> None:
        self._send(protocol.notification_message(method, params))

    # ------------------------------------------------------------------ input
    def _read_frame(self) -> bytes | None:
        """Return one frame, ``b""`` for an oversized frame, ``None`` on EOF."""
        line = self._reader.readline(self._max + 1)
        if not line:
            return None
        if len(line) > self._max and not line.endswith(b"\n"):
            # Discard the rest of the oversized frame.
            while True:
                rest = self._reader.readline(self._max)
                if not rest or rest.endswith(b"\n"):
                    break
            return b""
        return line

    def serve_forever(self) -> int:
        safelog.log.info("ipc_ready", protocol=protocol.PROTOCOL_VERSION)
        try:
            while not self._stopping:
                frame = self._read_frame()
                if frame is None:
                    break
                if frame == b"":
                    self._send(
                        protocol.error_message(
                            None, protocol.MESSAGE_TOO_LARGE, "Message exceeds size limit"
                        )
                    )
                    continue
                frame = frame.strip()
                if frame:
                    self._handle_frame(frame)
        finally:
            self._shutdown()
        return 0

    def _handle_frame(self, frame: bytes) -> None:
        try:
            request = protocol.parse_message(frame)
        except ProtocolError as exc:
            self._send(protocol.error_message(exc.request_id, exc.code, exc.message))
            return

        if request.method == CANCEL_METHOD:
            self._cancel(request.params.get("id"))
            return
        if request.method == SHUTDOWN_METHOD:
            if request.request_id is not None:
                self._send(protocol.result_message(request.request_id, {"ok": True}))
            self._stopping = True
            return
        if request.is_notification:
            return  # no other client->engine notifications are defined

        assert request.request_id is not None
        handler = self._registry.get(request.method)
        if handler is None:
            self._send(
                protocol.error_message(
                    request.request_id, protocol.METHOD_NOT_FOUND, "Method not found"
                )
            )
            return

        ctx = RequestContext(request.request_id, self)
        with self._inflight_lock:
            if request.request_id in self._inflight:
                self._send(
                    protocol.error_message(
                        request.request_id, protocol.INVALID_REQUEST, "Duplicate request id"
                    )
                )
                return
            self._inflight[request.request_id] = ctx
        self._executor.submit(self._run, request, handler, ctx)

    def _cancel(self, request_id: object) -> None:
        if isinstance(request_id, int | str):
            with self._inflight_lock:
                ctx = self._inflight.get(request_id)
            if ctx is not None:
                ctx.cancel()

    def _run(self, request: Request, handler: Handler, ctx: RequestContext) -> None:
        assert request.request_id is not None
        started = time.perf_counter()
        status = "ok"
        try:
            result = handler(request.params, ctx)
            response = protocol.result_message(request.request_id, result)
        except AirlockError as exc:
            status = exc.kind
            response = protocol.error_message(
                request.request_id, protocol.AIRLOCK_ERROR, exc.message, exc.to_data()
            )
        except InvalidParams as exc:
            status = "invalid_params"
            response = protocol.error_message(request.request_id, protocol.INVALID_PARAMS, str(exc))
        except RequestCancelled:
            status = "cancelled"
            response = protocol.error_message(
                request.request_id, protocol.REQUEST_CANCELLED, "Request cancelled"
            )
        except Exception as exc:  # never let a handler kill the engine
            status = "internal_error"
            safelog.log.error(
                "handler_exception", method=request.method, exception_type=type(exc).__name__
            )
            err = internal_error()
            response = protocol.error_message(
                request.request_id, protocol.INTERNAL_ERROR, err.message, err.to_data()
            )
        finally:
            with self._inflight_lock:
                self._inflight.pop(request.request_id, None)
        self._send(response)
        safelog.log.debug(
            "request_completed",
            method=request.method,
            status=status,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )

    def _shutdown(self) -> None:
        # Every accepted request still gets a response: queued work is drained,
        # not dropped. The host kills the process if it cannot wait.
        self._executor.shutdown(wait=True)
        safelog.log.info("ipc_stopped")
