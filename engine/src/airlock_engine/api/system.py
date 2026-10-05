"""``system.*`` methods: handshake and health."""

from __future__ import annotations

import os
import platform
import time
from typing import Any

from airlock_engine import __version__
from airlock_engine.ipc import protocol
from airlock_engine.ipc.server import MethodRegistry, RequestContext
from airlock_engine.security import network_guard

_STARTED = time.monotonic()


def register(registry: MethodRegistry) -> None:
    def hello(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        client_protocol = params.get("protocol_version")
        compatible = (
            isinstance(client_protocol, str)
            and client_protocol.split(".", 1)[0] == protocol.PROTOCOL_VERSION.split(".", 1)[0]
        )
        return {
            "engine": "airlock-engine",
            "engine_version": __version__,
            "protocol_version": protocol.PROTOCOL_VERSION,
            "compatible": compatible,
            "methods": registry.names(),
            "pid": os.getpid(),
            "network_isolation": network_guard.is_installed(),
        }

    def health(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        return {
            "status": "ok",
            "uptime_s": round(time.monotonic() - _STARTED, 1),
            "network_isolation": network_guard.is_installed(),
            "blocked_network_attempts": network_guard.blocked_attempts(),
            "python": platform.python_version(),
            "platform": platform.system().lower(),
        }

    registry.register("system.hello", hello)
    registry.register("system.health", health)
