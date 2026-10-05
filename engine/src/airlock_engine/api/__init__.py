"""RPC method handlers. ``build_registry`` is the single list of exposed methods."""

from __future__ import annotations

from airlock_engine.api import documents, system
from airlock_engine.ipc.server import MethodRegistry


def build_registry() -> MethodRegistry:
    registry = MethodRegistry()
    system.register(registry)
    documents.register(registry)
    return registry
