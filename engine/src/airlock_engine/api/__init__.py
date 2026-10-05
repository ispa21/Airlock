"""RPC method handlers. ``build_registry`` is the single list of exposed methods."""

from __future__ import annotations

from pathlib import Path

from airlock_engine.api import documents, profiles, rules, scan, system
from airlock_engine.ipc.server import MethodRegistry
from airlock_engine.scan import SessionStore
from airlock_engine.storage import Storage


def build_registry(data_dir: Path | None = None) -> MethodRegistry:
    """``data_dir=None`` keeps rules in memory (tests, or no writable profile)."""
    registry = MethodRegistry()
    storage = Storage(data_dir)
    sessions = SessionStore()
    system.register(registry)
    documents.register(registry)
    scan.register(registry, storage, sessions)
    rules.register(registry, storage)
    profiles.register(registry, storage)
    return registry
