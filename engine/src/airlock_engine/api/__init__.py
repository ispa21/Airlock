"""RPC method handlers. ``build_registry`` is the single list of exposed methods."""

from __future__ import annotations

import atexit
from pathlib import Path

from airlock_engine.api import (
    conversation,
    documents,
    profiles,
    rules,
    sanitize,
    scan,
    system,
    text,
    verify,
)
from airlock_engine.api.vaults import VaultHolder
from airlock_engine.ipc.server import MethodRegistry
from airlock_engine.masking.artifacts import ArtifactStore
from airlock_engine.scan import SessionStore
from airlock_engine.storage import Storage


def build_registry(data_dir: Path | None = None) -> MethodRegistry:
    """``data_dir=None`` keeps rules, the vault and protected copies in memory or a
    temporary folder (tests, or no writable profile)."""
    registry = MethodRegistry()
    storage = Storage(data_dir)
    sessions = SessionStore()
    artifacts = ArtifactStore(data_dir / "work" if data_dir is not None else None)
    # Protected copies never outlive the engine.
    atexit.register(artifacts.clear)
    system.register(registry)
    documents.register(registry)
    scan.register(registry, storage, sessions, artifacts)
    rules.register(registry, storage)
    profiles.register(registry, storage)
    vaults = VaultHolder(storage, data_dir / "vault" if data_dir else None)
    sanitize.register(registry, sessions, artifacts, vaults)
    text.register(registry, storage, vaults)
    conversation.register(registry, storage, vaults)
    # A copy is never saved into Airlock's own folders (work folder, vault, database).
    verify.register(registry, storage, artifacts, [data_dir] if data_dir else [])
    return registry
