"""SQLite settings, rules, profiles and (Phase 5) the encrypted pseudonym vault."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

from airlock_engine.security.keyprotect import KeyProtector, default_protector
from airlock_engine.storage.db import DB_FILE, Database, StorageError
from airlock_engine.storage.profiles import ProfileError, ProfileNotFound, ProfileStore
from airlock_engine.storage.rules import AllowList, RuleStore

__all__ = [
    "AllowList",
    "Database",
    "ProfileError",
    "ProfileNotFound",
    "ProfileStore",
    "RuleStore",
    "Storage",
    "StorageError",
    "default_data_dir",
]

APP_ID = "com.airlock.desktop"


def default_data_dir() -> Path:
    """Matches Tauri's ``app_local_data_dir`` for this app id."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_ID
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_ID
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / APP_ID


class Storage:
    """Lazily opened so a broken database never blocks the engine handshake."""

    def __init__(self, data_dir: Path | None) -> None:
        self.data_dir = data_dir
        self._lock = threading.Lock()
        self._db: Database | None = None
        self._rules: RuleStore | None = None
        self._allow: AllowList | None = None
        self._profiles: ProfileStore | None = None
        self.protector: KeyProtector | None = None

    def _open(self) -> None:
        if self._db is None:
            path = self.data_dir / DB_FILE if self.data_dir is not None else None
            self._db = Database(path)
            self._rules = RuleStore(self._db)
            self.protector = default_protector(self.data_dir)
            self._allow = AllowList(self._rules, self.protector)
            self._profiles = ProfileStore(self._db)

    @property
    def rules(self) -> RuleStore:
        with self._lock:
            self._open()
            assert self._rules is not None
            return self._rules

    @property
    def allow_list(self) -> AllowList:
        with self._lock:
            self._open()
            assert self._allow is not None
            return self._allow

    def key_protector(self) -> KeyProtector:
        with self._lock:
            self._open()
            assert self.protector is not None
            return self.protector

    @property
    def profiles(self) -> ProfileStore:
        with self._lock:
            self._open()
            assert self._profiles is not None
            return self._profiles

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
