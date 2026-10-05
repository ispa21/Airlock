"""SQLite database: connection, schema migrations and built-in seed data.

One file per user profile (``<data dir>/airlock.db``), WAL mode, foreign keys
on. The database holds settings, privacy profiles, categories, company rules
and allow-list fingerprints. It never stores document content, and the
allow-list keeps keyed hashes rather than values. Company rule patterns are
confidential: the file is created user-only (0600 on POSIX; on Windows it
lives under the per-user ``%LOCALAPPDATA%``, which is user-only by default).
"""

from __future__ import annotations

import contextlib
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from airlock_engine.detectors.entities import BUILTIN_ENTITIES, BUILTIN_RULE_CATEGORIES
from airlock_engine.policy.profiles import BUILTIN_PROFILES

DB_FILE = "airlock.db"

_MIGRATIONS: tuple[str, ...] = (
    # v1 — docs/ARCHITECTURE.md §6.2
    """
    CREATE TABLE settings (
      key   TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE privacy_profiles (
      id          TEXT PRIMARY KEY,
      name        TEXT NOT NULL,
      is_builtin  INTEGER NOT NULL DEFAULT 0,
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    );
    CREATE TABLE policy_rules (
      profile_id  TEXT NOT NULL REFERENCES privacy_profiles(id) ON DELETE CASCADE,
      entity_type TEXT NOT NULL,
      action      TEXT NOT NULL CHECK (action IN ('ALLOW','MASK','REDACT','GENERALIZE','BLOCK')),
      mask_style  TEXT NOT NULL DEFAULT 'typed_placeholder',
      PRIMARY KEY (profile_id, entity_type)
    );
    CREATE TABLE categories (
      id         TEXT PRIMARY KEY,
      label      TEXT NOT NULL,
      group_name TEXT NOT NULL,
      severity   INTEGER NOT NULL CHECK (severity BETWEEN 1 AND 4),
      is_builtin INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE custom_rules (
      id          TEXT PRIMARY KEY,
      kind        TEXT NOT NULL CHECK (kind IN ('exact','case_insensitive','normalized','regex')),
      pattern     TEXT NOT NULL,
      category_id TEXT NOT NULL REFERENCES categories(id),
      action      TEXT CHECK (action IS NULL OR
                              action IN ('ALLOW','MASK','REDACT','GENERALIZE','BLOCK')),
      enabled     INTEGER NOT NULL DEFAULT 1,
      created_at  TEXT NOT NULL,
      updated_at  TEXT NOT NULL
    );
    CREATE TABLE custom_rule_aliases (
      rule_id TEXT NOT NULL REFERENCES custom_rules(id) ON DELETE CASCADE,
      alias   TEXT NOT NULL,
      PRIMARY KEY (rule_id, alias)
    );
    CREATE TABLE allow_list (
      id          TEXT PRIMARY KEY,
      value_hmac  TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      created_at  TEXT NOT NULL,
      UNIQUE (value_hmac, entity_type)
    );
    CREATE TABLE license (
      id           INTEGER PRIMARY KEY CHECK (id = 1),
      license_json TEXT NOT NULL,
      signature    TEXT NOT NULL,
      verified_at  TEXT NOT NULL
    );
    """,
    # v2 — Phase 4: custom profiles copy a built-in profile and override it.
    """
    ALTER TABLE privacy_profiles ADD COLUMN base_id TEXT;
    ALTER TABLE privacy_profiles ADD COLUMN min_confidence REAL;
    ALTER TABLE privacy_profiles ADD COLUMN mask_style TEXT;
    """,
)

SCHEMA_VERSION = len(_MIGRATIONS)


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class StorageError(RuntimeError):
    pass


class Database:
    """A single shared connection guarded by a lock.

    The engine serves requests on a small thread pool; SQLite calls are short,
    so serialising them is simpler and safer than a connection per thread.
    ``path=None`` gives an in-memory database (tests, or no data directory).
    """

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._lock = threading.RLock()
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True)
            _restrict(path.parent, 0o700)
            created = not path.exists()
            if created:
                # Create the file user-only before SQLite opens it.
                fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
                os.close(fd)
            target = str(path)
        else:
            target = ":memory:"
        try:
            self._conn = sqlite3.connect(
                target, check_same_thread=False, isolation_level=None, timeout=5.0
            )
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA foreign_keys = ON")
            if path is not None:
                self._conn.execute("PRAGMA journal_mode = WAL")
                self._conn.execute("PRAGMA synchronous = NORMAL")
            self._migrate()
            self._seed()
        except sqlite3.DatabaseError as exc:
            raise StorageError("database unavailable") from exc

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            self._conn.execute("COMMIT")

    def query(self, sql: str, params: tuple[object, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return list(self._conn.execute(sql, params).fetchall())

    def schema_version(self) -> int:
        rows = self.query("SELECT version FROM schema_version")
        return int(rows[0]["version"]) if rows else 0

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        with self.transaction() as conn:
            conn.execute("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)")
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            current = int(row["version"]) if row else 0
            if current > SCHEMA_VERSION:
                raise StorageError("database is from a newer Airlock version")
            for script in _MIGRATIONS[current:]:
                for statement in _statements(script):
                    conn.execute(statement)
            if row is None:
                conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
            else:
                conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION,))

    def _seed(self) -> None:
        stamp = now()
        with self.transaction() as conn:
            for e in (*BUILTIN_ENTITIES.values(), *BUILTIN_RULE_CATEGORIES):
                conn.execute(
                    "INSERT INTO categories (id, label, group_name, severity, is_builtin) "
                    "VALUES (?, ?, ?, ?, 1) ON CONFLICT(id) DO UPDATE SET "
                    "label = excluded.label, group_name = excluded.group_name, "
                    "severity = excluded.severity, is_builtin = 1",
                    (e.id, e.label, e.category.value, int(e.severity)),
                )
            for profile in BUILTIN_PROFILES.values():
                conn.execute(
                    "INSERT INTO privacy_profiles (id, name, is_builtin, created_at, updated_at) "
                    "VALUES (?, ?, 1, ?, ?) ON CONFLICT(id) DO UPDATE SET name = excluded.name, "
                    "is_builtin = 1",
                    (profile.id, profile.name, stamp, stamp),
                )


def _statements(script: str) -> list[str]:
    return [s.strip() for s in script.split(";") if s.strip()]


def _restrict(path: Path, mode: int) -> None:
    if os.name == "posix":
        with contextlib.suppress(OSError):
            os.chmod(path, mode)
