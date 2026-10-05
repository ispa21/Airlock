"""Profile storage: built-ins, custom copies, validation, default, migration."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from airlock_engine.core.models import Action
from airlock_engine.policy.profiles import BUILTIN_PROFILES
from airlock_engine.storage import ProfileError, ProfileNotFound, Storage
from airlock_engine.storage.db import DB_FILE, SCHEMA_VERSION


def test_builtins_listed_and_immutable() -> None:
    store = Storage(None).profiles
    assert [p.id for p in store.all()] == ["company-default", "strict", "secrets-and-ids"]
    with pytest.raises(ProfileError):
        store.update("strict", name="Mine")
    with pytest.raises(ProfileError):
        store.delete("company-default")
    with pytest.raises(ProfileNotFound):
        store.get("profile_nope")


def test_custom_profile_round_trip(tmp_path: Path) -> None:
    store = Storage(tmp_path).profiles
    mine = store.create("Legal team", "strict")
    assert mine.base_id == "strict" and not mine.builtin
    mine = store.update(
        mine.id,
        actions={"EMAIL": Action.ALLOW, "PAN": Action.BLOCK},
        min_confidence=0.8,
        mask_style="placeholder",
    )
    assert mine.actions["EMAIL"] is Action.ALLOW and mine.min_confidence == 0.8
    store.set_default(mine.id)

    reopened = Storage(tmp_path).profiles
    loaded = reopened.get(mine.id)
    assert loaded.actions["PAN"] is Action.BLOCK and loaded.mask_style == "placeholder"
    assert reopened.default_id() == mine.id
    # None resets an entity to the base profile.
    loaded = reopened.update(mine.id, actions={"EMAIL": None})
    assert "EMAIL" not in loaded.actions
    # Copying a custom profile keeps its choices and the root built-in.
    copy = reopened.create("Legal copy", mine.id)
    assert copy.base_id == "strict" and copy.actions["PAN"] is Action.BLOCK
    assert copy.min_confidence == 0.8
    reopened.delete(mine.id)
    assert reopened.default_id() == "company-default"


def test_validation(tmp_path: Path) -> None:
    store = Storage(tmp_path).profiles
    p = store.create("Ops", "company-default")
    with pytest.raises(ProfileError):
        store.update(p.id, actions={"PAN": Action.GENERALIZE})
    with pytest.raises(ProfileError):
        store.update(p.id, actions={"NOT_A_TYPE": Action.MASK})
    with pytest.raises(ProfileError):
        store.update(p.id, min_confidence=1.5)
    with pytest.raises(ProfileError):
        store.update(p.id, mask_style="emoji")
    with pytest.raises(ProfileError):
        store.create("x", "company-default")
    # Custom categories are valid targets when the caller knows them.
    assert (
        store.update(
            p.id, actions={"INTERNAL_PROJECT": Action.REDACT}, known_types={"INTERNAL_PROJECT"}
        ).actions["INTERNAL_PROJECT"]
        is Action.REDACT
    )


def test_version_1_database_is_migrated(tmp_path: Path) -> None:
    """A Phase 3 database (schema v1) gains the profile columns in place."""
    path = tmp_path / DB_FILE
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version VALUES (1);
        CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE privacy_profiles (id TEXT PRIMARY KEY, name TEXT NOT NULL,
          is_builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL);
        CREATE TABLE policy_rules (profile_id TEXT NOT NULL REFERENCES privacy_profiles(id)
          ON DELETE CASCADE, entity_type TEXT NOT NULL, action TEXT NOT NULL,
          mask_style TEXT NOT NULL DEFAULT 'typed_placeholder',
          PRIMARY KEY (profile_id, entity_type));
        CREATE TABLE categories (id TEXT PRIMARY KEY, label TEXT NOT NULL,
          group_name TEXT NOT NULL, severity INTEGER NOT NULL, is_builtin INTEGER NOT NULL
          DEFAULT 0);
        CREATE TABLE custom_rules (id TEXT PRIMARY KEY, kind TEXT NOT NULL, pattern TEXT NOT NULL,
          category_id TEXT NOT NULL, action TEXT, enabled INTEGER NOT NULL DEFAULT 1,
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE custom_rule_aliases (rule_id TEXT NOT NULL, alias TEXT NOT NULL,
          PRIMARY KEY (rule_id, alias));
        CREATE TABLE allow_list (id TEXT PRIMARY KEY, value_hmac TEXT NOT NULL,
          entity_type TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE (value_hmac, entity_type));
        CREATE TABLE license (id INTEGER PRIMARY KEY, license_json TEXT NOT NULL,
          signature TEXT NOT NULL, verified_at TEXT NOT NULL);
        INSERT INTO privacy_profiles VALUES ('company-default', 'Company Default', 1, 'x', 'x');
        """
    )
    conn.commit()
    conn.close()
    storage = Storage(tmp_path)
    assert storage.rules.db.schema_version() == SCHEMA_VERSION == 3
    assert {p.id for p in storage.profiles.all()} == set(BUILTIN_PROFILES)
    created = storage.profiles.create("After upgrade", "company-default")
    assert storage.profiles.get(created.id).base_id == "company-default"
