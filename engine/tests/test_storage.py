"""SQLite storage: schema, permissions, rules CRUD, allow-list privacy."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import pytest

from airlock_engine.detectors.custom import RuleError
from airlock_engine.storage import Storage, StorageError
from airlock_engine.storage.db import DB_FILE, SCHEMA_VERSION, Database


@pytest.fixture
def storage(tmp_path: Path) -> Storage:
    return Storage(tmp_path / "data")


def test_schema_created_with_builtin_seed(storage: Storage) -> None:
    store = storage.rules
    assert store.db.schema_version() == SCHEMA_VERSION
    ids = {c.id for c in store.categories()}
    assert {"EMAIL", "AADHAAR", "API_KEY", "INTERNAL_PROJECT", "CLIENT_NAME"} <= ids
    tables = {r["name"] for r in store.db.query("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"settings", "privacy_profiles", "policy_rules", "categories", "custom_rules",
            "custom_rule_aliases", "allow_list", "license", "schema_version"} <= tables
    assert store.db.query("SELECT id FROM privacy_profiles")[0]["id"] == "company-default"


@pytest.mark.skipif(os.name != "posix", reason="POSIX permission bits")
def test_database_is_user_only(storage: Storage, tmp_path: Path) -> None:
    storage.rules  # noqa: B018 - opens the database
    assert (tmp_path / "data" / DB_FILE).stat().st_mode & 0o077 == 0
    assert (tmp_path / "data").stat().st_mode & 0o077 == 0


def test_rule_crud_and_persistence(tmp_path: Path) -> None:
    first = Storage(tmp_path)
    row = first.rules.create(kind="normalized", pattern="Project Phoenix",
                             category_id="INTERNAL_PROJECT", aliases=("Phoenix", "PHX"))
    assert row.aliases == ("PHX", "Phoenix")
    updated = first.rules.update(row.id, aliases=("PHX",), enabled=False, action="BLOCK")
    assert updated is not None and updated.aliases == ("PHX",) and not updated.enabled
    assert updated.action == "BLOCK"
    first.close()

    second = Storage(tmp_path)
    (loaded,) = second.rules.all()
    assert loaded.pattern == "Project Phoenix" and loaded.aliases == ("PHX",)
    assert second.rules.compiled() == []  # disabled rules are not compiled
    assert second.rules.delete(row.id)
    assert not second.rules.delete(row.id)
    assert second.rules.db.query("SELECT COUNT(*) AS n FROM custom_rule_aliases")[0]["n"] == 0


def test_rule_validation(storage: Storage) -> None:
    with pytest.raises(RuleError):
        storage.rules.create(kind="exact", pattern="X", category_id="NOPE")
    with pytest.raises(RuleError):
        storage.rules.create(kind="regex", pattern="(", category_id="INTERNAL_PROJECT")
    with pytest.raises(RuleError):
        storage.rules.create(kind="exact", pattern="ok", category_id="INTERNAL_PROJECT",
                             action="DELETE")
    assert storage.rules.update("rule_missing", pattern="x") is None


def test_custom_category(storage: Storage) -> None:
    cat = storage.rules.add_category("Board codenames", "INTELLECTUAL_PROPERTY", 4)
    assert cat.id == "BOARD_CODENAMES" and not cat.builtin
    again = storage.rules.add_category("Board codenames", "INTELLECTUAL_PROPERTY", 4)
    assert again.id == "BOARD_CODENAMES_2"
    rule = storage.rules.create(kind="exact", pattern="Nimbus", category_id=cat.id)
    (compiled,) = storage.rules.compiled()
    assert compiled.id == rule.id and int(compiled.severity) == 4
    with pytest.raises(RuleError):
        storage.rules.add_category("x", "PERSONAL", 2)
    with pytest.raises(RuleError):
        storage.rules.add_category("Valid", "NOT_A_GROUP", 2)


def test_allow_list_stores_only_keyed_hashes(tmp_path: Path) -> None:
    storage = Storage(tmp_path)
    allow = storage.allow_list
    allow.add("EMAIL", "test.user@example.invalid")
    assert allow.contains("EMAIL", "test.user@example.invalid")
    assert allow.contains("EMAIL", "TEST.USER@example.invalid")  # normalized
    assert not allow.contains("PHONE", "test.user@example.invalid")
    storage.close()
    raw = (tmp_path / DB_FILE).read_bytes()
    wal = tmp_path / (DB_FILE + "-wal")
    if wal.exists():
        raw += wal.read_bytes()
    assert b"test.user" not in raw
    # The key survives a restart, so the entry still matches.
    assert Storage(tmp_path).allow_list.contains("EMAIL", "test.user@example.invalid")


def test_database_from_a_newer_version_is_refused(tmp_path: Path) -> None:
    path = tmp_path / DB_FILE
    Database(path).close()
    conn = sqlite3.connect(path)
    conn.execute("UPDATE schema_version SET version = 999")
    conn.commit()
    conn.close()
    with pytest.raises(StorageError):
        Database(path)


def test_corrupt_database_raises_storage_error(tmp_path: Path) -> None:
    (tmp_path / DB_FILE).write_bytes(b"this is not sqlite" * 100)
    with pytest.raises(StorageError):
        Storage(tmp_path).rules  # noqa: B018


def test_in_memory_storage_needs_no_disk() -> None:
    storage = Storage(None)
    storage.rules.create(kind="exact", pattern="Nimbus", category_id="INTERNAL_PROJECT")
    assert len(storage.rules.all()) == 1
