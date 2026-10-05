"""Vault and key protection: encryption, tamper detection, restore rules."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from airlock_engine.masking.vault import Vault, VaultEntry, VaultError
from airlock_engine.security.keyprotect import (
    MASTER_FILE,
    DpapiProtector,
    FileProtector,
    KeyProtectionError,
    MemoryProtector,
    default_protector,
)
from airlock_engine.storage import Storage

ENTRIES = [
    VaultEntry("[PERSON_1]", "Rahul Sharma", "PERSON"),
    VaultEntry("[INTERNAL_PROJECT_1]", "Project Phoenix", "INTERNAL_PROJECT"),
    VaultEntry("[EMAIL_1]", "rahul.sharma@example.invalid", "EMAIL"),
    VaultEntry("Alex Example", "Priya Patel", "PERSON"),
]


@pytest.fixture
def vault(tmp_path: Path) -> Vault:
    v = Vault(tmp_path / "vault", FileProtector(tmp_path))
    v.put("art_0123456789abcdef", ENTRIES, {"format": "docx"})
    return v


def test_records_are_encrypted_at_rest(vault: Vault, tmp_path: Path) -> None:
    blob = (tmp_path / "vault" / "art_0123456789abcdef.bin").read_bytes()
    for e in ENTRIES:
        assert e.original.encode() not in blob and e.placeholder.encode() not in blob
    key_file = (tmp_path / "vault" / "vault.key").read_bytes()
    assert len(key_file) > 32  # wrapped, not the raw key
    if os.name == "posix":
        assert (tmp_path / "vault" / "art_0123456789abcdef.bin").stat().st_mode & 0o077 == 0
        assert (tmp_path / MASTER_FILE).stat().st_mode & 0o077 == 0


def test_restore_only_known_placeholders(vault: Vault) -> None:
    text = (
        "[PERSON_1] leads [INTERNAL_PROJECT_1]. [PERSON_1]'s mail is [EMAIL_1]. "
        "[PERSON_2] and [PERSON_10] are unknown. Alex Example and Alex Examples."
    )
    restored, count = vault.restore("art_0123456789abcdef", text) or ("", 0)
    assert restored == (
        "Rahul Sharma leads Project Phoenix. Rahul Sharma's mail is "
        "rahul.sharma@example.invalid. [PERSON_2] and [PERSON_10] are unknown. "
        "Priya Patel and Alex Examples."
    )
    assert count == 5


def test_survives_reopen_and_detects_tampering(vault: Vault, tmp_path: Path) -> None:
    reopened = Vault(tmp_path / "vault", FileProtector(tmp_path))
    assert reopened.entries("art_0123456789abcdef") == ENTRIES
    path = tmp_path / "vault" / "art_0123456789abcdef.bin"
    data = bytearray(path.read_bytes())
    data[-1] ^= 0x01
    path.write_bytes(bytes(data))
    with pytest.raises(VaultError):
        reopened.entries("art_0123456789abcdef")


def test_records_cannot_be_swapped_between_copies(vault: Vault, tmp_path: Path) -> None:
    src = tmp_path / "vault" / "art_0123456789abcdef.bin"
    (tmp_path / "vault" / "art_fedcba9876543210.bin").write_bytes(src.read_bytes())
    with pytest.raises(VaultError):
        vault.entries("art_fedcba9876543210")


def test_wrong_key_cannot_open_the_vault(vault: Vault, tmp_path: Path) -> None:
    (tmp_path / MASTER_FILE).write_bytes(os.urandom(32))
    with pytest.raises(VaultError):
        Vault(tmp_path / "vault", FileProtector(tmp_path))


def test_forget_purge_and_ids(vault: Vault, tmp_path: Path) -> None:
    assert vault.ids() == ["art_0123456789abcdef"]
    assert vault.restore("art_ffffffffffffffff", "x") is None
    old = tmp_path / "vault" / "art_0123456789abcdef.bin"
    os.utime(old, (1, 1))
    assert vault.purge(older_than_days=30) == 1
    assert vault.ids() == []
    vault.put("art_aaaaaaaaaaaaaaaa", ENTRIES, {})
    assert vault.forget("art_aaaaaaaaaaaaaaaa") and not vault.forget("art_aaaaaaaaaaaaaaaa")
    with pytest.raises(VaultError):
        vault.entries("../../etc/passwd")


def test_memory_vault_and_reprs() -> None:
    v = Vault(None, MemoryProtector())
    v.put("art_0123456789abcdef", ENTRIES, {})
    assert v.restore("art_0123456789abcdef", "[EMAIL_1]") == ("rahul.sharma@example.invalid", 1)
    assert "Rahul" not in repr(ENTRIES)


def test_protectors_round_trip_and_reject_foreign_blobs(tmp_path: Path) -> None:
    for protector in (MemoryProtector(), FileProtector(tmp_path)):
        assert protector.unwrap(protector.wrap(b"k" * 32)) == b"k" * 32
        with pytest.raises(KeyProtectionError):
            protector.unwrap(MemoryProtector().wrap(b"k" * 32))
    assert default_protector(None).name == "memory"
    expected = "dpapi" if sys.platform == "win32" else "file"
    assert default_protector(tmp_path).name == expected


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI exists only on Windows")
def test_dpapi_round_trip() -> None:
    protector = DpapiProtector()
    blob = protector.wrap(b"secret-key-material-0123456789ab")
    assert b"secret-key-material" not in blob
    assert protector.unwrap(blob) == b"secret-key-material-0123456789ab"
    with pytest.raises(KeyProtectionError):
        protector.unwrap(b"not a dpapi blob")


def test_allow_list_key_is_wrapped_and_legacy_key_migrated(tmp_path: Path) -> None:
    # Simulate a Phase 3 database: plain hex key, no wrapped key.
    setup = Storage(tmp_path)
    setup.rules.set_setting("allow_list_key", "11" * 32)
    setup.rules.delete_setting("allow_list_key_wrapped")
    setup.close()

    first = Storage(tmp_path)
    store = first.rules
    first.allow_list.add("EMAIL", "a@example.invalid")
    assert store.setting("allow_list_key") is None
    wrapped = store.setting("allow_list_key_wrapped")
    assert wrapped and "11" * 32 not in wrapped
    first.close()
    second = Storage(tmp_path)
    assert second.allow_list.contains("EMAIL", "a@example.invalid")
