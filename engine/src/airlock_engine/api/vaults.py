"""The vault, opened once and shared by protected copies and conversations."""

from __future__ import annotations

import threading
from pathlib import Path

from airlock_engine.core import errors
from airlock_engine.masking.conversations import Conversations
from airlock_engine.masking.vault import Vault, VaultError
from airlock_engine.security.keyprotect import KeyProtectionError, MemoryProtector
from airlock_engine.storage import Storage, StorageError


class VaultHolder:
    """Opens the vault lazily; a broken vault never blocks scanning."""

    def __init__(self, storage: Storage, directory: Path | None) -> None:
        self._storage = storage
        self._directory = directory
        self._vault: Vault | None = None
        self._lock = threading.Lock()
        self.conversations = Conversations(self.get)

    def get(self) -> Vault:
        with self._lock:
            if self._vault is None:
                try:
                    protector = (
                        self._storage.key_protector() if self._directory else MemoryProtector()
                    )
                    self._vault = Vault(self._directory, protector)
                    self._vault.purge()
                except (StorageError, VaultError, KeyProtectionError, OSError) as exc:
                    raise errors.vault_unavailable() from exc
            return self._vault
