"""Encrypted, local-only store of reversible replacements.

Each protected copy gets its own record: the placeholders (or synthetic
values) it contains, the original values and their entity types. Records are
AES-256-GCM encrypted with a vault key that is itself wrapped by the key
protector (DPAPI on Windows). The record id is bound in as associated data, so
records cannot be swapped between copies.

Restoring only replaces placeholders recorded for that copy; anything else,
including look-alike placeholders the AI invents, is left untouched.

Mappings never leave the device: they are not logged, not returned to the UI
except through an explicit restore, and never sent anywhere.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from airlock_engine.security.keyprotect import KeyProtectionError, KeyProtector

_MAGIC = b"ALV1"
_KEY_FILE = "vault.key"
_ID = re.compile(r"^[a-z]+_[0-9a-f]{8,32}$")
DEFAULT_RETENTION_DAYS = 30


class VaultError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class VaultEntry:
    placeholder: str
    original: str
    entity_type: str

    def __repr__(self) -> str:  # never print the original
        return f"VaultEntry({self.placeholder}, type={self.entity_type})"


class Vault:
    def __init__(self, directory: Path | None, protector: KeyProtector) -> None:
        self.directory = directory
        self.protector = protector
        self._lock = threading.Lock()
        self._memory: dict[str, bytes] = {}
        if directory is not None:
            directory.mkdir(parents=True, exist_ok=True)
            if os.name == "posix":
                with contextlib.suppress(OSError):
                    os.chmod(directory, 0o700)
        self._aes = AESGCM(self._load_key())

    def _load_key(self) -> bytes:
        if self.directory is None:
            return secrets.token_bytes(32)
        path = self.directory / _KEY_FILE
        try:
            if path.exists():
                return self.protector.unwrap(path.read_bytes())
        except KeyProtectionError as exc:
            raise VaultError("vault key cannot be unwrapped") from exc
        key = secrets.token_bytes(32)
        _write_private(path, self.protector.wrap(key))
        return key

    def _path(self, record_id: str) -> Path:
        if not _ID.match(record_id):
            raise VaultError("invalid record id")
        assert self.directory is not None
        return self.directory / f"{record_id}.bin"

    def put(self, record_id: str, entries: list[VaultEntry], meta: dict[str, Any]) -> None:
        payload = json.dumps(
            {
                "created": time.time(),
                "meta": meta,
                "entries": [[e.placeholder, e.original, e.entity_type] for e in entries],
            },
            ensure_ascii=False,
        ).encode("utf-8")
        nonce = secrets.token_bytes(12)
        blob = _MAGIC + nonce + self._aes.encrypt(nonce, payload, record_id.encode())
        with self._lock:
            if self.directory is None:
                self._memory[record_id] = blob
            else:
                _write_private(self._path(record_id), blob)

    def _read(self, record_id: str) -> dict[str, Any] | None:
        with self._lock:
            if self.directory is None:
                blob = self._memory.get(record_id)
            else:
                path = self._path(record_id)
                blob = path.read_bytes() if path.exists() else None
        if blob is None:
            return None
        if not blob.startswith(_MAGIC):
            raise VaultError("not a vault record")
        try:
            plain = self._aes.decrypt(blob[4:16], blob[16:], record_id.encode())
        except (InvalidTag, ValueError) as exc:
            raise VaultError("vault record was modified or belongs elsewhere") from exc
        data: dict[str, Any] = json.loads(plain)
        return data

    def entries(self, record_id: str) -> list[VaultEntry] | None:
        data = self._read(record_id)
        if data is None:
            return None
        return [VaultEntry(str(p), str(o), str(t)) for p, o, t in data["entries"]]

    def restore(self, record_id: str, text: str) -> tuple[str, int] | None:
        """Replace this record's placeholders in ``text``. None if no record."""
        entries = self.entries(record_id)
        if entries is None:
            return None
        mapping = {e.placeholder: e.original for e in entries}
        if not mapping:
            return text, 0
        pattern = re.compile("|".join(re.escape(p) for p in sorted(mapping, key=len, reverse=True)))
        count = 0

        def swap(m: re.Match[str]) -> str:
            nonlocal count
            # Synthetic stand-ins are plain words: require word edges for them.
            start, end = m.start(), m.end()
            token = m.group()
            if token[0].isalnum() and start > 0 and text[start - 1].isalnum():
                return token
            if token[-1].isalnum() and end < len(text) and text[end].isalnum():
                return token
            count += 1
            return mapping[token]

        return pattern.sub(swap, text), count

    def forget(self, record_id: str) -> bool:
        with self._lock:
            if self.directory is None:
                return self._memory.pop(record_id, None) is not None
            path = self._path(record_id)
            if path.exists():
                path.unlink()
                return True
            return False

    def ids(self) -> list[str]:
        with self._lock:
            if self.directory is None:
                return sorted(self._memory)
            return sorted(p.stem for p in self.directory.glob("*.bin"))

    def purge(self, older_than_days: float = DEFAULT_RETENTION_DAYS) -> int:
        """Delete records older than the retention period (by file time)."""
        if self.directory is None:
            return 0
        cutoff = time.time() - older_than_days * 86400
        removed = 0
        with self._lock:
            for path in self.directory.glob("*.bin"):
                with contextlib.suppress(OSError):
                    if path.stat().st_mtime < cutoff:
                        path.unlink()
                        removed += 1
        return removed


def _write_private(path: Path, data: bytes) -> None:
    """Write atomically, readable by the user only."""
    tmp = path.with_suffix(path.suffix + f".{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
    os.replace(tmp, path)
