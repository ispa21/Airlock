"""Protection for Airlock's own keys (vault key, allow-list key).

* **Windows**: DPAPI (``CryptProtectData``, current-user scope). Only the same
  Windows account on the same machine can unwrap the key.
* **Other platforms** (development, CI; macOS Keychain is a later item): a
  random master key in a user-only file (0600) next to the database. This
  keeps keys out of the database file, but anyone who can read the user's
  files can read the master key too.
* **Memory**: for tests and memory-only runs; keys vanish on exit.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import sys
from abc import ABC, abstractmethod
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_WRAP_AAD = b"airlock-key-wrap-v1"
_DPAPI_ENTROPY = b"airlock-key-v1"
MASTER_FILE = "keyring.bin"


class KeyProtectionError(RuntimeError):
    pass


class KeyProtector(ABC):
    #: Shown in the UI and docs: "dpapi", "file", "memory".
    name: str

    @abstractmethod
    def wrap(self, key: bytes) -> bytes: ...

    @abstractmethod
    def unwrap(self, blob: bytes) -> bytes: ...


class _AesWrapper(KeyProtector):
    def __init__(self, master: bytes) -> None:
        self._aes = AESGCM(master)

    def wrap(self, key: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._aes.encrypt(nonce, key, _WRAP_AAD)

    def unwrap(self, blob: bytes) -> bytes:
        try:
            return self._aes.decrypt(blob[:12], blob[12:], _WRAP_AAD)
        except (InvalidTag, ValueError) as exc:
            raise KeyProtectionError("key cannot be unwrapped") from exc


class MemoryProtector(_AesWrapper):
    name = "memory"

    def __init__(self) -> None:
        super().__init__(secrets.token_bytes(32))


class FileProtector(_AesWrapper):
    name = "file"

    def __init__(self, directory: Path) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / MASTER_FILE
        if path.exists():
            master = path.read_bytes()
        else:
            master = secrets.token_bytes(32)
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(master)
        if os.name == "posix":
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
        if len(master) != 32:
            raise KeyProtectionError("master key file is damaged")
        super().__init__(master)


class DpapiProtector(KeyProtector):
    """Windows Data Protection API through ctypes (no extra dependency)."""

    name = "dpapi"

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise KeyProtectionError("DPAPI is only available on Windows")

    @staticmethod
    def _call(data: bytes, protect: bool) -> bytes:
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def blob(raw: bytes) -> Blob:
            buffer = ctypes.create_string_buffer(raw, len(raw))
            return Blob(len(raw), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))

        crypt32 = ctypes.windll.crypt32  # type: ignore[attr-defined]
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        source, entropy, result = blob(data), blob(_DPAPI_ENTROPY), Blob()
        ui_forbidden = 0x1
        fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        ok = fn(
            ctypes.byref(source),
            None,
            ctypes.byref(entropy),
            None,
            None,
            ui_forbidden,
            ctypes.byref(result),
        )
        if not ok:
            raise KeyProtectionError("DPAPI call failed")
        try:
            return ctypes.string_at(result.pbData, result.cbData)
        finally:
            kernel32.LocalFree(result.pbData)

    def wrap(self, key: bytes) -> bytes:
        return self._call(key, protect=True)

    def unwrap(self, blob: bytes) -> bytes:
        return self._call(blob, protect=False)


def default_protector(data_dir: Path | None) -> KeyProtector:
    if data_dir is None:
        return MemoryProtector()
    if sys.platform == "win32":
        return DpapiProtector()
    return FileProtector(data_dir)
