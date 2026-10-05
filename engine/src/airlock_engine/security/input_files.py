"""Validation for files handed to the engine.

Every file is treated as potentially hostile. Before any parser sees it we
check that the path is absolute, refers to a regular file (not a device,
directory or pipe), is within the size limit, and that its bytes match its
extension. The original file is only ever opened read-only.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from airlock_engine.core import errors
from airlock_engine.documents import formats

MAX_FILE_BYTES: Final = 200 * 1024 * 1024
_MAX_PATH_CHARS: Final = 32_767  # Windows extended-length path limit
# Win32 device namespace (\\.\PhysicalDrive0, \\.\pipe\x, \\?\GLOBALROOT\...).
_DEVICE_PREFIXES: Final = ("\\\\.\\", "//./", "\\\\?\\globalroot", "\\\\?\\unc\\.\\")
_RESERVED_WINDOWS_NAMES: Final = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{i}" for i in range(1, 10)}
    | {f"lpt{i}" for i in range(1, 10)}
)


@dataclass(frozen=True, slots=True)
class ValidatedFile:
    path: Path
    size_bytes: int
    extension: str
    spec: formats.FormatSpec


def validate_input_file(raw_path: object, *, max_bytes: int = MAX_FILE_BYTES) -> ValidatedFile:
    path = _parse_path(raw_path)
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
    except FileNotFoundError as exc:
        raise errors.file_not_found() from exc
    except PermissionError as exc:
        raise errors.file_unreadable() from exc
    except (OSError, RuntimeError) as exc:  # RuntimeError: symlink loop
        raise errors.file_not_found() from exc

    if not stat.S_ISREG(info.st_mode):
        raise errors.not_a_regular_file()
    if info.st_size == 0:
        raise errors.file_empty()
    if info.st_size > max_bytes:
        raise errors.file_too_large(max_bytes // (1024 * 1024))

    extension = formats.extension_of(resolved)
    spec = formats.spec_for_extension(extension)
    if spec is None:
        raise errors.unsupported_format(extension)

    try:
        formats.sniff(resolved, spec)
    except PermissionError as exc:
        raise errors.file_unreadable() from exc
    except OSError as exc:
        raise errors.file_unreadable() from exc

    return ValidatedFile(path=resolved, size_bytes=info.st_size, extension=extension, spec=spec)


def _parse_path(raw_path: object) -> Path:
    if not isinstance(raw_path, str) or not raw_path or len(raw_path) > _MAX_PATH_CHARS:
        raise errors.file_not_found()
    if "\x00" in raw_path:
        raise errors.not_a_regular_file()
    lowered = raw_path.lower()
    if lowered.startswith(_DEVICE_PREFIXES):
        raise errors.not_a_regular_file()
    path = Path(raw_path)
    if not path.is_absolute():
        # The host always sends absolute paths; a relative one means a bug or
        # an attempt to resolve against the engine's working directory.
        raise errors.file_not_found()
    stem = path.name.split(".", 1)[0].lower()
    if os.name == "nt" and stem in _RESERVED_WINDOWS_NAMES:
        raise errors.not_a_regular_file()
    return path
