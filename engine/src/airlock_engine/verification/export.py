"""Write a verified copy to the place the user chose (Phase 7).

The destination comes from the host's native save dialog, never from the web
view. It is still checked here: an absolute path in an existing folder, the
copy's own extension, never the original file or one of Airlock's own
folders, never through a link. The bytes go to a temporary file in the same
folder and replace the destination in one step, so a failed save leaves
nothing half-written.
"""

from __future__ import annotations

import contextlib
import os
import secrets
from collections.abc import Iterable
from pathlib import Path

from airlock_engine.core import errors
from airlock_engine.security.input_files import DEVICE_PREFIXES, RESERVED_WINDOWS_NAMES

_MAX_PATH_CHARS = 32_767


def _same(a: Path, b: Path) -> bool:
    if os.path.normcase(os.path.realpath(a)) == os.path.normcase(os.path.realpath(b)):
        return True
    try:
        return a.exists() and b.exists() and os.path.samefile(a, b)
    except OSError:
        return False


def _inside(path: Path, folder: Path) -> bool:
    real = os.path.normcase(os.path.realpath(path))
    base = os.path.normcase(os.path.realpath(folder))
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def validate_destination(
    raw: object,
    *,
    extension: str,
    never: Iterable[Path],
    private_folders: Iterable[Path],
) -> Path:
    """The checked destination path, or an AirlockError saying what to change."""
    if not isinstance(raw, str) or not raw or len(raw) > _MAX_PATH_CHARS or "\x00" in raw:
        raise errors.export_destination_invalid()
    if raw.lower().startswith(DEVICE_PREFIXES):
        raise errors.export_destination_invalid()
    path = Path(raw)
    if not path.is_absolute() or not path.name or path.name in (".", ".."):
        raise errors.export_destination_invalid()
    if os.name == "nt" and path.name.split(".", 1)[0].lower() in RESERVED_WINDOWS_NAMES:
        raise errors.export_destination_invalid()
    if path.suffix.lower() != f".{extension.lower()}":
        raise errors.export_wrong_extension(extension)
    parent = path.parent
    if not parent.is_dir():
        raise errors.export_destination_invalid()
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise errors.export_destination_invalid()
    for original in never:
        if _same(path, original):
            raise errors.export_would_overwrite_original()
    for folder in private_folders:
        if _inside(path, folder):
            raise errors.export_destination_invalid()
    return path


def write_atomically(destination: Path, data: bytes) -> None:
    """Write ``data`` next to ``destination``, then move it into place."""
    temporary = destination.parent / f".{destination.name}.{secrets.token_hex(4)}.airlock-tmp"
    try:
        fd = os.open(
            temporary,
            os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0),
            0o666,
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    except PermissionError as exc:
        raise errors.export_not_permitted() from exc
    except OSError as exc:
        raise errors.export_failed() from exc
    finally:
        with contextlib.suppress(OSError):
            temporary.unlink()
