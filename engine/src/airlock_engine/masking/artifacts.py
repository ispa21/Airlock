"""Protected copies waiting to be verified and saved (Phase 7).

They live in a private work folder: ``<data dir>/work`` (user-only), or a
fresh temporary folder in memory-only mode. Anything left there by a previous
run is deleted at start-up; everything is deleted when the engine exits, when
the scan is discarded, or when the copy is discarded.
"""

from __future__ import annotations

import contextlib
import os
import secrets
import shutil
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Artifact:
    artifact_id: str
    scan_id: str
    path: Path
    format_id: str
    suggested_name: str
    size_bytes: int = 0
    sha256: str = ""
    removed: list[tuple[str, str]] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"Artifact(id={self.artifact_id}, format={self.format_id})"


class ArtifactStore:
    def __init__(self, work_dir: Path | None) -> None:
        self._temporary = work_dir is None
        if work_dir is None:
            work_dir = Path(tempfile.mkdtemp(prefix="airlock-work-"))
        work_dir.mkdir(parents=True, exist_ok=True)
        if os.name == "posix":
            with contextlib.suppress(OSError):
                os.chmod(work_dir, 0o700)
        self.work_dir = work_dir
        self._lock = threading.Lock()
        self._items: dict[str, Artifact] = {}
        self.swept = self._sweep_leftovers()

    def _sweep_leftovers(self) -> int:
        removed = 0
        for path in self.work_dir.iterdir():
            with contextlib.suppress(OSError):
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()
                removed += 1
        return removed

    def create(self, scan_id: str, format_id: str, extension: str, original_name: str) -> Artifact:
        artifact_id = f"art_{secrets.token_hex(8)}"
        stem = original_name.rsplit(".", 1)[0] if "." in original_name else original_name
        ext = "pdf" if format_id == "pdf" else extension
        artifact = Artifact(
            artifact_id=artifact_id,
            scan_id=scan_id,
            path=self.work_dir / f"{artifact_id}.{ext or 'bin'}",
            format_id=format_id,
            suggested_name=f"{stem} (Airlock protected).{ext}"
            if ext
            else f"{stem} (Airlock protected)",
        )
        with self._lock:
            self._items[artifact_id] = artifact
        return artifact

    def get(self, artifact_id: str) -> Artifact | None:
        with self._lock:
            return self._items.get(artifact_id)

    def discard(self, artifact_id: str) -> bool:
        with self._lock:
            artifact = self._items.pop(artifact_id, None)
        if artifact is None:
            return False
        with contextlib.suppress(FileNotFoundError):
            artifact.path.unlink()
        return True

    def discard_scan(self, scan_id: str) -> int:
        with self._lock:
            ids = [a.artifact_id for a in self._items.values() if a.scan_id == scan_id]
        return sum(self.discard(i) for i in ids)

    def clear(self) -> None:
        with self._lock:
            ids = list(self._items)
        for artifact_id in ids:
            self.discard(artifact_id)
        self._sweep_leftovers()
        if self._temporary:
            shutil.rmtree(self.work_dir, ignore_errors=True)
