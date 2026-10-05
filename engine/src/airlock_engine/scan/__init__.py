"""Scan sessions: an extracted document and its detections, held in engine
memory only.

A session is keyed by a random ``scan_id`` and lives until ``scan.discard``,
its TTL expires, a newer scan evicts it, or the engine exits. Nothing in a
session is written to disk. The UI receives finding ids and masked previews,
never raw values.
"""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass, field

from airlock_engine.core.models import ExtractedDocument
from airlock_engine.detectors.pipeline import DetectionOutcome

SESSION_TTL_S = 30 * 60
MAX_SESSIONS = 4


@dataclass
class ScanSession:
    scan_id: str
    document: ExtractedDocument
    outcome: DetectionOutcome
    format_id: str
    created: float = field(default_factory=time.monotonic)

    def __repr__(self) -> str:
        return f"ScanSession(id={self.scan_id}, findings={len(self.outcome.detected)})"


class SessionStore:
    def __init__(self, ttl_s: float = SESSION_TTL_S, max_sessions: int = MAX_SESSIONS) -> None:
        self._ttl = ttl_s
        self._max = max_sessions
        self._lock = threading.Lock()
        self._sessions: dict[str, ScanSession] = {}

    def _purge(self) -> None:
        cutoff = time.monotonic() - self._ttl
        for scan_id in [k for k, s in self._sessions.items() if s.created < cutoff]:
            del self._sessions[scan_id]

    def add(self, document: ExtractedDocument, outcome: DetectionOutcome, format_id: str) -> \
            ScanSession:
        session = ScanSession(f"scan_{secrets.token_hex(8)}", document, outcome, format_id)
        with self._lock:
            self._purge()
            while len(self._sessions) >= self._max:
                oldest = min(self._sessions.values(), key=lambda s: s.created)
                del self._sessions[oldest.scan_id]
            self._sessions[session.scan_id] = session
        return session

    def get(self, scan_id: str) -> ScanSession | None:
        with self._lock:
            self._purge()
            return self._sessions.get(scan_id)

    def discard(self, scan_id: str) -> bool:
        with self._lock:
            return self._sessions.pop(scan_id, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def __len__(self) -> int:
        with self._lock:
            self._purge()
            return len(self._sessions)
