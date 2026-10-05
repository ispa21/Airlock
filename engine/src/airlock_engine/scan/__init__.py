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
from typing import Any

from airlock_engine.core.models import Action, ExtractedDocument
from airlock_engine.detectors.pipeline import Detected, DetectionOutcome
from airlock_engine.policy.engine import PolicyDecision, PolicyEngine
from airlock_engine.policy.profiles import Profile

SESSION_TTL_S = 30 * 60
MAX_SESSIONS = 4


def order_findings(outcome: DetectionOutcome) -> tuple[list[tuple[str, Detected]], dict[str, int]]:
    """Stable finding ids (most severe first) and value groups: findings with
    the same entity type and value share a group, so a decision can apply to
    every occurrence without the UI ever seeing the value."""
    ordered = sorted(
        outcome.detected,
        key=lambda d: (-int(d.detection.severity), d.detection.segment_id, d.detection.start),
    )
    items = [(f"f{n}", item) for n, item in enumerate(ordered, start=1)]
    groups: dict[tuple[str, str], int] = {}
    value_group = {
        fid: groups.setdefault(
            (item.detection.entity_type, item.detection.matched_value.reveal()), len(groups) + 1
        )
        for fid, item in items
    }
    return items, value_group


@dataclass
class ScanSession:
    scan_id: str
    document: ExtractedDocument
    outcome: DetectionOutcome
    format_id: str
    policy: PolicyEngine
    profile: Profile
    items: list[tuple[str, Detected]] = field(default_factory=list)
    value_group: dict[str, int] = field(default_factory=dict)
    #: The user's per-finding decisions for this scan (never persisted).
    overrides: dict[str, Action] = field(default_factory=dict)
    #: Mask styles chosen per finding ("partial", ...), alongside MASK overrides.
    styles: dict[str, str] = field(default_factory=dict)
    decision: PolicyDecision | None = None
    #: Report context: entity labels for custom categories, detector status.
    meta: dict[str, Any] = field(default_factory=dict)
    created: float = field(default_factory=time.monotonic)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        if not self.items:
            self.items, self.value_group = order_findings(self.outcome)
        self.redecide()

    def replace_outcome(self, outcome: DetectionOutcome, policy: PolicyEngine) -> None:
        """Swap in fresh detections (after the user taught Airlock something).

        Finding ids change, so the user's decisions are carried over by value:
        a finding with the same type and value keeps its action and style.
        """
        by_value = {
            fid: (item.detection.entity_type, item.detection.matched_value.reveal())
            for fid, item in self.items
        }
        actions = {by_value[f]: a for f, a in self.overrides.items() if f in by_value}
        styles = {by_value[f]: s for f, s in self.styles.items() if f in by_value}
        self.outcome = outcome
        self.policy = policy
        self.items, self.value_group = order_findings(outcome)
        self.overrides, self.styles = {}, {}
        for fid, item in self.items:
            key = (item.detection.entity_type, item.detection.matched_value.reveal())
            if key in actions:
                self.overrides[fid] = actions[key]
            if key in styles:
                self.styles[fid] = styles[key]
        self.redecide()

    def redecide(self) -> PolicyDecision:
        self.decision = self.policy.decide(self.items, self.profile, self.overrides, self.styles)
        return self.decision

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

    def add(
        self,
        document: ExtractedDocument,
        outcome: DetectionOutcome,
        format_id: str,
        policy: PolicyEngine,
        profile: Profile,
    ) -> ScanSession:
        session = ScanSession(
            f"scan_{secrets.token_hex(8)}", document, outcome, format_id, policy, profile
        )
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
