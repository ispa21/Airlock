"""Conversations: the scope in which placeholders stay stable (Phase 12).

A conversation is the text a person exchanges with one AI chat: every prompt
protected in it reuses the placeholders issued earlier (``PERSON_001`` stays
Rahul Sharma for the whole conversation), and the AI's responses are restored
from its mapping. A protected copy can join a conversation (an opt-in privacy
workspace) so a document and the prompts about it share placeholders.

The mapping is a vault record named after the conversation id
(``AIRLOCK-2026-001928``): AES-256-GCM encrypted, never logged, never sent.
"""

from __future__ import annotations

import re
import secrets
import threading
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from typing import Any

from airlock_engine.masking.replacements import Seed
from airlock_engine.masking.vault import Vault, VaultEntry

CONVERSATION_ID = re.compile(r"^AIRLOCK-[0-9]{4}-[0-9]{6}$")
KIND = "conversation"


class ConversationNotFound(LookupError):
    pass


def as_seed(entries: Sequence[VaultEntry]) -> list[Seed]:
    return [
        (e.placeholder, e.original, e.entity_type, e.style or "typed_placeholder") for e in entries
    ]


def as_entries(seed: Sequence[Seed]) -> list[VaultEntry]:
    return [VaultEntry(text, value, entity_type, style) for text, value, entity_type, style in seed]


class Conversations:
    def __init__(self, vault: Callable[[], Vault]) -> None:
        self._vault = vault
        self._guard = threading.Lock()
        self._locks: dict[str, threading.Lock] = {}

    def start(self) -> str:
        vault = self._vault()
        year = time.localtime().tm_year
        with self._guard:
            while True:
                conversation_id = f"AIRLOCK-{year}-{secrets.randbelow(1_000_000):06d}"
                if not vault.exists(conversation_id):
                    break
            now = time.time()
            vault.put(conversation_id, [], {"kind": KIND, "started": now, "updated": now})
        return conversation_id

    @contextmanager
    def open(self, conversation_id: str) -> Iterator[list[Seed]]:
        """Hold the conversation while text is protected in it. The caller
        extends the yielded list in place; it is saved when the block ends."""
        if not CONVERSATION_ID.match(conversation_id):
            raise ConversationNotFound(conversation_id)
        with self._guard:
            lock = self._locks.setdefault(conversation_id, threading.Lock())
        with lock:
            vault = self._vault()
            found = vault.record(conversation_id)
            if found is None or found[1].get("kind") != KIND:
                raise ConversationNotFound(conversation_id)
            entries, meta = found
            seed = as_seed(entries)
            before = len(seed)
            yield seed
            if len(seed) != before:
                meta["updated"] = time.time()
                vault.put(conversation_id, as_entries(seed), _meta(meta))

    def entries(self, conversation_id: str) -> list[VaultEntry]:
        return self.status_and_entries(conversation_id)[1]

    def status_and_entries(self, conversation_id: str) -> tuple[dict[str, Any], list[VaultEntry]]:
        if not CONVERSATION_ID.match(conversation_id):
            raise ConversationNotFound(conversation_id)
        found = self._vault().record(conversation_id)
        if found is None or found[1].get("kind") != KIND:
            raise ConversationNotFound(conversation_id)
        entries, meta = found
        return _status(conversation_id, meta, entries), entries

    def list(self) -> list[dict[str, Any]]:
        vault = self._vault()
        out = []
        for record_id in vault.ids():
            if not CONVERSATION_ID.match(record_id):
                continue
            found = vault.record(record_id)
            if found is not None and found[1].get("kind") == KIND:
                out.append(_status(record_id, found[1], found[0]))
        return sorted(out, key=lambda c: c["updated"] or 0, reverse=True)

    def forget(self, conversation_id: str) -> bool:
        if not CONVERSATION_ID.match(conversation_id):
            return False
        with self._guard:
            self._locks.pop(conversation_id, None)
        return self._vault().forget(conversation_id)


def _meta(meta: dict[str, Any]) -> dict[str, Any]:
    return {"kind": KIND, "started": meta.get("started"), "updated": meta.get("updated")}


def _status(
    conversation_id: str, meta: dict[str, Any], entries: list[VaultEntry]
) -> dict[str, Any]:
    """Content-free description: ids, times and counts."""
    types: dict[str, int] = {}
    for e in entries:
        types[e.entity_type] = types.get(e.entity_type, 0) + 1
    started = meta.get("started")
    return {
        "conversation_id": conversation_id,
        "started": started,
        "updated": meta.get("updated") or started,
        "placeholders": len(entries),
        "types": types,
    }
