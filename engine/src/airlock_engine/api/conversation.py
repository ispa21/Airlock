"""``conversation.*`` and ``response.*``: conversation scopes and local
restoration of AI responses (Phase 12).

A response is restored from one scope: a conversation (``conversation_id``)
or a protected copy (``artifact_id``). ``response.analyze`` says what a
restore would do without revealing anything; ``response.review`` and
``response.restore`` are the only methods that return original values, and
only on an explicit request. Logs hold counts only.
"""

from __future__ import annotations

from typing import Any

from airlock_engine import safelog
from airlock_engine.api.scan import _Context
from airlock_engine.api.vaults import VaultHolder
from airlock_engine.core import errors
from airlock_engine.ipc.server import InvalidParams, MethodRegistry, RequestContext, require_str
from airlock_engine.masking.conversations import ConversationNotFound
from airlock_engine.masking.restore import Restoration, Restorer
from airlock_engine.masking.vault import VaultEntry, VaultError
from airlock_engine.storage import Storage

#: Text accepted as an AI response, in characters.
MAX_RESPONSE_CHARS = 2_000_000
#: Unknown placeholders listed in a response; the count covers all of them.
MAX_UNKNOWN = 50


def _entries(vaults: VaultHolder, params: dict[str, Any]) -> list[VaultEntry]:
    conversation_id = params.get("conversation_id")
    artifact_id = params.get("artifact_id")
    if (conversation_id is None) == (artifact_id is None):
        raise InvalidParams("give either 'conversation_id' or 'artifact_id'")
    try:
        if conversation_id is not None:
            if not isinstance(conversation_id, str) or len(conversation_id) > 64:
                raise InvalidParams("'conversation_id' must be a string")
            return vaults.conversations.entries(conversation_id)
        record_id = require_str(params, "artifact_id", max_len=64)
        entries = vaults.get().entries(record_id)
    except ConversationNotFound as exc:
        raise errors.conversation_not_found() from exc
    except VaultError as exc:
        raise errors.vault_record_not_found() from exc
    if entries is None:
        raise errors.vault_record_not_found()
    return entries


def _text(params: dict[str, Any]) -> str:
    text = params.get("text")
    if not isinstance(text, str) or len(text) > MAX_RESPONSE_CHARS:
        raise InvalidParams(f"'text' must be a string of at most {MAX_RESPONSE_CHARS} characters")
    return text


def _summary(result: Restoration, entries: list[VaultEntry]) -> dict[str, Any]:
    types = {e.placeholder: e.entity_type for e in entries}
    by_type: dict[str, int] = {}
    for placeholder in result.found:
        by_type[types[placeholder]] = by_type.get(types[placeholder], 0) + 1
    return {
        "placeholders": len(result.found),
        "occurrences": sum(result.found.values()),
        "types": by_type,
        "unknown": result.unknown[:MAX_UNKNOWN],
        "unknown_count": len(result.unknown),
    }


def register(registry: MethodRegistry, storage: Storage, vaults: VaultHolder) -> None:
    conversations = vaults.conversations

    def start(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        conversation_id = conversations.start()
        safelog.log.info("conversation_started")
        return {"conversation_id": conversation_id}

    def status(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        try:
            info, _ = conversations.status_and_entries(
                require_str(params, "conversation_id", max_len=64)
            )
        except ConversationNotFound as exc:
            raise errors.conversation_not_found() from exc
        return info

    def listing(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        return {"conversations": conversations.list()}

    def forget(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        deleted = conversations.forget(require_str(params, "conversation_id", max_len=64))
        if deleted:
            safelog.log.info("conversation_forgotten")
        return {"ok": True, "deleted": deleted}

    def analyze(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """What a restore would do: counts and unknown placeholders, no values."""
        entries = _entries(vaults, params)
        result = Restorer({e.placeholder: e.original for e in entries}).analyze(_text(params))
        return _summary(result, entries)

    def review(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """The placeholders in a response and what each would become."""
        entries = _entries(vaults, params)
        result = Restorer({e.placeholder: e.original for e in entries}).analyze(_text(params))
        labels = _Context(storage).entities()
        by_placeholder = {e.placeholder: e for e in entries}
        items = []
        for placeholder, count in result.found.items():
            entry = by_placeholder[placeholder]
            info = labels.get(entry.entity_type)
            items.append(
                {
                    "placeholder": placeholder,
                    "original": entry.original,
                    "entity_type": entry.entity_type,
                    "entity_label": info.label if info else entry.entity_type,
                    "count": count,
                }
            )
        safelog.log.info("response_reviewed", entity_count=len(items))
        return {**_summary(result, entries), "items": items}

    def restore(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Put the original values back into an AI response, on this device."""
        entries = _entries(vaults, params)
        result = Restorer({e.placeholder: e.original for e in entries}).restore(_text(params))
        safelog.log.info(
            "response_restored", entity_count=result.restored, remaining_count=len(result.unknown)
        )
        return {**_summary(result, entries), "text": result.text, "restored": result.restored}

    registry.register("conversation.start", start)
    registry.register("conversation.status", status)
    registry.register("conversation.list", listing)
    registry.register("conversation.forget", forget)
    registry.register("response.analyze", analyze)
    registry.register("response.review", review)
    registry.register("response.restore", restore)
