"""``text.protect``: protect a piece of text (a prompt, a selection, an e-mail).

Used by the browser extension (Phase 11) and by prompt and clipboard
protection in the app (Phase 12). The text goes through the same detectors,
company rules, allow-list and privacy profile as a document; every protected
value is replaced, including repeats the detectors did not flag themselves.

Privacy modes (chosen before anything is sent):

* ``reversible`` (default): placeholders such as ``PERSON_001``; with a
  conversation they are stored in its vault record so the AI's response can
  be restored, and the same value keeps its placeholder in every turn.
* ``synthetic``: realistic stand-ins where a safe reserved form exists
  (``person1@example.invalid``), placeholders otherwise; also reversible.
* ``redact``: ``[REDACTED]``; nothing is stored and nothing can be restored.
* ``block``: if anything sensitive is found, no text is returned at all.

Every result is checked again before it can be sent (the outbound check):
the protected text is scanned a second time, and any original value still in
it, or anything sensitive the first pass did not protect, stops it.

Text is never stored. Items the profile blocks (passwords, keys, tokens)
cannot be shared as they are, so they are redacted and counted as ``blocked``.
Findings leave as masked previews only.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from airlock_engine import safelog
from airlock_engine.api.scan import _profile, detect_document
from airlock_engine.api.vaults import VaultHolder
from airlock_engine.core import errors
from airlock_engine.core.models import Action, ExtractedDocument, Locator, SegmentKind, TextSegment
from airlock_engine.ipc.server import InvalidParams, MethodRegistry, RequestContext
from airlock_engine.masking.conversations import ConversationNotFound
from airlock_engine.masking.replacements import REDACTED, Replacer, Seed
from airlock_engine.masking.sweep import Sweeper, splice
from airlock_engine.masking.vault import VaultError
from airlock_engine.policy.engine import PolicyDecision
from airlock_engine.scan.report import EntityInfo, preview
from airlock_engine.storage import Storage
from airlock_engine.verification.verifier import FAILED, PASSED, CopyCheck, evaluate, normalize

#: Longest text accepted, in characters (a long prompt or a few pages).
MAX_TEXT_CHARS = 200_000
#: Findings listed in a response; the counts always cover all of them.
MAX_LISTED = 200
MODES = ("reversible", "synthetic", "redact", "block")
#: Outbound check results as the UI shows them.
CHECK_STATUS = {PASSED: "safe", FAILED: "blocked"}


def _flag(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be a boolean")
    return value


def _document(text: str) -> ExtractedDocument:
    return ExtractedDocument(
        "text", (TextSegment(0, text, Locator("text", "0"), SegmentKind.BODY, "Text"),)
    )


def _listed(
    decision: PolicyDecision, entities: dict[str, EntityInfo]
) -> tuple[Counter[str], list[dict[str, Any]]]:
    counts: Counter[str] = Counter()
    listed: list[dict[str, Any]] = []
    for f in decision.findings:
        d = f.detection
        effective = f.effective_action or f.action
        counts[effective.value] += 1
        if len(listed) < MAX_LISTED:
            info = entities.get(d.entity_type) or EntityInfo(d.entity_type, "OTHER", "company_rule")
            listed.append(
                {
                    "entity_type": d.entity_type,
                    "entity_label": info.label,
                    "category": info.category,
                    "preview": preview(d.entity_type, info.quality, d.matched_value.reveal()),
                    "action": effective.value,
                }
            )
    return counts, listed


class _Protection:
    """Replaces every protected value in one text (holds original values)."""

    def __init__(self, text: str, decision: PolicyDecision, mode: str, seed: list[Seed]) -> None:
        self.text = text
        self.blocked = 0
        self.protected: list[tuple[str, str]] = []
        self.inserted: set[str] = set()
        findings = {f.finding_id: f for f in decision.findings}
        replacer = Replacer(text, seed)
        edits: list[tuple[int, int, str]] = []
        pairs: list[tuple[str, str]] = []
        for region in decision.regions:
            primary = findings[region.primary_id]
            action, style = region.action, region.mask_style
            if action is Action.BLOCK:
                # Not shareable as it is: removed from the text, and reported.
                action, self.blocked = Action.REDACT, self.blocked + 1
            elif mode == "redact" and action in (Action.MASK, Action.GENERALIZE):
                action = Action.REDACT
            elif mode == "synthetic" and action is Action.MASK:
                style = "synthetic"
            value = text[region.start : region.end]
            replacement = replacer.text_for(primary.detection.entity_type, value, action, style)
            edits.append((region.start, region.end, replacement))
            pairs.append((value, replacement))
            self.protected.append((value, primary.detection.entity_type))
        # Values protected earlier in the conversation stay protected in this
        # turn even where the detectors do not flag them again.
        for placeholder, value, entity_type, _ in seed:
            pairs.append((value, REDACTED if mode == "redact" else placeholder))
            self.protected.append((value, entity_type))
        sweep = Sweeper(pairs)
        flagged = [(s, e) for s, e, _ in edits]
        for start, end, replacement in sweep.find(text):
            if not any(s < end and start < e for s, e in flagged):
                edits.append((start, end, replacement))
        self.edits = edits
        self.output = splice(text, edits) if edits else text
        self.inserted = {replacement for *_, replacement in edits}
        self.mappings = replacer.mappings()
        #: Distinct reversible placeholders (or stand-ins) in the output.
        self.placeholders = len(self.inserted & set(replacer.reversible))

    def __repr__(self) -> str:
        return f"_Protection(edits={len(self.edits)})"


def register(registry: MethodRegistry, storage: Storage, vaults: VaultHolder) -> None:
    def protect(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        text = params.get("text")
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            raise InvalidParams(f"'text' must be a string of at most {MAX_TEXT_CHARS} characters")
        profile_id = params.get("profile_id")
        if profile_id is not None and (not isinstance(profile_id, str) or len(profile_id) > 64):
            raise InvalidParams("'profile_id' must be a string")
        mode = params.get("mode", "reversible")
        if mode not in MODES:
            raise InvalidParams(f"'mode' must be one of {', '.join(MODES)}")
        conversation_id = params.get("conversation_id")
        if conversation_id is not None and (
            not isinstance(conversation_id, str) or len(conversation_id) > 64
        ):
            raise InvalidParams("'conversation_id' must be a string")
        use_ner = _flag(params, "ner", True)

        outcome, context, ner_status, _ = detect_document(storage, _document(text), use_ner, ctx)
        profile = _profile(storage, profile_id)
        items = [(f"f{i}", d) for i, d in enumerate(outcome.detected, start=1)]
        decision = context.policy().decide(items, profile)
        entities: dict[str, EntityInfo] = context.entities()
        counts, listed = _listed(decision, entities)
        response: dict[str, Any] = {
            "mode": mode,
            "conversation_id": conversation_id,
            "actions": dict(counts),
            "findings": listed,
            "profile": {"id": profile.id, "name": profile.name},
            "ner": ner_status,
        }

        sensitive = sum(n for action, n in counts.items() if action != Action.ALLOW.value)
        if mode == "block" and sensitive:
            safelog.log.info("text_withheld", finding_count=sensitive)
            return {
                **response,
                "text": None,
                "withheld": True,
                "changed": 0,
                "blocked": sensitive,
                "check": None,
            }

        try:
            if conversation_id is None:
                done = _Protection(text, decision, mode, [])
            else:
                with vaults.conversations.open(conversation_id) as seed:
                    done = _Protection(text, decision, mode, list(seed))
                    if mode != "redact":
                        known = {s[0] for s in seed}
                        seed.extend(m for m in done.mappings if m[0] not in known)
        except ConversationNotFound as exc:
            raise errors.conversation_not_found() from exc
        except VaultError as exc:
            raise errors.vault_unavailable() from exc

        # The outbound check: scan the result again before it can be sent.
        second, _, _, _ = detect_document(storage, _document(done.output), use_ner, ctx)
        kept = frozenset(
            normalize(f.detection.matched_value.reveal())
            for f in decision.findings
            if (f.effective_action or f.action) is Action.ALLOW
        )
        verdict = evaluate(
            _document(done.output),
            [],
            second.detected,
            CopyCheck(done.protected, frozenset(done.inserted), kept, use_ner=use_ner),
            entities,
        )
        summary = verdict.to_json()
        safelog.log.info(
            "text_protected",
            finding_count=len(decision.findings),
            entity_count=len(done.edits),
            remaining_count=summary["remaining_count"] + summary["new_count"],
            size_bytes=len(text.encode("utf-8", "surrogatepass")),
        )
        return {
            **response,
            "text": done.output,
            "withheld": False,
            "changed": len(done.edits),
            "blocked": done.blocked,
            "placeholders": done.placeholders,
            "check": {
                "status": CHECK_STATUS.get(verdict.status, "review"),
                "remaining_count": summary["remaining_count"],
                "new_count": summary["new_count"],
                "remaining": summary["remaining"],
                "kept_count": summary["kept_count"],
            },
        }

    registry.register("text.protect", protect)
