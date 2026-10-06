"""``text.protect``: protect a piece of text (a prompt, a selection, an e-mail).

Used by the browser extension (Phase 11) and later by prompt and clipboard
protection (Phase 12). The text goes through the same detectors, company
rules, allow-list and privacy profile as a document; every protected value
is replaced, including repeats the detectors did not flag themselves.

Text is never stored. Items the profile blocks (passwords, keys, tokens)
cannot be shared as they are, so they are redacted and counted as ``blocked``.
Findings leave as masked previews only.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from airlock_engine import safelog
from airlock_engine.api.scan import _profile, detect_document
from airlock_engine.core.models import Action, ExtractedDocument, Locator, SegmentKind, TextSegment
from airlock_engine.ipc.server import InvalidParams, MethodRegistry, RequestContext
from airlock_engine.masking.replacements import Replacer
from airlock_engine.masking.sweep import Sweeper, splice
from airlock_engine.scan.report import EntityInfo, preview
from airlock_engine.storage import Storage

#: Longest text accepted, in characters (a long prompt or a few pages).
MAX_TEXT_CHARS = 200_000
#: Findings listed in a response; the counts always cover all of them.
MAX_LISTED = 200


def _flag(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be a boolean")
    return value


def register(registry: MethodRegistry, storage: Storage) -> None:
    def protect(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        text = params.get("text")
        if not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            raise InvalidParams(f"'text' must be a string of at most {MAX_TEXT_CHARS} characters")
        profile_id = params.get("profile_id")
        if profile_id is not None and (not isinstance(profile_id, str) or len(profile_id) > 64):
            raise InvalidParams("'profile_id' must be a string")
        use_ner = _flag(params, "ner", True)

        document = ExtractedDocument(
            "text", (TextSegment(0, text, Locator("text", "0"), SegmentKind.BODY, "Text"),)
        )
        outcome, context, ner_status, _ = detect_document(storage, document, use_ner, ctx)
        profile = _profile(storage, profile_id)
        items = [(f"f{i}", d) for i, d in enumerate(outcome.detected, start=1)]
        decision = context.policy().decide(items, profile)
        findings = {f.finding_id: f for f in decision.findings}
        entities: dict[str, EntityInfo] = context.entities()

        replacer = Replacer(text)
        edits: list[tuple[int, int, str]] = []
        pairs: list[tuple[str, str]] = []
        blocked = 0
        for region in decision.regions:
            primary = findings[region.primary_id]
            action = region.action
            if action is Action.BLOCK:
                # Not shareable as it is: removed from the text, and reported.
                action, blocked = Action.REDACT, blocked + 1
            value = text[region.start : region.end]
            replacement = replacer.text_for(
                primary.detection.entity_type, value, action, region.mask_style
            )
            edits.append((region.start, region.end, replacement))
            pairs.append((value, replacement))
        protected = Sweeper(pairs).apply(splice(text, edits)) if edits else text

        counts: Counter[str] = Counter()
        listed: list[dict[str, Any]] = []
        for f in decision.findings:
            d = f.detection
            effective = f.effective_action or f.action
            counts[effective.value] += 1
            if len(listed) < MAX_LISTED:
                info = entities.get(d.entity_type) or EntityInfo(
                    d.entity_type, "OTHER", "company_rule"
                )
                listed.append(
                    {
                        "entity_type": d.entity_type,
                        "entity_label": info.label,
                        "category": info.category,
                        "preview": preview(d.entity_type, info.quality, d.matched_value.reveal()),
                        "action": effective.value,
                    }
                )
        safelog.log.info(
            "text_protected",
            finding_count=len(decision.findings),
            entity_count=len(edits),
            size_bytes=len(text.encode("utf-8", "surrogatepass")),
        )
        return {
            "text": protected,
            "changed": len(edits),
            "blocked": blocked,
            "actions": dict(counts),
            "findings": listed,
            "profile": {"id": profile.id, "name": profile.name},
            "ner": ner_status,
        }

    registry.register("text.protect", protect)
