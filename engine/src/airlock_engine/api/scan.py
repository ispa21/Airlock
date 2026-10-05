"""``scan.*`` methods: extract → detect → policy, keeping results in engine memory."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.core.models import Action, Category, ExtractedDocument
from airlock_engine.detectors import ner
from airlock_engine.detectors.custom import CompanyRule, RuleError
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.detectors.pipeline import DetectionCancelled, DetectionEngine, DetectionOutcome
from airlock_engine.extraction.context import ExtractionOptions
from airlock_engine.extraction.service import extract_path
from airlock_engine.extraction.summary import summarize
from airlock_engine.ipc.server import (
    InvalidParams,
    MethodRegistry,
    RequestCancelled,
    RequestContext,
    require_str,
)
from airlock_engine.masking.artifacts import ArtifactStore
from airlock_engine.masking.replacements import partial_allowed
from airlock_engine.policy.engine import PolicyEngine, is_high_risk
from airlock_engine.policy.profiles import (
    BUILTIN_PROFILES,
    DEFAULT_PROFILE_ID,
    MASK_STYLES,
    Profile,
)
from airlock_engine.scan import ScanSession, SessionStore
from airlock_engine.scan.report import EntityInfo, build_report, entity_info
from airlock_engine.storage import ProfileNotFound, Storage, StorageError

#: Overrides accepted in one call (each may target a whole value group).
MAX_OVERRIDES = 5_000


def _flag(params: dict[str, Any], key: str, default: bool = True) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be a boolean")
    return value


def _action(value: object) -> Action | None:
    if value is None:
        return None
    if not isinstance(value, str) or value not in Action.__members__:
        raise InvalidParams("'action' must be ALLOW, MASK, REDACT, GENERALIZE, BLOCK or null")
    return Action(value)


class _Context:
    """Rules, categories and profiles loaded from storage for one scan."""

    def __init__(self, storage: Storage) -> None:
        self.rules: list[CompanyRule] = []
        self.custom: dict[str, EntityInfo] = {}
        self.rule_actions: dict[str, Action] = {}
        self.allow: Any = None
        self.storage_ok = True
        try:
            store = storage.rules
            self.custom = {
                c.id: EntityInfo(c.label, c.group, "company_rule")
                for c in store.categories()
                if c.id not in BUILTIN_ENTITIES
            }
            self.rules = store.compiled()
            self.rule_actions = store.rule_actions()
            self.allow = storage.allow_list
        except StorageError:
            # Scanning must still work without the database; rules are reported as absent.
            safelog.log.warning("storage_unavailable")
            self.storage_ok = False

    def entities(self) -> dict[str, EntityInfo]:
        return entity_info(self.custom)

    def policy(self) -> PolicyEngine:
        entities = self.entities()
        return PolicyEngine(
            categories={k: Category(v.category) for k, v in entities.items()},
            labels={k: v.label for k, v in entities.items()},
            rule_actions=self.rule_actions,
        )


def _profile(storage: Storage, profile_id: str | None) -> Profile:
    try:
        store = storage.profiles
        return store.get(profile_id or store.default_id())
    except ProfileNotFound as exc:
        raise errors.profile_not_found() from exc
    except StorageError:
        if profile_id in (None, *BUILTIN_PROFILES):
            return BUILTIN_PROFILES[profile_id or DEFAULT_PROFILE_ID]
        raise errors.storage_unavailable() from None


def _reload(storage: Storage, current: Profile) -> Profile:
    """The session's profile as stored now: it may have been edited or deleted."""
    try:
        return storage.profiles.get(current.id)
    except ProfileNotFound:
        return _profile(storage, None)
    except StorageError:
        return current


def register(
    registry: MethodRegistry, storage: Storage, sessions: SessionStore, artifacts: ArtifactStore
) -> None:
    def respond(session: ScanSession) -> dict[str, Any]:
        meta = session.meta
        return build_report(
            session,
            meta.get("entities") or entity_info({}),
            ner_status=meta.get("ner_status", "disabled"),
            rule_count=meta.get("rule_count", 0),
        )

    def detect(
        document: ExtractedDocument, use_ner: bool, ctx: RequestContext
    ) -> tuple[DetectionOutcome, _Context, str, float]:
        """Run every detector with the current rules and allow-list."""
        started = time.perf_counter()
        context = _Context(storage)
        provider = None
        ner_status = "disabled"
        if use_ner:
            ctx.progress("prepare", 0, 1)
            provider = ner.shared_provider()
            ner_status = "used" if provider is not None else "unavailable"
        allow = context.allow
        engine = DetectionEngine(
            rules=context.rules,
            ner=provider,
            allow=allow.contains if allow is not None and allow.count() else None,
        )
        try:
            outcome = engine.run(document, progress=ctx.progress, cancelled=lambda: ctx.cancelled)
        except DetectionCancelled as exc:
            safelog.log.info("scan_cancelled")
            raise RequestCancelled from exc
        if outcome.ner_truncated:
            ner_status = "partial"
        return outcome, context, ner_status, (time.perf_counter() - started) * 1000

    def refresh_session(session: ScanSession, ctx: RequestContext) -> dict[str, Any]:
        outcome, context, ner_status, _ = detect(
            session.document, bool(session.meta.get("use_ner", True)), ctx
        )
        with session.lock:
            session.profile = _reload(storage, session.profile)
            session.replace_outcome(outcome, context.policy())
            session.meta.update(
                entities=context.entities(), ner_status=ner_status, rule_count=len(context.rules)
            )
            return {"scan_id": session.scan_id, **respond(session)}

    def start(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Extract the file in an isolated worker, run every detector, apply
        the privacy profile. Returns findings with masked previews and
        actions; raw values stay in the session."""
        path = require_str(params, "path")
        options = ExtractionOptions(ocr=_flag(params, "ocr"))
        use_ner = _flag(params, "ner")
        profile_id = params.get("profile_id")
        if profile_id is not None and (not isinstance(profile_id, str) or len(profile_id) > 64):
            raise InvalidParams("'profile_id' must be a string")
        profile = _profile(storage, profile_id)
        extraction = extract_path(path, options, ctx)
        ctx.raise_if_cancelled()

        outcome, context, ner_status, detect_ms = detect(extraction.document, use_ner, ctx)
        safelog.log.debug("scan_detected", file_type=extraction.spec.format_id)

        session = sessions.add(
            extraction.document, outcome, extraction.spec.format_id, context.policy(), profile
        )
        # Labels of custom categories as they were at scan time.
        session.meta.update(
            entities=context.entities(),
            ner_status=ner_status,
            use_ner=use_ner,
            rule_count=len(context.rules),
            # Needed to create the protected copy from exactly these bytes.
            path=extraction.path,
            sha256=extraction.sha256,
            extension=extraction.extension,
            name=Path(extraction.path).name,
            format_label=extraction.spec.label,
        )
        report = respond(session)
        _log_scan(report, extraction.spec.format_id, detect_ms)
        return {
            "scan_id": session.scan_id,
            "extraction": summarize(extraction.document, extraction.spec, extraction.duration_ms),
            "findings": report["findings"],
            "summary": report["summary"],
            "policy": report["policy"],
            "detection_ms": round(detect_ms),
            "risk": report["risk"],
        }

    def get_session(params: dict[str, Any]) -> ScanSession:
        session = sessions.get(require_str(params, "scan_id", max_len=64))
        if session is None:
            raise errors.scan_not_found()
        return session

    def set_profile(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Re-apply a different profile to a finished scan. The user's own
        decisions for this scan are kept."""
        session = get_session(params)
        profile = _profile(storage, require_str(params, "profile_id", max_len=64))
        with session.lock:
            session.profile = profile
            session.redecide()
            report = respond(session)
        safelog.log.info("policy_applied", finding_count=report["summary"]["total"])
        return {"scan_id": session.scan_id, **report}

    def override(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Change the action for findings in this scan.

        Each entry targets one ``finding_id`` or a whole ``value_group`` (every
        occurrence of the same value); ``action: null`` returns it to the
        profile's decision. Keeping a critical finding (``ALLOW``) requires
        ``acknowledge_risk: true``. Nothing is applied if any entry is invalid.
        """
        session = get_session(params)
        raw = params.get("overrides")
        if not isinstance(raw, list) or not raw or len(raw) > MAX_OVERRIDES:
            raise InvalidParams("'overrides' must be a non-empty list")
        acknowledged = _flag(params, "acknowledge_risk", default=False)
        groups: dict[int, list[str]] = {}
        for fid, group in session.value_group.items():
            groups.setdefault(group, []).append(fid)
        by_id = {fid: item.detection for fid, item in session.items}
        with session.lock:
            decision = session.decision or session.redecide()
            categories = {f.finding_id: f.category for f in decision.findings}
            changes: dict[str, Action | None] = {}
            style_changes: dict[str, str | None] = {}
            for entry in raw:
                if not isinstance(entry, dict):
                    raise InvalidParams("each override must be an object")
                action = _action(entry.get("action"))
                if "finding_id" in entry:
                    fid = entry["finding_id"]
                    if not isinstance(fid, str) or fid not in by_id:
                        raise errors.finding_not_found()
                    targets = [fid]
                elif "value_group" in entry:
                    group = entry["value_group"]
                    if not isinstance(group, int) or isinstance(group, bool) or group not in groups:
                        raise errors.finding_not_found()
                    targets = groups[group]
                else:
                    raise InvalidParams("each override needs 'finding_id' or 'value_group'")
                style = entry.get("mask_style")
                if style is not None and (
                    not isinstance(style, str)
                    or style not in MASK_STYLES
                    or action is not Action.MASK
                ):
                    raise InvalidParams("'mask_style' needs action MASK and a known style")
                for fid in targets:
                    if style == "partial" and not partial_allowed(by_id[fid].entity_type):
                        raise InvalidParams("partial masking is not available for credentials")
                    if (
                        action is Action.ALLOW
                        and is_high_risk(by_id[fid].severity, categories[fid])
                        and not acknowledged
                    ):
                        raise errors.confirmation_required()
                    changes[fid] = action
                    style_changes[fid] = style
            for fid, change in changes.items():
                if change is None:
                    session.overrides.pop(fid, None)
                else:
                    session.overrides[fid] = change
                if style_changes.get(fid) is None:
                    session.styles.pop(fid, None)
                else:
                    session.styles[fid] = str(style_changes[fid])
            session.redecide()
            report = respond(session)
        safelog.log.info("policy_overridden", finding_count=len(changes))
        return {"scan_id": session.scan_id, **report}

    def refresh(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Re-run detection on the scanned text (no re-reading of the file)
        with the current company rules, allow-list and profile, e.g. after
        settings changed. The user's decisions for this scan carry over."""
        result = refresh_session(get_session(params), ctx)
        safelog.log.info("scan_refreshed", finding_count=result["summary"]["total"])
        return result

    def teach(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Teach Airlock from one finding, then refresh the scan.

        * ``not_sensitive``: never flag this value again (allow-list; stored as
          a keyed hash). Not available for credentials.
        * ``company_rule``: always protect this value, in every document, as a
          company rule (``category_id``, ``match``: normalized | exact |
          case_insensitive, optional ``action``).
        """
        session = get_session(params)
        kind = require_str(params, "kind", max_len=32)
        finding_id = require_str(params, "finding_id", max_len=32)
        item = next((d for fid, d in session.items if fid == finding_id), None)
        if item is None:
            raise errors.finding_not_found()
        d = item.detection
        decision = session.decision or session.redecide()
        category = next(
            (f.category for f in decision.findings if f.finding_id == finding_id), Category.OTHER
        )
        if category is Category.CREDENTIALS:
            raise errors.cannot_teach_credential()
        if d.detector.startswith("custom."):
            # The rule already decides; the allow-list must not silently undo it.
            raise errors.cannot_teach_rule_match()
        value = d.matched_value.reveal()
        try:
            if kind == "not_sensitive":
                storage.allow_list.add(d.entity_type, value)
            elif kind == "company_rule":
                match = params.get("match", "normalized")
                if match not in ("normalized", "exact", "case_insensitive"):
                    raise InvalidParams("'match' must be normalized, exact or case_insensitive")
                chosen = _action(params.get("action"))
                storage.rules.create(
                    kind=str(match),
                    pattern=value,
                    category_id=str(params.get("category_id") or "CONFIDENTIAL_TERM"),
                    action=chosen.value if chosen is not None else None,
                )
            else:
                raise InvalidParams("'kind' must be not_sensitive or company_rule")
        except RuleError as exc:
            raise errors.invalid_rule(str(exc)) from exc
        except StorageError as exc:
            raise errors.storage_unavailable() from exc
        safelog.log.info("airlock_taught", status=kind)
        return refresh_session(session, ctx)

    def allowlist_status(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        try:
            return {"count": storage.allow_list.count()}
        except StorageError as exc:
            raise errors.storage_unavailable() from exc

    def allowlist_clear(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Forget every "not sensitive" decision (values are flagged again)."""
        try:
            storage.allow_list.clear()
        except StorageError as exc:
            raise errors.storage_unavailable() from exc
        safelog.log.info("allowlist_cleared")
        return {"ok": True, "count": 0}

    def discard(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Forget a scan's document text, findings and decisions."""
        scan_id = require_str(params, "scan_id", max_len=64)
        discarded = sessions.discard(scan_id)
        artifacts.discard_scan(scan_id)
        return {"ok": True, "discarded": discarded}

    registry.register("scan.start", start)
    registry.register("scan.set_profile", set_profile)
    registry.register("scan.override", override)
    registry.register("scan.refresh", refresh)
    registry.register("scan.teach", teach)
    registry.register("scan.discard", discard)
    registry.register("allowlist.status", allowlist_status)
    registry.register("allowlist.clear", allowlist_clear)


def _log_scan(report: dict[str, Any], file_type: str, detect_ms: float) -> None:
    summary = report["summary"]
    safelog.log.info(
        "scan_completed",
        file_type=file_type,
        finding_count=summary["total"],
        duration_ms=round(detect_ms),
    )
    for row in summary["by_entity"]:
        # Custom category ids are derived from company labels: log them only as "custom".
        entity_type = row["entity_type"] if row["entity_type"] in BUILTIN_ENTITIES else "custom"
        safelog.log.debug("scan_entity", entity_type=entity_type.lower(), entity_count=row["count"])
    for action, count in report["policy"]["actions"].items():
        if count:
            safelog.log.debug("policy_action", status=action.lower(), finding_count=count)
