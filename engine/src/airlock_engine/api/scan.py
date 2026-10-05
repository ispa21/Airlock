"""``scan.*`` methods: extract → detect, keeping results in engine memory."""

from __future__ import annotations

import time
from typing import Any

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.detectors import ner
from airlock_engine.detectors.custom import CompanyRule
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.detectors.pipeline import DetectionCancelled, DetectionEngine
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
from airlock_engine.scan import SessionStore
from airlock_engine.scan.report import EntityInfo, build_report, entity_info
from airlock_engine.storage import Storage, StorageError


def _flag(params: dict[str, Any], key: str, default: bool = True) -> bool:
    value = params.get(key, default)
    if not isinstance(value, bool):
        raise InvalidParams(f"'{key}' must be a boolean")
    return value


def register(registry: MethodRegistry, storage: Storage, sessions: SessionStore) -> None:
    def load_rules() -> tuple[list[CompanyRule], dict[str, EntityInfo], Any]:
        try:
            store = storage.rules
            custom = {
                c.id: EntityInfo(c.label, c.group, "company_rule")
                for c in store.categories()
                if c.id not in BUILTIN_ENTITIES
            }
            return store.compiled(), custom, storage.allow_list
        except StorageError:
            # Scanning must still work without the database; rules are reported as absent.
            safelog.log.warning("storage_unavailable")
            return [], {}, None

    def start(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Extract the file in an isolated worker, then run every detector.

        Returns findings with masked previews. Raw values stay in the session.
        """
        path = require_str(params, "path")
        options = ExtractionOptions(ocr=_flag(params, "ocr"))
        use_ner = _flag(params, "ner")
        extraction = extract_path(path, options, ctx)
        ctx.raise_if_cancelled()

        started = time.perf_counter()
        rules, custom_entities, allow = load_rules()
        provider = None
        ner_status = "disabled"
        if use_ner:
            ctx.progress("prepare", 0, 1)
            provider = ner.shared_provider()
            ner_status = "used" if provider is not None else "unavailable"
        engine = DetectionEngine(
            rules=rules,
            ner=provider,
            allow=allow.contains if allow is not None and allow.count() else None,
        )
        try:
            outcome = engine.run(
                extraction.document, progress=ctx.progress, cancelled=lambda: ctx.cancelled
            )
        except DetectionCancelled as exc:
            safelog.log.info("scan_cancelled", file_type=extraction.spec.format_id)
            raise RequestCancelled from exc
        if outcome.ner_truncated:
            ner_status = "partial"
        detect_ms = (time.perf_counter() - started) * 1000

        session = sessions.add(extraction.document, outcome, extraction.spec.format_id)
        report = build_report(
            session, entity_info(custom_entities), ner_status=ner_status, rule_count=len(rules)
        )
        _log_scan(report, extraction.spec.format_id, detect_ms)
        return {
            "scan_id": session.scan_id,
            "extraction": summarize(extraction.document, extraction.spec, extraction.duration_ms),
            "findings": report["findings"],
            "summary": report["summary"],
            "detection_ms": round(detect_ms),
            # Deterministic, explainable risk scoring arrives in Phase 6.
            "risk": None,
        }

    def discard(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        """Forget a scan's document text and findings."""
        discarded = sessions.discard(require_str(params, "scan_id", max_len=64))
        return {"ok": True, "discarded": discarded}

    registry.register("scan.start", start)
    registry.register("scan.discard", discard)


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


__all__ = ["errors", "register"]
