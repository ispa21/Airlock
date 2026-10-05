"""Builds the content-free scan result sent to the UI.

Raw matched values never leave this module: each finding carries a masked
preview, a structural location label and ids only.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from airlock_engine.core.models import Category, SegmentKind, Severity
from airlock_engine.core.sensitive import mask_preview
from airlock_engine.detectors.entities import BUILTIN_ENTITIES, QualityClass
from airlock_engine.detectors.pipeline import DetectionOutcome
from airlock_engine.policy.engine import is_high_risk
from airlock_engine.policy.profiles import GENERALIZABLE
from airlock_engine.scan import ScanSession

#: Findings listed individually in one response; the summary always counts all.
MAX_LISTED_FINDINGS = 2_000

_BULLETS = "••••••••"
#: Public, non-secret prefixes that help a user recognise which credential it is.
_SECRET_PREFIXES = (
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "glpat-",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "xoxo-",
    "sk_live_",
    "sk_test_",
    "rk_live_",
    "rk_test_",
    "pk_live_",
    "pk_test_",
    "sk-ant-",
    "sk-proj-",
    "sk-",
    "AKIA",
    "ASIA",
    "AIza",
    "SG.",
    "npm_",
    "eyJ",
    "https://hooks.slack.com/",
)
_LAST4_TYPES = frozenset({"AADHAAR", "CREDIT_CARD", "BANK_ACCOUNT", "IBAN"})
#: Segment kinds a reader sees when opening the file normally.
_VISIBLE_KINDS = frozenset(
    {SegmentKind.BODY, SegmentKind.HEADER_FOOTER, SegmentKind.OCR, SegmentKind.NAME}
)

SEVERITY_LABELS = {
    Severity.LOW: "low",
    Severity.MEDIUM: "medium",
    Severity.HIGH: "high",
    Severity.CRITICAL: "critical",
}


@dataclass(frozen=True, slots=True)
class EntityInfo:
    label: str
    category: str
    quality: str


def preview(entity_type: str, quality: QualityClass | str, value: str) -> str:
    """Masked preview: enough shape to recognise the finding, never enough to use it."""
    if quality == QualityClass.SECRET:
        if entity_type == "PRIVATE_KEY":
            return "-----BEGIN " + _BULLETS + " PRIVATE KEY-----"
        prefix = next((p for p in _SECRET_PREFIXES if value.startswith(p)), "")
        return prefix + _BULLETS
    if entity_type in _LAST4_TYPES:
        tail = "".join(ch for ch in value if ch.isalnum())[-4:]
        return _BULLETS[:4] + " " + tail
    if entity_type == "PHONE":
        digits = [ch for ch in value if ch.isdigit()]
        head = value[:3] if value.startswith("+") else ""
        return f"{head}{_BULLETS[:6]}{''.join(digits[-2:])}"
    return mask_preview(value)


def entity_info(custom: Mapping[str, EntityInfo]) -> dict[str, EntityInfo]:
    out = {
        e.id: EntityInfo(e.label, e.category.value, e.quality.value)
        for e in BUILTIN_ENTITIES.values()
    }
    out.update(custom)
    return out


def build_report(
    session: ScanSession,
    entities: Mapping[str, EntityInfo],
    *,
    ner_status: str,
    rule_count: int,
) -> dict[str, Any]:
    outcome: DetectionOutcome = session.outcome
    decision = session.decision or session.redecide()
    segments = {s.segment_id: s for s in session.document.segments}
    findings: list[dict[str, Any]] = []
    by_entity: Counter[str] = Counter()
    by_category: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    hidden = 0
    max_severity = 0
    ordered = decision.findings
    for f in ordered:
        d = f.detection
        info = entities.get(d.entity_type) or EntityInfo(
            d.entity_type, Category.OTHER.value, QualityClass.COMPANY_RULE.value
        )
        segment = segments[d.segment_id]
        is_hidden = segment.kind not in _VISIBLE_KINDS
        hidden += is_hidden
        by_entity[d.entity_type] += 1
        by_category[info.category] += 1
        by_severity[SEVERITY_LABELS[d.severity]] += 1
        max_severity = max(max_severity, int(d.severity))
        if len(findings) < MAX_LISTED_FINDINGS:
            effective = f.effective_action or f.action
            findings.append(
                {
                    "id": f.finding_id,
                    "entity_type": d.entity_type,
                    "entity_label": info.label,
                    "category": info.category,
                    "severity": SEVERITY_LABELS[d.severity],
                    "confidence": round(d.confidence, 2),
                    "detector": d.detector,
                    "corroborated_by": list(f.corroborating_detectors),
                    "rule_id": d.rule_id if d.detector.startswith("custom.") else None,
                    "preview": preview(d.entity_type, info.quality, d.matched_value.reveal()),
                    "location": {"kind": segment.kind.value, "label": segment.label},
                    "hidden": is_hidden,
                    "value_group": session.value_group[f.finding_id],
                    "action": f.action.value,
                    "effective_action": effective.value,
                    "reason": f.policy_reason,
                    "overridden": f.overridden,
                    "covered_by": f.covered_by,
                    "generalizable": d.entity_type in GENERALIZABLE,
                    "high_risk": is_high_risk(d.severity, Category(info.category)),
                }
            )

    summary = {
        "total": len(ordered),
        "listed": len(findings),
        "distinct_values": len(set(session.value_group.values())),
        "hidden": hidden,
        "max_severity": SEVERITY_LABELS[Severity(max_severity)] if max_severity else None,
        "by_severity": {label: by_severity[label] for label in SEVERITY_LABELS.values()},
        "by_category": [{"category": c, "count": n} for c, n in by_category.most_common()],
        "by_entity": [
            {
                "entity_type": t,
                "label": entities[t].label if t in entities else t,
                "category": entities[t].category if t in entities else Category.OTHER.value,
                "count": n,
            }
            for t, n in by_entity.most_common()
        ],
        "detectors": {
            "ner": ner_status,
            "company_rules": rule_count,
            "rule_timeouts": outcome.rule_timeouts,
        },
        "allowed": outcome.allowed,
    }
    return {"findings": findings, "summary": summary, "policy": policy_summary(session)}


def policy_summary(session: ScanSession) -> dict[str, Any]:
    decision = session.decision or session.redecide()
    profile = decision.profile
    return {
        "profile": {"id": profile.id, "name": profile.name, "builtin": profile.builtin},
        "actions": decision.counts(),
        "regions": len(decision.regions),
        "blocked": decision.blocked,
        "overridden": sum(1 for f in decision.findings if f.overridden),
        # Phase 7 adds verification; this only says no BLOCK is left.
        "ready": decision.blocked == 0,
    }
