"""Turns detections into findings with actions, and overlapping findings into
non-overlapping regions for the masker.

Detection says *what* a span is; policy says *what to do* with it. Every
decision carries a short, content-free reason so the report can explain it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from airlock_engine.core.models import Action, Category, Finding, Severity
from airlock_engine.detectors.pipeline import Detected
from airlock_engine.policy.profiles import ACTION_LABELS, ACTION_ORDER, GENERALIZABLE, Profile


@dataclass(frozen=True, slots=True)
class Region:
    """A span the masker will rewrite as one unit (Phase 5)."""

    segment_id: int
    start: int
    end: int
    action: Action
    #: Finding whose type and style the replacement uses.
    primary_id: str
    member_ids: tuple[str, ...]
    mask_style: str


@dataclass
class PolicyDecision:
    profile: Profile
    findings: list[Finding] = field(default_factory=list)
    regions: list[Region] = field(default_factory=list)

    @property
    def blocked(self) -> int:
        """Regions that stop the document from being shared as is."""
        return sum(1 for r in self.regions if r.action is Action.BLOCK)

    def counts(self) -> dict[str, int]:
        out = {a.value: 0 for a in Action}
        for f in self.findings:
            out[(f.effective_action or f.action).value] += 1
        return out


_PROPER = frozenset({"Aadhaar"})
_CATEGORY_PHRASES = {
    Category.PERSONAL: "personal data",
    Category.GOVERNMENT: "government ids",
    Category.FINANCIAL: "financial details",
    Category.BUSINESS: "business details",
    Category.CREDENTIALS: "credentials such as passwords and keys",
    Category.INTELLECTUAL_PROPERTY: "intellectual property",
    Category.OTHER: "other details",
}


def _label(entity_label: str) -> str:
    """Lower-case the first word for use mid-sentence, except acronyms and names."""
    first = entity_label.split(" ", 1)[0]
    if first.isupper() or first in _PROPER:
        return entity_label
    return entity_label[:1].lower() + entity_label[1:]


class PolicyEngine:
    def __init__(
        self,
        *,
        categories: Mapping[str, Category],
        labels: Mapping[str, str],
        rule_actions: Mapping[str, Action] | None = None,
    ) -> None:
        """``categories``/``labels`` cover built-in entity types and custom
        category ids; ``rule_actions`` holds actions set on company rules."""
        self._categories = categories
        self._labels = labels
        self._rule_actions = rule_actions or {}

    def _base(self, item: Detected, profile: Profile) -> tuple[Action, str]:
        d = item.detection
        label = _label(self._labels.get(d.entity_type, d.entity_type))
        category = self._categories.get(d.entity_type, Category.OTHER)
        company_rule = d.detector.startswith("custom.")
        if company_rule and d.rule_id in self._rule_actions:
            action = self._rule_actions[d.rule_id]
            return action, f"The company rule that found this is set to {ACTION_LABELS[action]}."
        action, source = profile.resolve(d.entity_type, category, company_rule=company_rule)
        never_skip = company_rule or category is Category.CREDENTIALS
        if action is not Action.ALLOW and not never_skip and d.confidence < profile.min_confidence:
            return Action.ALLOW, (
                f"Kept: Airlock is {round(d.confidence * 100)}% sure about this {label}, "
                f"below the {round(profile.min_confidence * 100)}% threshold of "
                f"{profile.name}."
            )
        if source == "entity" or source == "company_rule":
            what = "company-rule matches" if source == "company_rule" else f"each {label}"
        elif source == "category":
            what = _CATEGORY_PHRASES[category]
        else:
            what = "anything not listed"
        return action, f"{profile.name} {_verb(action)} {what}."

    def decide(
        self,
        items: Sequence[tuple[str, Detected]],
        profile: Profile,
        overrides: Mapping[str, Action] | None = None,
        styles: Mapping[str, str] | None = None,
    ) -> PolicyDecision:
        """``styles`` holds per-finding mask styles chosen by the user."""
        overrides = overrides or {}
        styles = styles or {}
        decision = PolicyDecision(profile)
        findings: list[Finding] = []
        for finding_id, item in items:
            d = item.detection
            if finding_id in overrides:
                action, reason, overridden = overrides[finding_id], "Changed by you.", True
            else:
                action, reason = self._base(item, profile)
                overridden = False
            if action is Action.GENERALIZE and d.entity_type not in GENERALIZABLE:
                action = Action.MASK
                reason += " This type cannot be generalised, so it is masked instead."
            findings.append(
                Finding(
                    finding_id=finding_id,
                    detection=d,
                    category=self._categories.get(d.entity_type, Category.OTHER),
                    action=action,
                    policy_reason=reason,
                    corroborating_detectors=item.corroborating,
                    mask_style=styles.get(finding_id, profile.style_for(d.entity_type)),
                    overridden=overridden,
                )
            )
        decision.findings, decision.regions = _resolve_overlaps(findings)
        return decision


def _verb(action: Action) -> str:
    return {
        Action.ALLOW: "keeps",
        Action.GENERALIZE: "generalises",
        Action.MASK: "masks",
        Action.REDACT: "removes",
        Action.BLOCK: "blocks",
    }[action]


def _rank(f: Finding) -> tuple[int, int, int, float]:
    d = f.detection
    return (ACTION_ORDER[f.action], int(d.severity), d.end - d.start, d.confidence)


def _resolve_overlaps(findings: list[Finding]) -> tuple[list[Finding], list[Region]]:
    """Group overlapping findings (transitively) per segment. Each group that
    does anything becomes one region spanning the union, with the strongest
    action; the other members are ``covered_by`` the strongest finding."""
    by_segment: dict[int, list[Finding]] = {}
    for f in findings:
        by_segment.setdefault(f.detection.segment_id, []).append(f)
    resolved: dict[str, Finding] = {}
    regions: list[Region] = []
    for segment_id, group in by_segment.items():
        group.sort(key=lambda f: (f.detection.start, -f.detection.end))
        clusters: list[list[Finding]] = []
        end = -1
        for f in group:
            if clusters and f.detection.start < end:
                clusters[-1].append(f)
                end = max(end, f.detection.end)
            else:
                clusters.append([f])
                end = f.detection.end
        for cluster in clusters:
            primary = max(cluster, key=_rank)
            action = primary.action
            for f in cluster:
                covered = None if f is primary else primary.finding_id
                resolved[f.finding_id] = _replace(f, covered, action)
            if action is Action.ALLOW:
                continue
            regions.append(
                Region(
                    segment_id=segment_id,
                    start=min(f.detection.start for f in cluster),
                    end=max(f.detection.end for f in cluster),
                    action=action,
                    primary_id=primary.finding_id,
                    member_ids=tuple(f.finding_id for f in cluster),
                    mask_style=primary.mask_style,
                )
            )
    ordered = [resolved[f.finding_id] for f in findings]
    regions.sort(key=lambda r: (r.segment_id, r.start))
    return ordered, regions


def _replace(f: Finding, covered_by: str | None, effective: Action) -> Finding:
    return Finding(
        finding_id=f.finding_id,
        detection=f.detection,
        category=f.category,
        action=f.action,
        policy_reason=f.policy_reason,
        corroborating_detectors=f.corroborating_detectors,
        mask_style=f.mask_style,
        overridden=f.overridden,
        covered_by=covered_by,
        effective_action=effective,
    )


def is_high_risk(severity: Severity, category: Category) -> bool:
    """Allowing these needs an explicit acknowledgement from the user."""
    return severity is Severity.CRITICAL or category is Category.CREDENTIALS
