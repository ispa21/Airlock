"""Privacy profiles: which action applies to which kind of finding.

A profile answers "what do we do with an e-mail address / an API key /
an internal project name?". Resolution order for one finding:

1. the user's override for this scan,
2. the company rule's own action (if the rule sets one),
3. the profile's action for the entity type (or custom category id),
4. the profile's action for company-rule findings,
5. the profile's action for the report category (PERSONAL, CREDENTIALS...),
6. the profile's default action.

Findings below the profile's confidence threshold are allowed, except
company-rule and credential findings, which are never discarded on
confidence.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from airlock_engine.core.models import Action, Category

#: Stronger actions win when findings overlap.
ACTION_ORDER: dict[Action, int] = {
    Action.ALLOW: 0,
    Action.GENERALIZE: 1,
    Action.MASK: 2,
    Action.REDACT: 3,
    Action.BLOCK: 4,
}

MASK_STYLES = ("typed_placeholder", "placeholder", "synthetic", "partial")

#: Entity types with a meaningful coarser form (DOB → year, e-mail → domain,
#: IP → subnet, ...). GENERALIZE on anything else falls back to MASK.
GENERALIZABLE = frozenset({"DATE_OF_BIRTH", "EMAIL", "PHONE", "IP_ADDRESS", "URL", "MONEY"})

ACTION_LABELS: dict[Action, str] = {
    Action.ALLOW: "kept",
    Action.GENERALIZE: "generalised",
    Action.MASK: "masked",
    Action.REDACT: "redacted",
    Action.BLOCK: "blocked",
}

DEFAULT_PROFILE_ID = "company-default"


@dataclass(frozen=True)
class Profile:
    id: str
    name: str
    description: str = ""
    builtin: bool = False
    #: Built-in profile a custom profile was copied from.
    base_id: str | None = None
    #: Explicit entity type (or custom category id) → action.
    actions: Mapping[str, Action] = field(default_factory=dict)
    #: Report category → action, used when no entity action is set.
    category_actions: Mapping[Category, Action] = field(default_factory=dict)
    company_rule_action: Action = Action.MASK
    default_action: Action = Action.MASK
    min_confidence: float = 0.6
    mask_style: str = "typed_placeholder"
    #: Entity type → mask style, when it differs from ``mask_style``.
    styles: Mapping[str, str] = field(default_factory=dict)

    def style_for(self, entity_type: str) -> str:
        return self.styles.get(entity_type, self.mask_style)

    def resolve(
        self, entity_type: str, category: Category, *, company_rule: bool
    ) -> tuple[Action, str]:
        """Action and where it came from: "entity", "company_rule", "category", "default"."""
        if entity_type in self.actions:
            return self.actions[entity_type], "entity"
        if company_rule:
            return self.company_rule_action, "company_rule"
        if category in self.category_actions:
            return self.category_actions[category], "category"
        return self.default_action, "default"

    def with_changes(self, **changes: object) -> Profile:
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "builtin": self.builtin,
            "base_id": self.base_id,
            "actions": dict(self.actions),
            "category_actions": dict(self.category_actions),
            "company_rule_action": self.company_rule_action,
            "default_action": self.default_action,
            "min_confidence": self.min_confidence,
            "mask_style": self.mask_style,
            "styles": dict(self.styles),
        }
        data.update(changes)
        return Profile(**data)  # type: ignore[arg-type]


_A, _C = Action, Category

COMPANY_DEFAULT = Profile(
    id=DEFAULT_PROFILE_ID,
    name="Company Default",
    description="Blocks credentials, masks personal data, ids, financial details and "
    "company terms. Keeps public details such as places and product names.",
    builtin=True,
    category_actions={
        _C.CREDENTIALS: _A.BLOCK,
        _C.GOVERNMENT: _A.MASK,
        _C.FINANCIAL: _A.MASK,
        _C.PERSONAL: _A.MASK,
        _C.BUSINESS: _A.MASK,
        _C.INTELLECTUAL_PROPERTY: _A.MASK,
        _C.OTHER: _A.MASK,
    },
    actions={
        "DATE_OF_BIRTH": _A.GENERALIZE,
        "LOCATION": _A.ALLOW,
        "MONEY": _A.ALLOW,
        "PRODUCT": _A.ALLOW,
        "EVENT": _A.ALLOW,
        "IFSC": _A.ALLOW,  # a branch code alone identifies no one
    },
    min_confidence=0.6,
)

STRICT = Profile(
    id="strict",
    name="Strict",
    description="Blocks credentials, removes government and financial ids entirely and "
    "masks everything else Airlock finds, including places, amounts and product names.",
    builtin=True,
    category_actions={
        _C.CREDENTIALS: _A.BLOCK,
        _C.GOVERNMENT: _A.REDACT,
        _C.FINANCIAL: _A.REDACT,
        _C.PERSONAL: _A.MASK,
        _C.BUSINESS: _A.MASK,
        _C.INTELLECTUAL_PROPERTY: _A.REDACT,
        _C.OTHER: _A.MASK,
    },
    actions={"DATE_OF_BIRTH": _A.REDACT, "MONEY": _A.MASK},
    company_rule_action=_A.REDACT,
    min_confidence=0.5,
)

SECRETS_AND_IDS = Profile(
    id="secrets-and-ids",
    name="Secrets & IDs only",
    description="Blocks credentials and masks government, financial and company-rule "
    "matches. Names, e-mail addresses and other details are kept.",
    builtin=True,
    category_actions={
        _C.CREDENTIALS: _A.BLOCK,
        _C.GOVERNMENT: _A.MASK,
        _C.FINANCIAL: _A.MASK,
    },
    actions={"MONEY": _A.ALLOW, "IFSC": _A.ALLOW},
    default_action=_A.ALLOW,
    min_confidence=0.6,
)

BUILTIN_PROFILES: dict[str, Profile] = {p.id: p for p in (COMPANY_DEFAULT, STRICT, SECRETS_AND_IDS)}
