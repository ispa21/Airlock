"""Deterministic, explainable risk score (0-100).

The score is a plain sum of named factors, each with a cap, so every point
can be shown to the user ("Credentials: +45"). The same findings always give
the same score: no randomness, no model, no hidden weights.

Two scores are reported:

* **before** — the document as it is: every finding counts.
* **after** — what would remain in the protected copy with the current
  decisions: only findings that are kept (ALLOW), plus anything still set to
  BLOCK (it cannot be shared until resolved). Content Airlock cannot read is
  removed from protected copies, so it only counts *before*.

Levels: 0 none, 1-24 low, 25-49 medium, 50-74 high, 75-100 critical.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final

from airlock_engine.core.models import Action, Category, Finding

LEVELS: Final = ((75, "critical"), (50, "high"), (25, "medium"), (1, "low"), (0, "none"))


@dataclass(frozen=True, slots=True)
class FactorRule:
    id: str
    label: str
    #: Points for the first distinct value, then for each further distinct value.
    first: float
    each: float
    cap: float
    matches: Callable[[Finding], bool]


def _category(*categories: Category) -> Callable[[Finding], bool]:
    def match(f: Finding) -> bool:
        return not _is_rule(f) and f.category in categories and not _is_ner(f)

    return match


def _is_rule(f: Finding) -> bool:
    return f.detection.detector.startswith("custom.")


def _is_ner(f: Finding) -> bool:
    return f.detection.detector.startswith("ner.")


#: Order matters only for display; each finding counts in the first factor it matches.
FACTORS: Final[tuple[FactorRule, ...]] = (
    FactorRule(
        "credentials", "Passwords, keys and tokens", 40, 5, 60, _category(Category.CREDENTIALS)
    ),
    FactorRule(
        "government_ids",
        "Government ids (PAN, Aadhaar, GSTIN)",
        25,
        5,
        40,
        _category(Category.GOVERNMENT),
    ),
    FactorRule(
        "financial", "Card, bank and account details", 20, 4, 35, _category(Category.FINANCIAL)
    ),
    FactorRule("company_terms", "Company-confidential terms (your rules)", 15, 3, 30, _is_rule),
    FactorRule("personal", "Personal contact details", 8, 1, 20, _category(Category.PERSONAL)),
    FactorRule(
        "business",
        "Internal systems, addresses and business details",
        6,
        1,
        15,
        _category(Category.BUSINESS, Category.INTELLECTUAL_PROPERTY, Category.OTHER),
    ),
    FactorRule("names", "Names, places and amounts (language model)", 3, 0.5, 10, _is_ner),
)
HIDDEN_POINTS: Final = 10.0
UNREADABLE_POINTS: Final = 5.0
VOLUME_THRESHOLD: Final = 50
VOLUME_POINTS: Final = 10.0


@dataclass(frozen=True, slots=True)
class Factor:
    id: str
    label: str
    points: int
    detail: str


@dataclass
class RiskReport:
    score: int
    level: str
    factors: list[Factor] = field(default_factory=list)

    def to_json(self) -> dict[str, object]:
        return {
            "score": self.score,
            "level": self.level,
            "factors": [
                {"id": f.id, "label": f.label, "points": f.points, "detail": f.detail}
                for f in self.factors
            ],
        }


def level_for(score: int) -> str:
    return next(name for threshold, name in LEVELS if score >= threshold)


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else many or one + 's'}"


class RiskScorer:
    def score(
        self,
        findings: Sequence[Finding],
        *,
        value_key: Callable[[Finding], object],
        hidden_ids: Iterable[str] = (),
        unreadable: int = 0,
    ) -> RiskReport:
        """Score ``findings``. ``value_key`` groups repeats of the same value."""
        hidden = set(hidden_ids)
        claimed: set[str] = set()
        factors: list[Factor] = []
        total = 0.0
        for rule in FACTORS:
            matched = [f for f in findings if f.finding_id not in claimed and rule.matches(f)]
            if not matched:
                continue
            claimed.update(f.finding_id for f in matched)
            distinct = len({value_key(f) for f in matched})
            points = min(rule.cap, rule.first + rule.each * (distinct - 1))
            total += points
            factors.append(
                Factor(
                    rule.id,
                    rule.label,
                    round(points),
                    f"{_plural(distinct, 'distinct value')} found {_plural(len(matched), 'time')}",
                )
            )

        hidden_count = sum(1 for f in findings if f.finding_id in hidden)
        if hidden_count:
            total += HIDDEN_POINTS
            factors.append(
                Factor(
                    "hidden",
                    "Sensitive data in hidden parts",
                    round(HIDDEN_POINTS),
                    f"{_plural(hidden_count, 'finding')} in comments, properties, tracked changes "
                    "or other places you would not see when opening the file",
                )
            )
        distinct_all = len({value_key(f) for f in findings})
        if distinct_all >= VOLUME_THRESHOLD:
            total += VOLUME_POINTS
            factors.append(
                Factor(
                    "volume",
                    "Large amount of sensitive data",
                    round(VOLUME_POINTS),
                    f"{distinct_all} distinct sensitive values",
                )
            )
        if unreadable:
            total += UNREADABLE_POINTS
            factors.append(
                Factor(
                    "unreadable",
                    "Content Airlock could not read",
                    round(UNREADABLE_POINTS),
                    f"{_plural(unreadable, 'item')} (macros, objects, pictures) "
                    "could not be checked",
                )
            )
        score = min(100, round(total))
        return RiskReport(score, level_for(score), factors)


def residual(findings: Sequence[Finding]) -> list[Finding]:
    """Findings that would still be exposed with the current decisions."""
    return [f for f in findings if (f.effective_action or f.action) in (Action.ALLOW, Action.BLOCK)]
