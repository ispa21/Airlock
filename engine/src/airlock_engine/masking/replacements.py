"""Replacement text for each action and mask style.

* MASK, ``typed_placeholder``: ``[EMAIL_1]``. The same value always gets the
  same placeholder within a file, so an AI can still follow who is who.
* MASK, ``placeholder``: ``[MASKED_1]``. Same, without revealing the type.
* MASK, ``synthetic``: a realistic but reserved stand-in (``person1@example.invalid``,
  ``192.0.2.1``); types without a safe reserved form use typed placeholders.
* MASK, ``partial``: part of the value stays recognisable — last four
  characters of ids and numbers (``XXXX XXXX 4691``, as on a masked Aadhaar),
  initials of names (``R. S.``), first letter and domain of e-mail addresses.
  Never for credentials (part of a secret is still a leak). Not reversible.
* REDACT: ``[REDACTED]``. No type, no numbering, nothing to link.
* GENERALIZE: a coarser form (date of birth → year, e-mail → domain, IP →
  subnet, URL → host, amount → rounded).

Placeholders and synthetic values are reversible through the vault; redacted
and generalised values are not.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from airlock_engine.core.models import Action
from airlock_engine.detectors.entities import BUILTIN_ENTITIES, BUILTIN_RULE_CATEGORIES
from airlock_engine.masking.sweep import UNSAFE_REPLACEMENT_CHARS

REDACTED = "[REDACTED]"
_GENERIC_TYPES = frozenset(BUILTIN_ENTITIES) | {c.id for c in BUILTIN_RULE_CATEGORIES}
#: Custom categories are named after company labels; never put those in a placeholder.
CUSTOM_TYPE = "CONFIDENTIAL"

_SYNTHETIC_FIRST = ("Alex", "Sam", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Avery")
_SYNTHETIC_LAST = ("Example", "Sample", "Placeholder", "Testcase")
_YEAR = re.compile(r"(?<!\d)(19|20)\d{2}(?!\d)")
_NUMBER = re.compile(r"\d[\d,]*(?:\.\d+)?")


class Replacer:
    """Issues replacement text, consistent per (type, value) within one file."""

    def __init__(self, existing_text: str = "") -> None:
        #: Text already in the document: placeholders must not collide with it (R11).
        self._existing = existing_text
        self._issued: dict[tuple[str, str, str], str] = {}
        self._counters: dict[str, int] = {}
        #: replacement text → (original value, entity type), reversible ones only.
        self.reversible: dict[str, tuple[str, str]] = {}

    def _next(self, key: str, render: object) -> str:
        assert callable(render)
        n = self._counters.get(key, 0)
        while True:
            n += 1
            text = str(render(n))
            if text not in self._existing and text not in self.reversible:
                self._counters[key] = n
                return text

    def text_for(self, entity_type: str, value: str, action: Action, mask_style: str) -> str:
        if action is Action.REDACT:
            return REDACTED
        if action is Action.GENERALIZE:
            general = generalize(entity_type, value)
            if general is not None:
                return _check(general)
            action = Action.MASK  # no coarser form: fall back to a placeholder
        if action is not Action.MASK:
            raise ValueError(f"no replacement for action {action.value}")
        if mask_style == "partial" and partial_allowed(entity_type):
            return _check(partial(entity_type, value))
        key = (entity_type, value, mask_style)
        if key in self._issued:
            return self._issued[key]
        label = entity_type if entity_type in _GENERIC_TYPES else CUSTOM_TYPE
        text = None
        if mask_style == "synthetic":
            text = self._synthetic(entity_type, value)
        if text is None:
            if mask_style == "placeholder":
                text = self._next("MASKED", lambda n: f"[MASKED_{n}]")
            else:
                text = self._next(label, lambda n: f"[{label}_{n}]")
        self._issued[key] = _check(text)
        self.reversible[text] = (value, entity_type)
        return text

    def _synthetic(self, entity_type: str, value: str) -> str | None:
        if entity_type == "PERSON":
            pool = len(_SYNTHETIC_FIRST) * len(_SYNTHETIC_LAST)
            return self._next(
                "syn:person",
                lambda n: (
                    f"{_SYNTHETIC_FIRST[(n - 1) % len(_SYNTHETIC_FIRST)]} "
                    f"{_SYNTHETIC_LAST[((n - 1) // len(_SYNTHETIC_FIRST)) % len(_SYNTHETIC_LAST)]}"
                    + ("" if n <= pool else f" {n}")
                ),
            )
        if entity_type == "EMAIL":
            return self._next("syn:email", lambda n: f"person{n}@example.invalid")
        if entity_type == "PHONE":
            # Indian numbers never start with 0 after the country code: clearly fake.
            return self._next("syn:phone", lambda n: f"+91 00000 {n:05d}")
        if entity_type == "IP_ADDRESS":
            if ":" in value:
                return self._next("syn:ip6", lambda n: f"2001:db8::{n:x}")
            return self._next("syn:ip4", lambda n: f"192.0.2.{(n - 1) % 254 + 1}")
        if entity_type == "URL":
            return self._next("syn:url", lambda n: f"https://example.invalid/link-{n}")
        if entity_type == "ORGANIZATION":
            return self._next("syn:org", lambda n: f"Example Company {n}")
        if entity_type == "LOCATION":
            return self._next("syn:loc", lambda n: f"Sample City {n}")
        return None


#: Entity types whose values are words (names) rather than codes.
_WORD_TYPES = frozenset({"PERSON", "ORGANIZATION", "LOCATION", "PRODUCT", "EVENT"})


def partial_allowed(entity_type: str) -> bool:
    entity = BUILTIN_ENTITIES.get(entity_type)
    return entity is None or entity.category.value != "CREDENTIALS"


def partial(entity_type: str, value: str) -> str:
    """Keep just enough to recognise the value; hide the rest with X."""
    if entity_type == "EMAIL" and "@" in value:
        local, _, domain = value.rpartition("@")
        return f"{local[:1]}{'X' * max(3, len(local) - 1)}@{domain}"
    words = value.split()
    if entity_type in _WORD_TYPES or (
        entity_type not in BUILTIN_ENTITIES and all(w.isalpha() for w in words)
    ):
        return " ".join(f"{w[0].upper()}." for w in words if w[:1].isalpha()) or "X"
    alnum = [i for i, ch in enumerate(value) if ch.isalnum()]
    keep = set(alnum[-4:]) if len(alnum) > 4 else set()
    return "".join(ch if (i in keep or not ch.isalnum()) else "X" for i, ch in enumerate(value))


def generalize(entity_type: str, value: str) -> str | None:
    """A coarser form of ``value``, or None if the type has none."""
    if entity_type == "DATE_OF_BIRTH":
        m = _YEAR.search(value)
        return m.group() if m else "[DATE]"
    if entity_type == "EMAIL":
        domain = value.rsplit("@", 1)[-1].strip()
        return f"[EMAIL @{domain}]" if domain and domain != value else "[EMAIL]"
    if entity_type == "PHONE":
        return _phone_country(value)
    if entity_type == "IP_ADDRESS":
        try:
            address = ipaddress.ip_address(value.strip("[]"))
        except ValueError:
            return "[IP_ADDRESS]"
        prefix = 24 if address.version == 4 else 64
        return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))
    if entity_type == "URL":
        raw = value if "://" in value else f"https://{value}"
        try:
            parts = urlsplit(raw)
            host = parts.hostname or ""
        except ValueError:
            return "[URL]"
        if not host:
            return "[URL]"
        scheme = parts.scheme if "://" in value else ""
        return f"{scheme}://{host}" if scheme else host
    if entity_type == "MONEY":
        m = _NUMBER.search(value)
        if m is None:
            return "[AMOUNT]"
        try:
            number = float(m.group().replace(",", ""))
        except ValueError:
            return "[AMOUNT]"
        rounded = _round_significant(number)
        return f"{value[: m.start()]}~{rounded}{value[m.end() :]}"
    return None


def _round_significant(number: float) -> str:
    if number == 0:
        return "0"
    magnitude = len(str(int(abs(number)))) - 1 if abs(number) >= 1 else 0
    if abs(number) < 1:
        return f"{number:.1g}"
    step = 10**magnitude
    # Half up (not Python's round-half-even): 4.5 crore → ~5 crore.
    return str(int(abs(number) / step + 0.5) * step * (1 if number >= 0 else -1))


def _phone_country(value: str) -> str:
    import phonenumbers

    try:
        number = phonenumbers.parse(value, "IN")
    except phonenumbers.NumberParseException:
        return "[PHONE]"
    if value.strip().startswith("+") and number.country_code:
        return f"[PHONE +{number.country_code}]"
    return "[PHONE]"


def _check(text: str) -> str:
    if not text or UNSAFE_REPLACEMENT_CHARS & set(text):
        # Fall back to a neutral token rather than break the file's structure.
        return REDACTED
    return text
