"""Company rules, categories, the allow-list and settings."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

from airlock_engine.core.models import Action, Category, Severity
from airlock_engine.detectors.custom import CompanyRule, RuleError, normalize, validate_rule_terms
from airlock_engine.security.keyprotect import KeyProtector
from airlock_engine.storage.db import Database, now

ACTIONS = ("ALLOW", "MASK", "REDACT", "GENERALIZE", "BLOCK")
_CATEGORY_ID = re.compile(r"^[A-Z][A-Z0-9_]{1,47}$")


@dataclass(frozen=True, slots=True)
class CategoryRow:
    id: str
    label: str
    group: str
    severity: int
    builtin: bool

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "label": self.label,
            "group": self.group,
            "severity": self.severity,
            "builtin": self.builtin,
        }


@dataclass(frozen=True, slots=True)
class RuleRow:
    id: str
    kind: str
    pattern: str
    aliases: tuple[str, ...]
    category_id: str
    action: str | None
    enabled: bool
    created_at: str
    updated_at: str

    def __repr__(self) -> str:  # patterns are confidential
        return f"RuleRow(id={self.id}, kind={self.kind})"

    def to_json(self) -> dict[str, Any]:
        """For the rules screen only: the user's own rule text, never document content."""
        return {
            "id": self.id,
            "kind": self.kind,
            "pattern": self.pattern,
            "aliases": list(self.aliases),
            "category_id": self.category_id,
            "action": self.action,
            "enabled": self.enabled,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }


class RuleStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    # --- categories ---------------------------------------------------------

    def categories(self) -> list[CategoryRow]:
        return [
            CategoryRow(r["id"], r["label"], r["group_name"], r["severity"], bool(r["is_builtin"]))
            for r in self.db.query("SELECT * FROM categories ORDER BY is_builtin, label")
        ]

    def category(self, category_id: str) -> CategoryRow | None:
        rows = self.db.query("SELECT * FROM categories WHERE id = ?", (category_id,))
        if not rows:
            return None
        r = rows[0]
        return CategoryRow(
            r["id"], r["label"], r["group_name"], r["severity"], bool(r["is_builtin"])
        )

    def add_category(self, label: str, group: str, severity: int) -> CategoryRow:
        label = label.strip()
        if not 2 <= len(label) <= 60:
            raise RuleError("A category name needs 2 to 60 characters.")
        if group not in {c.value for c in Category}:
            raise RuleError("Choose a valid category group.")
        if severity not in {int(s) for s in Severity}:
            raise RuleError("Severity must be between 1 and 4.")
        base = re.sub(r"[^A-Z0-9]+", "_", label.upper()).strip("_")[:40] or "CUSTOM"
        if not base[0].isalpha():
            base = f"C_{base}"
        category_id = base
        n = 2
        while self.category(category_id) is not None:
            category_id = f"{base}_{n}"
            n += 1
        if not _CATEGORY_ID.match(category_id):
            raise RuleError("A category name needs at least two letters or digits.")
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO categories (id, label, group_name, severity, is_builtin) "
                "VALUES (?, ?, ?, ?, 0)",
                (category_id, label, group, severity),
            )
        result = self.category(category_id)
        assert result is not None
        return result

    # --- rules -------------------------------------------------------------

    def all(self) -> list[RuleRow]:
        aliases: dict[str, list[str]] = {}
        for r in self.db.query("SELECT rule_id, alias FROM custom_rule_aliases ORDER BY alias"):
            aliases.setdefault(r["rule_id"], []).append(r["alias"])
        return [
            RuleRow(
                r["id"],
                r["kind"],
                r["pattern"],
                tuple(aliases.get(r["id"], ())),
                r["category_id"],
                r["action"],
                bool(r["enabled"]),
                r["created_at"],
                r["updated_at"],
            )
            for r in self.db.query("SELECT * FROM custom_rules ORDER BY created_at, id")
        ]

    def get(self, rule_id: str) -> RuleRow | None:
        return next((r for r in self.all() if r.id == rule_id), None)

    def _check(
        self,
        kind: str,
        pattern: str,
        aliases: tuple[str, ...],
        category_id: str,
        action: str | None,
    ) -> None:
        validate_rule_terms(kind, pattern, aliases)
        if self.category(category_id) is None:
            raise RuleError("Choose an existing category for this rule.")
        if action is not None and action not in ACTIONS:
            raise RuleError("Choose a valid action.")

    def create(
        self,
        *,
        kind: str,
        pattern: str,
        category_id: str,
        aliases: tuple[str, ...] = (),
        action: str | None = None,
        enabled: bool = True,
    ) -> RuleRow:
        aliases = _clean_aliases(aliases, pattern)
        self._check(kind, pattern, aliases, category_id, action)
        rule_id = f"rule_{uuid.uuid4().hex[:12]}"
        stamp = now()
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO custom_rules (id, kind, pattern, category_id, action, enabled, "
                "created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (rule_id, kind, pattern, category_id, action, int(enabled), stamp, stamp),
            )
            conn.executemany(
                "INSERT INTO custom_rule_aliases (rule_id, alias) VALUES (?, ?)",
                [(rule_id, a) for a in aliases],
            )
        row = self.get(rule_id)
        assert row is not None
        return row

    def update(self, rule_id: str, **changes: Any) -> RuleRow | None:
        current = self.get(rule_id)
        if current is None:
            return None
        kind = changes.get("kind", current.kind)
        pattern = changes.get("pattern", current.pattern)
        category_id = changes.get("category_id", current.category_id)
        action = changes.get("action", current.action)
        enabled = changes.get("enabled", current.enabled)
        aliases = _clean_aliases(tuple(changes.get("aliases", current.aliases)), pattern)
        self._check(kind, pattern, aliases, category_id, action)
        with self.db.transaction() as conn:
            conn.execute(
                "UPDATE custom_rules SET kind = ?, pattern = ?, category_id = ?, action = ?, "
                "enabled = ?, updated_at = ? WHERE id = ?",
                (kind, pattern, category_id, action, int(enabled), now(), rule_id),
            )
            conn.execute("DELETE FROM custom_rule_aliases WHERE rule_id = ?", (rule_id,))
            conn.executemany(
                "INSERT INTO custom_rule_aliases (rule_id, alias) VALUES (?, ?)",
                [(rule_id, a) for a in aliases],
            )
        return self.get(rule_id)

    def delete(self, rule_id: str) -> bool:
        with self.db.transaction() as conn:
            return conn.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,)).rowcount > 0

    def compiled(self) -> list[CompanyRule]:
        """Enabled rules in the shape the detector needs."""
        severity = {c.id: Severity(c.severity) for c in self.categories()}
        return [
            CompanyRule(
                id=r.id,
                kind=r.kind,
                pattern=r.pattern,
                category_id=r.category_id,
                severity=severity.get(r.category_id, Severity.HIGH),
                aliases=r.aliases,
                enabled=r.enabled,
            )
            for r in self.all()
            if r.enabled
        ]

    def rule_actions(self) -> dict[str, Action]:
        """Actions set on individual enabled rules (overriding the profile)."""
        return {r.id: Action(r.action) for r in self.all() if r.enabled and r.action}

    # --- settings ----------------------------------------------------------

    def setting(self, key: str) -> str | None:
        rows = self.db.query("SELECT value FROM settings WHERE key = ?", (key,))
        return str(rows[0]["value"]) if rows else None

    def delete_setting(self, key: str) -> None:
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    def set_setting(self, key: str, value: str) -> None:
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )


def _clean_aliases(aliases: tuple[str, ...], pattern: str) -> tuple[str, ...]:
    out: list[str] = []
    for a in aliases:
        if not isinstance(a, str):
            raise RuleError("Aliases must be text.")
        if a not in out and a != pattern:
            out.append(a)
    return tuple(out)


class AllowList:
    """Values the user marked "not sensitive", stored as keyed fingerprints.

    The HMAC key is random per installation and wrapped by the key protector
    (DPAPI on Windows), so the database alone cannot be used to test guesses.
    """

    _KEY_SETTING = "allow_list_key_wrapped"
    _LEGACY_SETTING = "allow_list_key"  # Phase 3: plain hex, migrated on first use

    def __init__(self, store: RuleStore, protector: KeyProtector) -> None:
        self._store = store
        wrapped = store.setting(self._KEY_SETTING)
        if wrapped is not None:
            self._key = protector.unwrap(base64.b64decode(wrapped))
        else:
            legacy = store.setting(self._LEGACY_SETTING)
            self._key = bytes.fromhex(legacy) if legacy else secrets.token_bytes(32)
            store.set_setting(
                self._KEY_SETTING, base64.b64encode(protector.wrap(self._key)).decode("ascii")
            )
            if legacy:
                store.delete_setting(self._LEGACY_SETTING)
        self._cache: set[tuple[str, str]] | None = None

    def _fingerprint(self, value: str) -> str:
        canonical = normalize(value) or value.strip()
        return hmac.new(self._key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()

    def add(self, entity_type: str, value: str) -> None:
        with self._store.db.transaction() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO allow_list (id, value_hmac, entity_type, created_at) "
                "VALUES (?, ?, ?, ?)",
                (f"allow_{uuid.uuid4().hex[:12]}", self._fingerprint(value), entity_type, now()),
            )
        self._cache = None

    def count(self) -> int:
        return int(self._store.db.query("SELECT COUNT(*) AS n FROM allow_list")[0]["n"])

    def clear(self) -> None:
        with self._store.db.transaction() as conn:
            conn.execute("DELETE FROM allow_list")
        self._cache = None

    def contains(self, entity_type: str, value: str) -> bool:
        if self._cache is None:
            self._cache = {
                (r["entity_type"], r["value_hmac"])
                for r in self._store.db.query("SELECT entity_type, value_hmac FROM allow_list")
            }
        if not self._cache:
            return False
        return (entity_type, self._fingerprint(value)) in self._cache
