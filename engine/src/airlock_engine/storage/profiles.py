"""Privacy profiles: built-ins come from code, custom profiles from SQLite.

A custom profile names the built-in profile it was copied from (``base_id``)
and stores only its own entity → action choices in ``policy_rules``. Built-in
profiles cannot be edited; the user duplicates one to customise it.
"""

from __future__ import annotations

import re
import uuid
from typing import Any

from airlock_engine.core.models import Action
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.policy.profiles import (
    BUILTIN_PROFILES,
    DEFAULT_PROFILE_ID,
    GENERALIZABLE,
    MASK_STYLES,
    Profile,
)
from airlock_engine.storage.db import Database, now

_DEFAULT_SETTING = "default_profile"
_NAME = re.compile(r"^[^\x00-\x1f]{2,60}$")


class ProfileError(ValueError):
    """A profile change is invalid. The message is safe to show the user."""


class ProfileNotFound(LookupError):
    pass


class ProfileStore:
    def __init__(self, db: Database) -> None:
        self.db = db

    # --- reading -----------------------------------------------------------

    def all(self) -> list[Profile]:
        custom = [
            self._load(r)
            for r in self.db.query(
                "SELECT * FROM privacy_profiles WHERE is_builtin = 0 ORDER BY created_at, id"
            )
        ]
        return [*BUILTIN_PROFILES.values(), *custom]

    def get(self, profile_id: str) -> Profile:
        if profile_id in BUILTIN_PROFILES:
            return BUILTIN_PROFILES[profile_id]
        rows = self.db.query(
            "SELECT * FROM privacy_profiles WHERE id = ? AND is_builtin = 0", (profile_id,)
        )
        if not rows:
            raise ProfileNotFound(profile_id)
        return self._load(rows[0])

    def _load(self, row: Any) -> Profile:
        base = BUILTIN_PROFILES.get(row["base_id"] or "", BUILTIN_PROFILES[DEFAULT_PROFILE_ID])
        actions = dict(base.actions)
        for r in self.db.query(
            "SELECT entity_type, action FROM policy_rules WHERE profile_id = ?", (row["id"],)
        ):
            actions[r["entity_type"]] = Action(r["action"])
        return base.with_changes(
            id=row["id"],
            name=row["name"],
            description=f"Custom profile based on {base.name}.",
            builtin=False,
            base_id=base.id,
            actions=actions,
            min_confidence=row["min_confidence"]
            if row["min_confidence"] is not None
            else base.min_confidence,
            mask_style=row["mask_style"] or base.mask_style,
        )

    def default_id(self) -> str:
        rows = self.db.query("SELECT value FROM settings WHERE key = ?", (_DEFAULT_SETTING,))
        if rows:
            value = str(rows[0]["value"])
            try:
                self.get(value)
                return value
            except ProfileNotFound:
                pass
        return DEFAULT_PROFILE_ID

    # --- writing -----------------------------------------------------------

    def set_default(self, profile_id: str) -> None:
        self.get(profile_id)
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO settings (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (_DEFAULT_SETTING, profile_id),
            )

    def create(self, name: str, base_id: str) -> Profile:
        name = _check_name(name)
        source = self.get(base_id)
        root = source.base_id if not source.builtin and source.base_id else source.id
        profile_id = f"profile_{uuid.uuid4().hex[:12]}"
        stamp = now()
        base = BUILTIN_PROFILES[root]
        with self.db.transaction() as conn:
            conn.execute(
                "INSERT INTO privacy_profiles (id, name, is_builtin, created_at, updated_at, "
                "base_id, min_confidence, mask_style) VALUES (?, ?, 0, ?, ?, ?, ?, ?)",
                (
                    profile_id,
                    name,
                    stamp,
                    stamp,
                    root,
                    None if source.min_confidence == base.min_confidence else source.min_confidence,
                    None if source.mask_style == base.mask_style else source.mask_style,
                ),
            )
            # Copy only what differs from the root built-in profile.
            conn.executemany(
                "INSERT INTO policy_rules (profile_id, entity_type, action) VALUES (?, ?, ?)",
                [
                    (profile_id, entity_type, action.value)
                    for entity_type, action in source.actions.items()
                    if base.actions.get(entity_type) is not action
                ],
            )
        return self.get(profile_id)

    def update(
        self,
        profile_id: str,
        *,
        name: str | None = None,
        actions: dict[str, Action | None] | None = None,
        min_confidence: float | None = None,
        mask_style: str | None = None,
        known_types: set[str] | None = None,
    ) -> Profile:
        current = self.get(profile_id)
        if current.builtin:
            raise ProfileError("Built-in profiles can't be changed. Duplicate it to customise it.")
        known = (known_types or set()) | set(BUILTIN_ENTITIES)
        for entity_type, action in (actions or {}).items():
            if entity_type not in known:
                raise ProfileError("One of the data types in this change is not known.")
            if action is Action.GENERALIZE and entity_type not in GENERALIZABLE:
                raise ProfileError("This data type has no generalised form. Choose mask instead.")
        if min_confidence is not None and not 0.0 <= min_confidence <= 1.0:
            raise ProfileError("The confidence threshold must be between 0 and 100%.")
        if mask_style is not None and mask_style not in MASK_STYLES:
            raise ProfileError("Choose a valid placeholder style.")
        base = BUILTIN_PROFILES[current.base_id or DEFAULT_PROFILE_ID]
        with self.db.transaction() as conn:
            if name is not None:
                conn.execute(
                    "UPDATE privacy_profiles SET name = ? WHERE id = ?",
                    (_check_name(name), profile_id),
                )
            if min_confidence is not None:
                conn.execute(
                    "UPDATE privacy_profiles SET min_confidence = ? WHERE id = ?",
                    (min_confidence, profile_id),
                )
            if mask_style is not None:
                conn.execute(
                    "UPDATE privacy_profiles SET mask_style = ? WHERE id = ?",
                    (mask_style, profile_id),
                )
            for entity_type, action in (actions or {}).items():
                conn.execute(
                    "DELETE FROM policy_rules WHERE profile_id = ? AND entity_type = ?",
                    (profile_id, entity_type),
                )
                # None resets the type to the base profile's behaviour.
                if action is not None and base.actions.get(entity_type) is not action:
                    conn.execute(
                        "INSERT INTO policy_rules (profile_id, entity_type, action) "
                        "VALUES (?, ?, ?)",
                        (profile_id, entity_type, action.value),
                    )
            conn.execute(
                "UPDATE privacy_profiles SET updated_at = ? WHERE id = ?", (now(), profile_id)
            )
        return self.get(profile_id)

    def delete(self, profile_id: str) -> None:
        current = self.get(profile_id)
        if current.builtin:
            raise ProfileError("Built-in profiles can't be deleted.")
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM privacy_profiles WHERE id = ?", (profile_id,))
            conn.execute(
                "DELETE FROM settings WHERE key = ? AND value = ?", (_DEFAULT_SETTING, profile_id)
            )


def _check_name(name: str) -> str:
    name = name.strip()
    if not _NAME.match(name):
        raise ProfileError("A profile name needs 2 to 60 characters.")
    return name
