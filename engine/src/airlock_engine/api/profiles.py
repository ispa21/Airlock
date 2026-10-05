"""``profiles.*`` methods: privacy profiles and their entity → action table."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.core.models import Action, Category
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.ipc.server import InvalidParams, MethodRegistry, RequestContext, require_str
from airlock_engine.policy.profiles import GENERALIZABLE, MASK_STYLES, Profile
from airlock_engine.storage import ProfileError, ProfileNotFound, Storage, StorageError

T = TypeVar("T")


def _guard(fn: Callable[[], T]) -> T:
    try:
        return fn()
    except ProfileNotFound as exc:
        raise errors.profile_not_found() from exc
    except ProfileError as exc:
        raise errors.invalid_profile(str(exc)) from exc
    except StorageError as exc:
        raise errors.storage_unavailable() from exc


def register(registry: MethodRegistry, storage: Storage) -> None:
    def entity_types() -> list[dict[str, Any]]:
        rows = [
            {"id": e.id, "label": e.label, "category": e.category.value, "company_rule": False}
            for e in BUILTIN_ENTITIES.values()
        ]
        rows += [
            {"id": c.id, "label": c.label, "category": c.group, "company_rule": True}
            for c in storage.rules.categories()
            if c.id not in BUILTIN_ENTITIES
        ]
        for row in rows:
            row["generalizable"] = row["id"] in GENERALIZABLE
        return rows

    def to_json(profile: Profile, types: list[dict[str, Any]], default_id: str) -> dict[str, Any]:
        table = {}
        for t in types:
            action, source = profile.resolve(
                t["id"], Category(t["category"]), company_rule=t["company_rule"]
            )
            table[t["id"]] = {"action": action.value, "source": source}
        return {
            "id": profile.id,
            "name": profile.name,
            "description": profile.description,
            "builtin": profile.builtin,
            "base_id": profile.base_id,
            "default": profile.id == default_id,
            "min_confidence": profile.min_confidence,
            "mask_style": profile.mask_style,
            "actions": table,
        }

    def list_profiles(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            store = storage.profiles
            types = entity_types()
            default_id = store.default_id()
            return {
                "profiles": [to_json(p, types, default_id) for p in store.all()],
                "default_id": default_id,
                "entity_types": types,
                "actions": [a.value for a in Action],
                "mask_styles": list(MASK_STYLES),
            }

        return _guard(run)

    def create(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        name = require_str(params, "name", max_len=200)
        base_id = require_str(params, "base_id", max_len=64)

        def run() -> dict[str, Any]:
            store = storage.profiles
            profile = store.create(name, base_id)
            safelog.log.info("profile_created")
            return {"profile": to_json(profile, entity_types(), store.default_id())}

        return _guard(run)

    def update(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        profile_id = require_str(params, "id", max_len=64)
        name = params.get("name")
        if name is not None and not isinstance(name, str):
            raise InvalidParams("'name' must be a string")
        raw_actions = params.get("actions", {})
        if not isinstance(raw_actions, dict):
            raise InvalidParams("'actions' must be an object of entity type → action or null")
        actions: dict[str, Action | None] = {}
        for entity_type, action in raw_actions.items():
            valid = action is None or (isinstance(action, str) and action in Action.__members__)
            if not valid:
                raise InvalidParams("each action must be an action name or null")
            actions[str(entity_type)] = Action(action) if action is not None else None
        min_confidence = params.get("min_confidence")
        if min_confidence is not None and (
            isinstance(min_confidence, bool) or not isinstance(min_confidence, int | float)
        ):
            raise InvalidParams("'min_confidence' must be a number")
        mask_style = params.get("mask_style")
        if mask_style is not None and not isinstance(mask_style, str):
            raise InvalidParams("'mask_style' must be a string")

        def run() -> dict[str, Any]:
            store = storage.profiles
            types = entity_types()
            profile = store.update(
                profile_id,
                name=name,
                actions=actions,
                min_confidence=float(min_confidence) if min_confidence is not None else None,
                mask_style=mask_style,
                known_types={t["id"] for t in types},
            )
            safelog.log.info("profile_updated", entity_count=len(actions))
            return {"profile": to_json(profile, types, store.default_id())}

        return _guard(run)

    def delete(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        profile_id = require_str(params, "id", max_len=64)

        def run() -> dict[str, Any]:
            storage.profiles.delete(profile_id)
            safelog.log.info("profile_deleted")
            return {"ok": True, "default_id": storage.profiles.default_id()}

        return _guard(run)

    def set_default(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        profile_id = require_str(params, "id", max_len=64)

        def run() -> dict[str, Any]:
            storage.profiles.set_default(profile_id)
            return {"ok": True, "default_id": profile_id}

        return _guard(run)

    registry.register("profiles.list", list_profiles)
    registry.register("profiles.create", create)
    registry.register("profiles.update", update)
    registry.register("profiles.delete", delete)
    registry.register("profiles.set_default", set_default)
