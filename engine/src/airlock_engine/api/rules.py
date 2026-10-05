"""``rules.*`` methods: company rules ("teach Airlock") and their categories.

Rule text is the user's own and is returned to the rules screen, but it is
company-confidential: it is never logged and never appears in error messages.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, TypeVar

from airlock_engine import safelog
from airlock_engine.core import errors
from airlock_engine.detectors.custom import RULE_KINDS, RuleError
from airlock_engine.ipc.server import InvalidParams, MethodRegistry, RequestContext, require_str
from airlock_engine.storage import Storage, StorageError
from airlock_engine.storage.rules import ACTIONS

T = TypeVar("T")

_UPDATABLE = ("kind", "pattern", "category_id", "aliases", "action", "enabled")


def _aliases(params: dict[str, Any]) -> tuple[str, ...]:
    value = params.get("aliases", [])
    if not isinstance(value, list) or not all(isinstance(a, str) for a in value):
        raise InvalidParams("'aliases' must be a list of strings")
    return tuple(value)


def _action(params: dict[str, Any]) -> str | None:
    value = params.get("action")
    if value is not None and not isinstance(value, str):
        raise InvalidParams("'action' must be a string or null")
    return value


def _enabled(params: dict[str, Any]) -> bool:
    value = params.get("enabled", True)
    if not isinstance(value, bool):
        raise InvalidParams("'enabled' must be a boolean")
    return value


def _guard(fn: Callable[[], T]) -> T:
    try:
        return fn()
    except RuleError as exc:
        raise errors.invalid_rule(str(exc)) from exc
    except StorageError as exc:
        raise errors.storage_unavailable() from exc


def register(registry: MethodRegistry, storage: Storage) -> None:
    def list_rules(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            store = storage.rules
            return {
                "rules": [r.to_json() for r in store.all()],
                "categories": [c.to_json() for c in store.categories()],
                "kinds": list(RULE_KINDS),
                "actions": list(ACTIONS),
            }

        return _guard(run)

    def create(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        def run() -> dict[str, Any]:
            row = storage.rules.create(
                kind=require_str(params, "kind", max_len=32),
                pattern=require_str(params, "pattern", max_len=2_000),
                category_id=require_str(params, "category_id", max_len=64),
                aliases=_aliases(params),
                action=_action(params),
                enabled=_enabled(params),
            )
            safelog.log.info("rule_created", status=row.kind)
            return {"rule": row.to_json()}

        return _guard(run)

    def update(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        rule_id = require_str(params, "id", max_len=64)
        changes: dict[str, Any] = {}
        for key in _UPDATABLE:
            if key not in params:
                continue
            if key == "aliases":
                changes[key] = _aliases(params)
            elif key == "action":
                changes[key] = _action(params)
            elif key == "enabled":
                changes[key] = _enabled(params)
            else:
                changes[key] = require_str(params, key, max_len=2_000)

        def run() -> dict[str, Any]:
            row = storage.rules.update(rule_id, **changes)
            if row is None:
                raise errors.rule_not_found()
            safelog.log.info("rule_updated", status=row.kind)
            return {"rule": row.to_json()}

        return _guard(run)

    def delete(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        rule_id = require_str(params, "id", max_len=64)

        def run() -> dict[str, Any]:
            if not storage.rules.delete(rule_id):
                raise errors.rule_not_found()
            safelog.log.info("rule_deleted")
            return {"ok": True}

        return _guard(run)

    def add_category(params: dict[str, Any], ctx: RequestContext) -> dict[str, Any]:
        severity = params.get("severity", 3)
        if not isinstance(severity, int) or isinstance(severity, bool):
            raise InvalidParams("'severity' must be an integer")

        def run() -> dict[str, Any]:
            row = storage.rules.add_category(
                require_str(params, "label", max_len=200),
                require_str(params, "group", max_len=32),
                severity,
            )
            return {"category": row.to_json()}

        return _guard(run)

    registry.register("rules.list", list_rules)
    registry.register("rules.create", create)
    registry.register("rules.update", update)
    registry.register("rules.delete", delete)
    registry.register("rules.add_category", add_category)
