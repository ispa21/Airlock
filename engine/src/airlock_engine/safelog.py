"""Structured logging that cannot carry document content.

Only allowlisted fields are emitted, and string values must be short
identifier-like tokens (``[a-z0-9_.-]``). Anything else is dropped and counted.
That structurally rules out names, e-mail addresses, numbers with separators,
paths and free text from ever reaching a log line (PRD §33).

Log lines are JSON objects written to stderr; the desktop host persists them.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from typing import IO, Any, Final

_TOKEN = re.compile(r"^[a-z0-9_.\-]{1,64}$")
#: Python class names ("OSError", "RegistryError") are code, not content.
_CLASS_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")

# field -> allowed python types
_FIELDS: Final[dict[str, tuple[type, ...]]] = {
    "event": (str,),
    "level": (str,),
    "method": (str,),
    "file_type": (str,),
    "format": (str,),
    "error_kind": (str,),
    "detector": (str,),
    "entity_type": (str,),
    "entity_count": (int,),
    "segment_count": (int,),
    "finding_count": (int,),
    "remaining_count": (int,),
    "size_bytes": (int,),
    "duration_ms": (int, float),
    "request_id": (int,),
    "pid": (int,),
    "version": (str,),
    "protocol": (str,),
    "status": (str,),
    "exception_type": (str,),
    "logger": (str,),
}

_LEVELS: Final = ("debug", "info", "warning", "error")


class SafeLogger:
    def __init__(self, stream: IO[str] | None = None, level: str = "info") -> None:
        self._stream = stream
        self._min = _LEVELS.index(level) if level in _LEVELS else 1
        self.dropped_fields = 0

    def _out(self) -> IO[str]:
        return self._stream if self._stream is not None else sys.stderr

    def log(self, level: str, event: str, **fields: Any) -> None:
        if level not in _LEVELS or _LEVELS.index(level) < self._min:
            return
        record: dict[str, Any] = {"ts": round(time.time(), 3)}
        if not _is_allowed("event", event):
            event = "invalid_event"
        dropped = 0
        for key, value in {"level": level, "event": event, **fields}.items():
            if not _is_allowed(key, value):
                dropped += 1
                continue
            record[key] = value
        if dropped:
            self.dropped_fields += dropped
            record["dropped_fields"] = dropped
        try:
            self._out().write(json.dumps(record, separators=(",", ":")) + "\n")
            self._out().flush()
        except (OSError, ValueError):
            pass  # logging must never break a scan

    def debug(self, event: str, **fields: Any) -> None:
        self.log("debug", event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self.log("info", event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self.log("warning", event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self.log("error", event, **fields)


def _is_allowed(key: str, value: Any) -> bool:
    types = _FIELDS.get(key)
    if types is None or isinstance(value, bool) or not isinstance(value, types):
        return False
    if isinstance(value, str):
        pattern = _CLASS_NAME if key == "exception_type" else _TOKEN
        return bool(pattern.match(value))
    return True


log = SafeLogger()


def configure(level: str) -> None:
    global log
    log = SafeLogger(level=level)
    _silence_third_party()


class _ThirdPartyHandler(logging.Handler):
    """Third-party libraries may log text they parsed. Keep only the fact."""

    def emit(self, record: logging.LogRecord) -> None:
        logger_name = record.name.split(".")[0].lower()
        log.log(
            "warning" if record.levelno >= logging.WARNING else "debug",
            "third_party_log",
            logger=logger_name if _TOKEN.match(logger_name) else "unknown",
        )


def _silence_third_party() -> None:
    root = logging.getLogger()
    root.handlers[:] = [_ThirdPartyHandler()]
    root.setLevel(logging.WARNING)
    logging.captureWarnings(True)
