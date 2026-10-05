"""Credential and secret detectors; Phase 4 policy maps them to BLOCK by default.

Two families:

* **Provider tokens** with a documented, recognisable shape (``AKIA…``,
  ``ghp_…``, ``xoxb-…``, PEM private keys, JWTs). These are matched anywhere.
* **Assigned secrets**: a value assigned to a key whose name says it is a
  secret (``password=``, ``"client_secret":``, ``DB_PASS:``), plus
  credentials embedded in connection strings and URLs. Placeholders such as
  ``${DB_PASSWORD}``, ``<your-key>`` or ``changeme`` are ignored.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Iterator

from airlock_engine.core.interfaces import Detector
from airlock_engine.core.models import DetectionResult, TextSegment
from airlock_engine.detectors.base import result

_B = r"(?<![A-Za-z0-9_\-])"  # left token boundary
_E = r"(?![A-Za-z0-9_\-])"  # right token boundary


#: (rule id, entity type, pattern, value group). Group 0 = whole match.
_TOKENS: tuple[tuple[str, str, re.Pattern[str], int], ...] = (
    (
        "secret.aws_access_key",
        "CLOUD_KEY",
        re.compile(_B + r"(?:AKIA|ASIA|ABIA|ACCA|AROA|AIDA)[A-Z2-7]{16}" + _E),
        0,
    ),
    (
        "secret.github_token",
        "API_KEY",
        re.compile(_B + r"(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{60,255})" + _E),
        0,
    ),
    ("secret.gitlab_token", "API_KEY", re.compile(_B + r"glpat-[A-Za-z0-9_\-]{20,}" + _E), 0),
    (
        "secret.slack_token",
        "API_KEY",
        re.compile(_B + r"xox[abposr]-[A-Za-z0-9]{8,}(?:-[A-Za-z0-9]{4,})+" + _E),
        0,
    ),
    (
        "secret.slack_webhook",
        "API_KEY",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{16,}"),
        0,
    ),
    (
        "secret.stripe_key",
        "API_KEY",
        re.compile(_B + r"(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}" + _E),
        0,
    ),
    ("secret.google_api_key", "API_KEY", re.compile(_B + r"AIza[0-9A-Za-z_\-]{35}" + _E), 0),
    (
        "secret.openai_key",
        "API_KEY",
        re.compile(
            _B + r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}" + _E
        ),
        0,
    ),
    (
        "secret.anthropic_key",
        "API_KEY",
        re.compile(_B + r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}" + _E),
        0,
    ),
    (
        "secret.generic_sk_key",
        "API_KEY",
        re.compile(_B + r"sk-(?:proj-|live-)?[A-Za-z0-9]{32,}" + _E),
        0,
    ),
    (
        "secret.sendgrid_key",
        "API_KEY",
        re.compile(_B + r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}" + _E),
        0,
    ),
    ("secret.twilio_key", "API_KEY", re.compile(_B + r"SK[0-9a-f]{32}" + _E), 0),
    ("secret.npm_token", "API_KEY", re.compile(_B + r"npm_[A-Za-z0-9]{36}" + _E), 0),
    (
        "secret.azure_storage_key",
        "CLOUD_KEY",
        re.compile(r"(?i)AccountKey=([A-Za-z0-9+/]{86}==)"),
        1,
    ),
    (
        "secret.azure_sas",
        "CLOUD_KEY",
        re.compile(r"(?i)(?:SharedAccessSignature|[?&]sig)=([A-Za-z0-9%+/=]{40,})"),
        1,
    ),
)

_PEM = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
    r"[\s\S]{16,16384}?"
    r"-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
)
_PEM_OPEN = re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY")

_JWT = re.compile(_B + r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{16,}" + _E)

# scheme://user:password@host — the password group is the secret.
_URL_CREDENTIALS = re.compile(
    r"(?i)\b[a-z][a-z0-9+.\-]{1,20}://[^\s:/@\"'<>]{1,128}:([^\s@/\"'<>]{1,256})@[\w.\-\[\]]+"
)
# ADO/ODBC/JDBC style: "Password=...;" / "Pwd=..."
_KV_CONNECTION = re.compile(r"(?i)(?<![\w])(?:password|pwd)\s*=\s*([^;\s\"']{1,256})")
#: Other keys that make "Password=…" part of an ADO/ODBC/JDBC connection string.
_CONNECTION_KEYS = re.compile(
    r"(?i)jdbc:|(?:server|data source|host|user id|uid|database|databasename|initial catalog"
    r"|dsn|provider)\s*="
)

_SECRET_KEY_WORD = re.compile(
    r"(?i)password|passwd|passphrase|pass(?![a-z])|pwd|secret|token|api[_\-]?key|apikey|"
    r"access[_\-]?key|"
    r"private[_\-]?key|auth[_\-]?key|credential|signing[_\-]?key|encryption[_\-]?key|"
    r"master[_\-]?key"
)
_KEY_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")
# After the key name: optional closing quote, an assignment operator, then the value.
_VALUE = re.compile(
    r"[\"']?[ \t]*(:=|=>|=|:)[ \t]*"
    r"(?:\"([^\"\r\n]{1,512})\"|'([^'\r\n]{1,512})'|([^\s,;\"'}\]]{1,512}))"
)
_BEARER = re.compile(r"(?i)\b(?:authorization\s*:\s*)?bearer\s+([A-Za-z0-9_\-.=+/]{20,})")

_PLACEHOLDER = re.compile(
    r"""(?ix)^(?:
        \$\{[^}]*\}?|\$\(?[A-Za-z_][A-Za-z0-9_]*\)?|%[A-Za-z_][A-Za-z0-9_]*%|\{\{[^}]*\}\}
        |<[^>]*>|\[[^\]]*\]|\*+|x+|\.{3,}|•+
        |(?:your|my|the)[_\-\s]?.*|.*[_\-]?here
        |changeme|change[_\-]?me|placeholder|example|sample|dummy|test|testing|todo|tbd|fixme
        |none|null|nil|undefined|false|true|empty|redacted|hidden|secret|password|passwd
        |required|optional|string|str|env|os\.environ.*|process\.env.*|getenv.*
        |settings\..*|config\..*|self\..*|this\..*|request\..*|args\..*|kwargs.*
    )$"""
)


def _is_plausible_secret(value: str) -> bool:
    value = value.strip()
    if len(value) < 6 or _PLACEHOLDER.match(value):
        return False
    if value.endswith(("(", ")")) or "(" in value:
        return False  # a function call, e.g. get_secret("db")
    return not (value.isalpha() and value.islower() and len(value) < 10)


def _jwt_valid(token: str) -> bool:
    header = token.split(".", 1)[0]
    try:
        decoded = base64.urlsafe_b64decode(header + "=" * (-len(header) % 4))
        return isinstance(json.loads(decoded), dict) and "alg" in json.loads(decoded)
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False


class SecretDetector(Detector):
    name = "secrets"

    def detect(self, segment: TextSegment) -> Iterator[DetectionResult]:
        text = segment.text
        if len(text) < 8:
            return
        seen: list[tuple[int, int]] = []

        def emit(
            rule: str, entity_type: str, start: int, end: int, conf: float
        ) -> Iterator[DetectionResult]:
            if end <= start or any(s <= start and end <= e for s, e in seen):
                return
            seen.append((start, end))
            yield result(segment, entity_type, start, end, detector=rule, confidence=conf)

        if "PRIVATE KEY" in text:
            for m in _PEM.finditer(text):
                yield from emit("secret.private_key", "PRIVATE_KEY", m.start(), m.end(), 0.99)
            # A header without a matching footer (truncated paste) is still a key.
            for m in _PEM_OPEN.finditer(text):
                if not any(s <= m.start() < e for s, e in seen):
                    line_end = text.find("\n\n", m.end())
                    end = len(text) if line_end == -1 else line_end
                    yield from emit("secret.private_key", "PRIVATE_KEY", m.start(), end, 0.95)

        for rule, entity_type, pattern, group in _TOKENS:
            for m in pattern.finditer(text):
                yield from emit(rule, entity_type, m.start(group), m.end(group), 0.97)

        if "eyJ" in text:
            for m in _JWT.finditer(text):
                if _jwt_valid(m.group()):
                    yield from emit("secret.jwt", "ACCESS_TOKEN", m.start(), m.end(), 0.97)

        if "://" in text:
            for m in _URL_CREDENTIALS.finditer(text):
                if _is_plausible_secret(m.group(1)):
                    yield from emit(
                        "secret.url_credentials", "CONNECTION_STRING", m.start(1), m.end(1), 0.95
                    )

        lower = text.lower()
        if "bearer" in lower:
            for m in _BEARER.finditer(text):
                yield from emit("secret.bearer_token", "ACCESS_TOKEN", m.start(1), m.end(1), 0.93)
        if (
            ("pwd" in lower or "password" in lower)
            and ";" in text
            and _CONNECTION_KEYS.search(text)
        ):
            for m in _KV_CONNECTION.finditer(text):
                if _is_plausible_secret(m.group(1)):
                    yield from emit(
                        "secret.connection_password",
                        "CONNECTION_STRING",
                        m.start(1),
                        m.end(1),
                        0.93,
                    )
        done_keys: set[int] = set()
        for hit in _SECRET_KEY_WORD.finditer(text):
            key_start, key_end = hit.start(), hit.end()
            while key_start > 0 and text[key_start - 1] in _KEY_CHARS:
                key_start -= 1
            while key_end < len(text) and text[key_end] in _KEY_CHARS:
                key_end += 1
            if key_end in done_keys or key_end - key_start > 80:
                continue
            done_keys.add(key_end)
            vm = _VALUE.match(text, key_end)
            if vm is None:
                continue
            group = next(g for g in (2, 3, 4) if vm.group(g) is not None)
            value = vm.group(group)
            stripped = value.strip()
            if not _is_plausible_secret(stripped):
                continue
            prose = group == 4 and vm.group(1) == ":" and stripped.isalpha()
            if prose:
                continue  # "Secret: classified" in running text
            start = vm.start(group) + (len(value) - len(value.lstrip()))
            yield from emit("secret.assigned", "PASSWORD", start, start + len(stripped), 0.92)

        # Context from a spreadsheet header ("Password" column).
        if (
            segment.context
            and len(segment.context) < 64
            and _SECRET_KEY_WORD.search(segment.context)
        ):
            value = text.strip()
            if _is_plausible_secret(value) and " " not in value:
                start = text.index(value)
                yield from emit("secret.assigned", "PASSWORD", start, start + len(value), 0.9)


def builtin_secret_detectors() -> list[Detector]:
    return [SecretDetector()]
