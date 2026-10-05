"""A string wrapper that refuses to leak through repr, str, format or JSON.

Every value a detector matches is wrapped in :class:`SensitiveValue`. Accidental
``print(finding)``, f-strings, ``logging`` calls or ``json.dumps`` therefore show
``<redacted>`` instead of the secret. Code that genuinely needs the raw value
(masking, verification) must call :meth:`SensitiveValue.reveal` explicitly,
which makes every such access easy to audit with a single grep.
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final

_REDACTED: Final = "<redacted>"
_MASK_CHAR: Final = "•"  # bullet, as used in the privacy report


class SensitiveValue:
    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SensitiveValue wraps str only")
        self._value = value

    def reveal(self) -> str:
        """Return the raw value. Never pass the result to a logger or the UI."""
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return f"SensitiveValue({_REDACTED}, len={len(self._value)})"

    def __str__(self) -> str:
        return _REDACTED

    def __format__(self, format_spec: str) -> str:
        return _REDACTED

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SensitiveValue):
            return hmac.compare_digest(self._value.encode(), other._value.encode())
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("SensitiveValue", self._value))

    def __reduce__(self) -> tuple[object, ...]:
        # Block pickling so values cannot be serialised to disk by accident.
        raise TypeError("SensitiveValue cannot be pickled")

    def fingerprint(self, key: bytes) -> str:
        """Keyed, non-reversible identifier for de-duplicating findings.

        The key is per-session, so fingerprints cannot be correlated across
        sessions or brute-forced from logs.
        """
        return hmac.new(key, self._value.encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def preview(self) -> str:
        """Partially masked form suitable for the privacy report.

        Keeps just enough shape for a human to recognise the finding:
        ``rahul@company.com`` -> ``r••••@company.com``;
        ``ABCDE1234F`` -> ``AB••••••4F``.
        """
        return mask_preview(self._value)


def mask_preview(value: str) -> str:
    if "@" in value:
        local, _, domain = value.partition("@")
        head = local[:1]
        return f"{head}{_MASK_CHAR * max(len(local) - 1, 4)}@{domain}"
    n = len(value)
    if n <= 4:
        return _MASK_CHAR * n
    if n <= 8:
        return value[0] + _MASK_CHAR * (n - 2) + value[-1]
    return value[:2] + _MASK_CHAR * (n - 4) + value[-2:]
