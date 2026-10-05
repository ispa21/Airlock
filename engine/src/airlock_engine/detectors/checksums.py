"""Checksum and structure validators for identifiers.

A checksum turns "looks like a number" into "is almost certainly this id",
which is what lets these detectors hold a ≥ 0.98 precision gate.
"""

from __future__ import annotations

import re
import string

# --- Luhn (payment cards) ----------------------------------------------------


def luhn_valid(digits: str) -> bool:
    if not digits.isdigit() or len(digits) < 2:
        return False
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def luhn_check_digit(payload: str) -> str:
    for d in "0123456789":
        if luhn_valid(payload + d):
            return d
    raise AssertionError("unreachable")


# --- Verhoeff (Aadhaar) ------------------------------------------------------

_V_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_V_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_V_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(digits: str) -> bool:
    if not digits.isdigit():
        return False
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _V_D[c][_V_P[i % 8][ord(ch) - 48]]
    return c == 0


def verhoeff_check_digit(payload: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(payload)):
        c = _V_D[c][_V_P[(i + 1) % 8][ord(ch) - 48]]
    return str(_V_INV[c])


# --- PAN ---------------------------------------------------------------------

#: Fourth character of a PAN: the holder type (person, company, firm, trust...).
PAN_HOLDER_TYPES = "ABCFGHJLPTK"
PAN_SHAPE = re.compile(r"^[A-Z]{3}[ABCFGHJLPTK][A-Z][0-9]{4}[A-Z]$")


def pan_valid(value: str) -> bool:
    # The last character is a check letter, but the algorithm is not public;
    # validation is structural (holder type + shape).
    return bool(PAN_SHAPE.match(value)) and value[5:9] != "0000"


# --- GSTIN -------------------------------------------------------------------

_GST_CHARS = string.digits + string.ascii_uppercase
#: GST state codes in use (01-38), plus 97 (other territory) and 99 (centre jurisdiction).
_GST_STATES = frozenset({f"{n:02d}" for n in range(1, 39)} | {"97", "99"})


def gstin_check_char(payload14: str) -> str:
    total = 0
    for i, ch in enumerate(payload14):
        value = _GST_CHARS.index(ch) * (2 if i % 2 else 1)
        total += value // 36 + value % 36
    return _GST_CHARS[(36 - total % 36) % 36]


def gstin_valid(value: str) -> bool:
    if len(value) != 15 or any(ch not in _GST_CHARS for ch in value):
        return False
    if value[:2] not in _GST_STATES or not pan_valid(value[2:12]):
        return False
    if value[12] == "0":
        return False
    return gstin_check_char(value[:14]) == value[14]


# --- IBAN --------------------------------------------------------------------

#: Lengths for common IBAN countries; others accept 15-34.
_IBAN_LENGTHS = {
    "AE": 23,
    "AT": 20,
    "BE": 16,
    "CH": 21,
    "CY": 28,
    "CZ": 24,
    "DE": 22,
    "DK": 18,
    "EE": 20,
    "ES": 24,
    "FI": 18,
    "FR": 27,
    "GB": 22,
    "GR": 27,
    "HR": 21,
    "HU": 28,
    "IE": 22,
    "IT": 27,
    "LT": 20,
    "LU": 20,
    "LV": 21,
    "MT": 31,
    "NL": 18,
    "NO": 15,
    "PL": 28,
    "PT": 25,
    "QA": 29,
    "RO": 24,
    "SA": 24,
    "SE": 24,
    "SI": 19,
    "SK": 24,
}


def iban_valid(value: str) -> bool:
    iban = value.replace(" ", "").upper()
    if not 15 <= len(iban) <= 34 or not iban[:2].isalpha() or not iban[2:4].isdigit():
        return False
    expected = _IBAN_LENGTHS.get(iban[:2])
    if expected is not None and len(iban) != expected:
        return False
    if not iban.isalnum() or not iban.isascii():
        return False
    rearranged = iban[4:] + iban[:4]
    number = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(number) % 97 == 1


# --- Payment card brand ranges -----------------------------------------------


def card_brand_valid(digits: str) -> bool:
    """IIN ranges of the major networks, including RuPay."""
    n = len(digits)
    if not 13 <= n <= 19:
        return False
    p2, p4, p6 = int(digits[:2]), int(digits[:4]), int(digits[:6])
    if digits[0] == "4":
        return n in (13, 16, 19)  # Visa
    if 51 <= p2 <= 55 or 2221 <= p4 <= 2720:
        return n == 16  # Mastercard
    if p2 in (34, 37):
        return n == 15  # American Express
    if p4 == 6011 or p2 == 65 or 644 <= int(digits[:3]) <= 649 or 622126 <= p6 <= 622925:
        return 16 <= n <= 19  # Discover / RuPay 65
    if p2 in (60, 81, 82) or int(digits[:3]) == 508 or p4 == 6521 or p4 == 6522:
        return n == 16  # RuPay
    if 3528 <= p4 <= 3589:
        return 16 <= n <= 19  # JCB
    if p2 in (36, 38, 39) or 300 <= int(digits[:3]) <= 305:
        return 14 <= n <= 19  # Diners
    if p2 == 50 or 56 <= p2 <= 69:
        return 12 <= n <= 19  # Maestro
    return p2 == 62 and 16 <= n <= 19  # UnionPay
