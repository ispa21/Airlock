"""Government and financial identifiers: PAN, Aadhaar, GSTIN, IFSC, bank
account, payment card and IBAN."""

from __future__ import annotations

import re

from airlock_engine.core.interfaces import Detector
from airlock_engine.core.models import TextSegment
from airlock_engine.detectors.base import (
    Candidate,
    PatternDetector,
    digits_only,
    glued,
    has_context,
    has_digit,
    keywords,
)
from airlock_engine.detectors.checksums import (
    card_brand_valid,
    gstin_valid,
    iban_valid,
    luhn_valid,
    pan_valid,
    verhoeff_valid,
)

# --- PAN ---------------------------------------------------------------------

_PAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Za-z]{3}[ABCFGHJLPTKabcfghjlptk][A-Za-z]\d{4}[A-Za-z]"
    r"(?![A-Za-z0-9])"
)
_PAN_CONTEXT = keywords("pan", "permanent account number", "income tax", "pan no", "pan card")


def _pan(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    value = m.group()
    context = has_context(segment, m.start(), m.end(), _PAN_CONTEXT)
    if not value.isupper():
        # Lower/mixed case only with explicit context ("pan: abcpe1234f").
        if not context:
            return None
        value = value.upper()
    if not pan_valid(value):
        return None
    return Candidate(m.start(), m.end(), 0.97 if context else 0.9)


def pan_detector() -> Detector:
    return PatternDetector("regex.pan", "PAN", _PAN, _pan, prefilter=has_digit)


# --- Aadhaar -----------------------------------------------------------------

# Not part of a longer grouped number (a card or IBAN printed in blocks of four).
_AADHAAR = re.compile(
    r"(?<![\w./-])(?<!\d,)(?<!\d[ -])[2-9]\d{3}([ -]?)\d{4}\1\d{4}(?![\w/-]|[.,]\d|[ -]\d)"
)
_AADHAAR_CONTEXT = keywords("aadhaar", "aadhar", "adhaar", "uid", "uidai", "आधार", "enrolment")


def _aadhaar(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    digits = digits_only(m.group())
    if not verhoeff_valid(digits):
        return None
    grouped = bool(m.group(1))
    context = has_context(segment, m.start(), m.end(), _AADHAAR_CONTEXT)
    if context:
        return Candidate(m.start(), m.end(), 0.99)
    if grouped:
        return Candidate(m.start(), m.end(), 0.9)
    # 12 contiguous digits pass Verhoeff 1 time in 10: needs context.
    return None


def aadhaar_detector() -> Detector:
    return PatternDetector("regex.aadhaar", "AADHAAR", _AADHAAR, _aadhaar, prefilter=has_digit)


# --- GSTIN -------------------------------------------------------------------

_GSTIN = re.compile(
    r"(?<![A-Za-z0-9])\d{2}[A-Za-z]{5}\d{4}[A-Za-z][0-9A-Za-z][Zz][0-9A-Za-z]"
    r"(?![A-Za-z0-9])"
)


def _gstin(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    if not gstin_valid(m.group().upper()):
        return None
    return Candidate(m.start(), m.end(), 0.99)


def gstin_detector() -> Detector:
    return PatternDetector("regex.gstin", "GSTIN", _GSTIN, _gstin, prefilter=has_digit)


# --- IFSC --------------------------------------------------------------------

_IFSC = re.compile(r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])")
_IFSC_CONTEXT = keywords("ifsc", "ifs code", "branch code", "rtgs", "neft", "imps", "bank")


def _ifsc(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    value = m.group()
    tail = value[5:]
    if not any(ch.isdigit() for ch in tail):
        return None  # e.g. a word in capitals
    context = has_context(segment, m.start(), m.end(), _IFSC_CONTEXT)
    # Branch codes are usually numeric; alphanumeric ones need context.
    if not tail.isdigit() and not context:
        return None
    return Candidate(m.start(), m.end(), 0.97 if context else 0.9)


def ifsc_detector() -> Detector:
    return PatternDetector("regex.ifsc", "IFSC", _IFSC, _ifsc, prefilter=has_digit)


# --- Payment cards -----------------------------------------------------------

_ACCOUNT_CONTEXT = keywords(
    "account",
    "a/c",
    "acct",
    "acc no",
    "ac no",
    "account no",
    "account number",
    "bank",
    "savings",
    "current account",
    "beneficiary",
    "khata",
    "खाता",
)

# A comma or period may end the sentence, but not separate digit groups (1,234.56).
_CARD = re.compile(r"(?<![\w./-])(?<!\d,)\d(?:[ -]?\d){12,18}(?![\w/-]|[.,]\d)")
_CARD_CONTEXT = keywords(
    "card", "credit", "debit", "visa", "mastercard", "amex", "rupay", "cc", "card no", "card number"
)


def _card(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    raw = m.group()
    digits = digits_only(raw)
    separators = {ch for ch in raw if not ch.isdigit()}
    if len(separators) > 1:
        return None
    if separators:
        groups = [len(g) for g in re.split(r"[ -]", raw)]
        if groups not in (
            [4, 4, 4, 4],
            [4, 6, 5],
            [4, 6, 4],
            [4, 4, 4, 4, 3],
            [4, 4, 4, 2],
            [4, 4, 4, 4, 2],
            [4, 4, 4, 3],
            [4, 4, 5],
            [4, 6, 6],
        ):
            return None
    if not (luhn_valid(digits) and card_brand_valid(digits)):
        return None
    if len(set(digits)) <= 2:
        return None  # 4444 4444 4444 4448 style filler
    context = has_context(segment, m.start(), m.end(), _CARD_CONTEXT)
    if (
        not separators
        and not context
        and has_context(segment, m.start(), m.end(), _ACCOUNT_CONTEXT)
    ):
        return None  # "A/c no. 5863…": an account number that happens to pass Luhn
    return Candidate(m.start(), m.end(), 0.99 if context or separators else 0.95)


def card_detector() -> Detector:
    return PatternDetector("regex.card", "CREDIT_CARD", _CARD, _card, prefilter=has_digit)


# --- Bank account ------------------------------------------------------------

_ACCOUNT = re.compile(r"(?<![\w./-])(?<!\d,)\d(?:[ -]?\d){8,17}(?![\w/-]|[.,]\d)")


def _account(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    raw = m.group()
    digits = digits_only(raw)
    if not 9 <= len(digits) <= 18 or len(set(digits)) == 1:
        return None
    if glued(segment.text, m.start(), m.end()):
        return None
    if not has_context(segment, m.start(), m.end(), _ACCOUNT_CONTEXT):
        return None
    return Candidate(m.start(), m.end(), 0.85)


def bank_account_detector() -> Detector:
    return PatternDetector(
        "regex.bank_account", "BANK_ACCOUNT", _ACCOUNT, _account, prefilter=has_digit
    )


# --- IBAN --------------------------------------------------------------------

_IBAN = re.compile(
    r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?"
    r"(?![A-Za-z0-9])"
)


def _iban(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    if not iban_valid(m.group()):
        return None
    return Candidate(m.start(), m.end(), 0.99)


def iban_detector() -> Detector:
    return PatternDetector("regex.iban", "IBAN", _IBAN, _iban, prefilter=has_digit)
