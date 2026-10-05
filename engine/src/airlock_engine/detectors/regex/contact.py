"""E-mail, phone, IP address, URL and date-of-birth detectors."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterator

import phonenumbers

from airlock_engine.core.interfaces import Detector
from airlock_engine.core.models import DetectionResult, TextSegment
from airlock_engine.detectors.base import (
    Candidate,
    PatternDetector,
    glued,
    has_context,
    has_digit,
    keywords,
    result,
)

# --- E-mail ------------------------------------------------------------------

_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+\-])"
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+\-]{0,62}[A-Za-z0-9_%+\-])?"
    r"@(?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}"
    r"(?![A-Za-z0-9\-])"
)

_URL_USERINFO = re.compile(r"://[^\s/@]*:$")


def _email(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    local = m.group().split("@", 1)[0]
    if ".." in local:
        return None
    if _URL_USERINFO.search(segment.text, max(0, m.start() - 160), m.start()):
        return None  # "scheme://user:password@host": the password is a secret, not an e-mail
    return Candidate(m.start(), m.end(), 0.98)


def email_detector() -> Detector:
    return PatternDetector("regex.email", "EMAIL", _EMAIL, _email, prefilter=lambda t: "@" in t)


# --- Phone -------------------------------------------------------------------

_PHONE_CONTEXT = keywords(
    "phone", "ph", "mobile", "mob", "cell", "tel", "telephone", "contact", "call", "whatsapp",
    "fax", "landline", "helpline", "m", "t",
)
#: Reference numbers that look like bare mobile numbers.
_NOT_PHONE_CONTEXT = keywords(
    "order", "invoice", "inv", "ref", "reference", "id", "txn", "transaction", "ticket", "po",
    "sku", "serial", "policy", "awb", "tracking", "utr", "receipt", "challan", "claim", "case",
    "account", "a/c", "acct", "no", "number", "#",
)
_EXTENSION = re.compile(r"[\s,;]*(?:ext\.?|extn\.?|extension|x|#)\s*\d{1,6}$", re.IGNORECASE)
_IP_SHAPE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_TIMESTAMPISH = re.compile(r"\d{1,4}[:/]\d")


class PhoneDetector(Detector):
    """Indian and international numbers, validated against libphonenumber
    metadata (bundled, offline)."""

    name = "regex.phone"

    def __init__(self, default_region: str = "IN") -> None:
        self._region = default_region

    def detect(self, segment: TextSegment) -> Iterator[DetectionResult]:
        text = segment.text
        if sum(ch.isdigit() for ch in text) < 7:
            return
        try:
            matches = list(
                phonenumbers.PhoneNumberMatcher(
                    text, self._region, leniency=phonenumbers.Leniency.VALID, max_tries=10_000
                )
            )
        except Exception:  # pragma: no cover - library defensive
            return
        for m in matches:
            start, end = m.start, m.end
            raw = m.raw_string
            ext = _EXTENSION.search(raw)
            if ext is not None:  # keep the number, not ", ext 12"
                raw = raw[: ext.start()]
                end = start + len(raw)
            if glued(text, start, end) or _TIMESTAMPISH.search(raw) or _IP_SHAPE.match(raw):
                continue
            # Part of a dotted/decimal number (amounts, versions, IPs).
            if (start > 0 and text[start - 1] in ".,") or (
                end < len(text) - 1 and text[end] in ".," and text[end + 1].isdigit()
            ):
                continue
            digits = sum(ch.isdigit() for ch in raw)
            formatted = raw.startswith("+") or any(ch in raw for ch in " -().")
            context = has_context(segment, start, end, _PHONE_CONTEXT)
            if context:
                confidence = 0.95
            elif formatted:
                confidence = 0.85
            elif (
                ((digits == 10 and raw[0] in "6789")
                 or (digits == 11 and raw[:1] == "0" and raw[1:2] in ("6", "7", "8", "9")))
                and not has_context(segment, start, end, _NOT_PHONE_CONTEXT, before=24)
            ):
                confidence = 0.7  # bare Indian mobile number
            else:
                continue  # unformatted digits without context: too ambiguous
            yield result(segment, "PHONE", start, end, detector=self.name, confidence=confidence)


# --- IP address --------------------------------------------------------------

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w]|\.\d)")
_IPV6 = re.compile(
    r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}|(?:\d{1,3}\.){3}\d{1,3})?"
    r"(?![\w:])"
)
_VERSION_CONTEXT = re.compile(
    r"(?:\bv|\bver(?:sion)?|\brelease|\bbuild|\bfirmware|\bupdate|\bpatch|\bkb|\bos)"
    r"[\s.:#-]*$",
    re.IGNORECASE,
)


def _ipv4(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    try:
        address = ipaddress.IPv4Address(m.group())
    except ValueError:
        return None  # octet > 255 or leading zeros
    if int(m.group().split(".", 1)[0]) == 0:
        return None
    if _VERSION_CONTEXT.search(segment.text[max(0, m.start() - 12) : m.start()]):
        return None
    confidence = 0.9 if (address.is_private or address.is_global) else 0.8
    return Candidate(m.start(), m.end(), confidence)


def _ipv6(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    value = m.group()
    if value.count(":") < 2 or ("::" not in value and value.count(":") != 7):
        return None
    if not any(c.isalpha() for c in value) and "::" not in value:
        return None
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return None
    if value in ("::",):
        return None
    return Candidate(m.start(), m.end(), 0.9)


def ipv4_detector() -> Detector:
    return PatternDetector("regex.ipv4", "IP_ADDRESS", _IPV4, _ipv4, prefilter=lambda t: "." in t)


def ipv6_detector() -> Detector:
    return PatternDetector(
        "regex.ipv6", "IP_ADDRESS", _IPV6, _ipv6, prefilter=lambda t: t.count(":") >= 2
    )


# --- URL ---------------------------------------------------------------------

_URL = re.compile(
    r"(?<![\w@/])(?:(?:https?|ftp|sftp|ssh|smb|file)://|www\.)"
    r"[^\s<>\"'`{}|\\^\[\]]+",
    re.IGNORECASE,
)
_TRAILING = ".,;:!?)]}'\""


def _url(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    start, end = m.start(), m.end()
    text = segment.text
    while end > start and text[end - 1] in _TRAILING:
        # Keep a closing bracket that has its opening partner inside the URL.
        if text[end - 1] == ")" and text[start:end].count("(") >= text[start:end].count(")"):
            break
        end -= 1
    value = text[start:end]
    host_part = re.sub(r"^[a-z]+://", "", value, flags=re.IGNORECASE)
    if len(host_part) < 4 or ("." not in host_part.split("/", 1)[0] and not host_part.startswith(
        ("localhost", "[")
    )):
        return None
    return Candidate(start, end, 0.95)


def url_detector() -> Detector:
    return PatternDetector(
        "regex.url", "URL", _URL, _url,
        prefilter=lambda t: "://" in t or "www." in t.lower(),
    )


# --- Date of birth -----------------------------------------------------------

_MONTHS = (
    "jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec|january|february|march|april|june|"
    "july|august|september|october|november|december"
)
_DATE = re.compile(
    r"(?<![\w/.-])(?:"
    r"\d{1,2}[/.-]\d{1,2}[/.-](?:19|20)\d{2}"
    r"|(?:19|20)\d{2}[/.-]\d{1,2}[/.-]\d{1,2}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)?[\s-](?:{_MONTHS})\.?,?[\s-](?:19|20)\d{{2}}"
    rf"|(?:{_MONTHS})\.?\s\d{{1,2}}(?:st|nd|rd|th)?,?\s(?:19|20)\d{{2}}"
    r")(?![\w/-])",
    re.IGNORECASE,
)
_DOB_CONTEXT = keywords("dob", "d.o.b", "date of birth", "birth date", "birthdate", "born",
                        "birthday", "जन्म तिथि")


def _dob(segment: TextSegment, m: re.Match[str]) -> Candidate | None:
    if not has_context(segment, m.start(), m.end(), _DOB_CONTEXT, before=32):
        return None
    return Candidate(m.start(), m.end(), 0.9)


def dob_detector() -> Detector:
    return PatternDetector("regex.date_of_birth", "DATE_OF_BIRTH", _DATE, _dob, prefilter=has_digit)
