"""Deterministic pattern detectors with checksum and context validation."""

from __future__ import annotations

from airlock_engine.core.interfaces import Detector
from airlock_engine.detectors.regex.contact import (
    PhoneDetector,
    dob_detector,
    email_detector,
    ipv4_detector,
    ipv6_detector,
    url_detector,
)
from airlock_engine.detectors.regex.ids import (
    aadhaar_detector,
    bank_account_detector,
    card_detector,
    gstin_detector,
    iban_detector,
    ifsc_detector,
    pan_detector,
)


def builtin_regex_detectors() -> list[Detector]:
    return [
        email_detector(),
        PhoneDetector(),
        ipv4_detector(),
        ipv6_detector(),
        url_detector(),
        dob_detector(),
        pan_detector(),
        aadhaar_detector(),
        gstin_detector(),
        ifsc_detector(),
        card_detector(),
        bank_account_detector(),
        iban_detector(),
    ]
