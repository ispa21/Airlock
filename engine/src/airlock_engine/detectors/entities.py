"""Catalogue of built-in entity types.

Every detector emits one of these ids (or a company-rule category id). The
catalogue fixes the report category, the default severity and the quality
class whose precision/recall gate applies (docs/TESTING.md).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from airlock_engine.core.models import Category, Severity


class QualityClass(StrEnum):
    SECRET = "secret"  # noqa: S105 - a class name, not a password
    CHECKSUMMED_ID = "checksummed_id"
    CONTACT = "contact"  # e-mail, phone, IP, URL
    CONTEXTUAL_ID = "contextual_id"  # ids without a checksum, gated on context
    COMPANY_RULE = "company_rule"
    NER = "ner"


@dataclass(frozen=True, slots=True)
class EntityType:
    id: str
    label: str
    category: Category
    severity: Severity
    quality: QualityClass


_C, _S, _Q = Category, Severity, QualityClass

_BUILTIN: tuple[EntityType, ...] = (
    # Personal and contact
    EntityType("EMAIL", "E-mail address", _C.PERSONAL, _S.MEDIUM, _Q.CONTACT),
    EntityType("PHONE", "Phone number", _C.PERSONAL, _S.MEDIUM, _Q.CONTACT),
    EntityType("DATE_OF_BIRTH", "Date of birth", _C.PERSONAL, _S.HIGH, _Q.CONTEXTUAL_ID),
    EntityType("PERSON", "Person name", _C.PERSONAL, _S.MEDIUM, _Q.NER),
    EntityType("LOCATION", "Location", _C.PERSONAL, _S.LOW, _Q.NER),
    # Government ids (India)
    EntityType("PAN", "PAN (income-tax id)", _C.GOVERNMENT, _S.HIGH, _Q.CHECKSUMMED_ID),
    EntityType("AADHAAR", "Aadhaar number", _C.GOVERNMENT, _S.CRITICAL, _Q.CHECKSUMMED_ID),
    EntityType("GSTIN", "GSTIN (GST registration)", _C.GOVERNMENT, _S.MEDIUM, _Q.CHECKSUMMED_ID),
    # Financial
    EntityType("CREDIT_CARD", "Payment card number", _C.FINANCIAL, _S.CRITICAL, _Q.CHECKSUMMED_ID),
    EntityType("IBAN", "IBAN", _C.FINANCIAL, _S.HIGH, _Q.CHECKSUMMED_ID),
    EntityType("BANK_ACCOUNT", "Bank account number", _C.FINANCIAL, _S.HIGH, _Q.CONTEXTUAL_ID),
    EntityType("IFSC", "IFSC (bank branch code)", _C.FINANCIAL, _S.LOW, _Q.CHECKSUMMED_ID),
    EntityType("MONEY", "Monetary amount", _C.FINANCIAL, _S.LOW, _Q.NER),
    # Business and infrastructure
    EntityType("ORGANIZATION", "Organisation name", _C.BUSINESS, _S.LOW, _Q.NER),
    EntityType("PRODUCT", "Product name", _C.BUSINESS, _S.LOW, _Q.NER),
    EntityType("EVENT", "Event", _C.BUSINESS, _S.LOW, _Q.NER),
    EntityType("IP_ADDRESS", "IP address", _C.BUSINESS, _S.MEDIUM, _Q.CONTACT),
    EntityType("URL", "Web address", _C.OTHER, _S.LOW, _Q.CONTACT),
    # Credentials
    EntityType("PRIVATE_KEY", "Private key", _C.CREDENTIALS, _S.CRITICAL, _Q.SECRET),
    EntityType("API_KEY", "API key or token", _C.CREDENTIALS, _S.CRITICAL, _Q.SECRET),
    EntityType("CLOUD_KEY", "Cloud access key", _C.CREDENTIALS, _S.CRITICAL, _Q.SECRET),
    EntityType("ACCESS_TOKEN", "Access token (JWT)", _C.CREDENTIALS, _S.CRITICAL, _Q.SECRET),
    EntityType("PASSWORD", "Password or secret", _C.CREDENTIALS, _S.CRITICAL, _Q.SECRET),
    EntityType(
        "CONNECTION_STRING", "Connection string with credentials", _C.CREDENTIALS,
        _S.CRITICAL, _Q.SECRET,
    ),
)

BUILTIN_ENTITIES: dict[str, EntityType] = {e.id: e for e in _BUILTIN}

#: Custom-rule categories every installation starts with.
BUILTIN_RULE_CATEGORIES: tuple[EntityType, ...] = (
    EntityType("INTERNAL_PROJECT", "Internal project", _C.INTELLECTUAL_PROPERTY, _S.HIGH,
               _Q.COMPANY_RULE),
    EntityType("CLIENT_NAME", "Client or customer", _C.BUSINESS, _S.HIGH, _Q.COMPANY_RULE),
    EntityType("EMPLOYEE_ID", "Employee id", _C.PERSONAL, _S.MEDIUM, _Q.COMPANY_RULE),
    EntityType("INTERNAL_SYSTEM", "Internal system or host", _C.BUSINESS, _S.MEDIUM,
               _Q.COMPANY_RULE),
    EntityType("CONFIDENTIAL_TERM", "Confidential term", _C.BUSINESS, _S.HIGH, _Q.COMPANY_RULE),
)


def entity(entity_id: str) -> EntityType:
    return BUILTIN_ENTITIES[entity_id]
