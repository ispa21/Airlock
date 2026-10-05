"""Unit tests for checksums and the built-in pattern and secret detectors."""

from __future__ import annotations

import pytest

from airlock_engine.core.models import ExtractedDocument, Locator, TextSegment
from airlock_engine.detectors import checksums
from airlock_engine.detectors.pipeline import DetectionEngine
from synthetic import Synth


def found(text: str, context: str = "") -> list[tuple[str, str]]:
    doc = ExtractedDocument("txt", (TextSegment(0, text, Locator("t", "0"), context=context),))
    return [
        (i.detection.entity_type, text[i.detection.start : i.detection.end])
        for i in DetectionEngine().run(doc).detected
    ]


def types(text: str, context: str = "") -> set[str]:
    return {t for t, _ in found(text, context)}


# --- checksums ---------------------------------------------------------------


def test_luhn_known_values() -> None:
    assert checksums.luhn_valid("79927398713")
    assert not checksums.luhn_valid("79927398710")
    assert checksums.luhn_check_digit("7992739871") == "3"


def test_verhoeff_known_values() -> None:
    # Published Verhoeff test vector: 236 -> check digit 3.
    assert checksums.verhoeff_check_digit("236") == "3"
    assert checksums.verhoeff_valid("2363")
    assert not checksums.verhoeff_valid("2364")


def test_verhoeff_detects_every_single_digit_error() -> None:
    s = Synth(3)
    for _ in range(50):
        digits = s.aadhaar(grouped=False)
        for pos in range(12):
            for d in "0123456789":
                if d != digits[pos]:
                    assert not checksums.verhoeff_valid(digits[:pos] + d + digits[pos + 1 :])


def test_gstin_checksum_and_structure() -> None:
    s = Synth(5)
    for _ in range(100):
        g = s.gstin()
        assert checksums.gstin_valid(g)
        wrong = g[:14] + ("0" if g[14] != "0" else "1")
        assert not checksums.gstin_valid(wrong)
    assert not checksums.gstin_valid("00ABCPE1234F1Z5")  # state code 00


def test_pan_structure() -> None:
    assert checksums.pan_valid("ABCPE1234F")
    assert not checksums.pan_valid("ABCXE1234F")  # X is not a holder type
    assert not checksums.pan_valid("ABCPE0000F")


def test_iban_mod97() -> None:
    assert checksums.iban_valid("GB82 WEST 1234 5698 7654 32")
    assert checksums.iban_valid("DE89370400440532013000")
    assert not checksums.iban_valid("GB82 WEST 1234 5698 7654 33")


# --- identifiers -------------------------------------------------------------


def test_aadhaar_needs_grouping_or_context() -> None:
    aad = Synth(1).aadhaar(grouped=False)
    assert "AADHAAR" not in types(f"Order {aad} shipped")
    assert "AADHAAR" in types(f"Aadhaar: {aad}")
    grouped = f"{aad[:4]} {aad[4:8]} {aad[8:]}"
    assert ("AADHAAR", grouped) in found(f"proof {grouped} attached")


def test_aadhaar_with_bad_checksum_is_ignored() -> None:
    aad = Synth(2).aadhaar(grouped=False)
    bad = aad[:11] + str((int(aad[11]) + 1) % 10)
    assert "AADHAAR" not in types(f"Aadhaar {bad}")


def test_aadhaar_starting_with_0_or_1_is_not_aadhaar() -> None:
    payload = "1" + "2345678901"
    digits = payload + checksums.verhoeff_check_digit(payload)
    assert "AADHAAR" not in types(f"Aadhaar {digits}")


def test_lowercase_pan_only_with_context() -> None:
    assert "PAN" in types("pan: abcpe1234f")
    assert "PAN" not in types("ref abcpe1234f")


def test_card_requires_luhn_and_brand() -> None:
    s = Synth(9)
    card = s.card()
    assert "CREDIT_CARD" in types(f"card {card}")
    digits = "".join(ch for ch in card if ch.isdigit())
    broken = digits[:-1] + str((int(digits[-1]) + 1) % 10)
    assert "CREDIT_CARD" not in types(f"card {broken}")
    assert "CREDIT_CARD" not in types("1234 5678 9012 3456")  # no brand


def test_bank_account_requires_context() -> None:
    assert "BANK_ACCOUNT" not in types("Total units 123456789012 shipped")
    assert ("BANK_ACCOUNT", "123456789012") in found("Account no: 123456789012")
    assert ("BANK_ACCOUNT", "123456789012") in found("123456789012", context="A/c Number")


def test_numbers_followed_by_sentence_punctuation() -> None:
    """Regression (found in the real-app run): "account no 5707536455, IFSC …"."""
    s = Synth(12)
    aad, card = s.aadhaar(), s.card()
    assert ("BANK_ACCOUNT", "5707536455") in found("Bank: account no 5707536455, IFSC next.")
    assert ("BANK_ACCOUNT", "5707536455") in found("Account no 5707536455.")
    assert ("AADHAAR", aad) in found(f"Aadhaar {aad}, verified.")
    assert ("CREDIT_CARD", card) in found(f"Card {card}.")
    # ...but thousands separators are still not ids.
    assert "BANK_ACCOUNT" not in types("Account balance 1,234,567,890,123")


def test_ifsc_and_gstin() -> None:
    s = Synth(4)
    g = s.gstin()
    assert ("GSTIN", g) in found(f"GST No {g}")
    assert ("IFSC", "SBIN0001234") in found("IFSC: SBIN0001234")
    assert "IFSC" not in types("CODEWORDS ABCD0EFGHIJ")


def test_phone_formats_and_reference_numbers() -> None:
    assert ("PHONE", "+91 98765 43210") in found("Mobile +91 98765 43210")
    assert ("PHONE", "+44 20 7946 0958") in found("UK: +44 20 7946 0958")
    assert "PHONE" not in types("Order #9876543210 shipped")
    assert "PHONE" not in types("INV-9876543210")
    assert "PHONE" not in types("2024-01-15 10:30:45")
    assert "PHONE" not in types("server 192.168.10.20")


def test_ip_addresses_and_versions() -> None:
    assert ("IP_ADDRESS", "10.0.0.12") in found("host 10.0.0.12")
    assert ("IP_ADDRESS", "2001:db8::8a2e:370:7334") in found("v6 2001:db8::8a2e:370:7334")
    assert "IP_ADDRESS" not in types("Upgraded to v1.2.3.4")
    assert "IP_ADDRESS" not in types("version 10.0.0.1 released")
    assert "IP_ADDRESS" not in types("999.1.1.1")
    assert "IP_ADDRESS" not in types("12:30:45 and MAC 00:1A:2B:3C:4D:5E")


def test_url_trailing_punctuation() -> None:
    assert ("URL", "https://wiki.example.invalid/a_(b)") in found(
        "See https://wiki.example.invalid/a_(b)."
    )
    assert ("URL", "www.example.invalid/x") in found("(www.example.invalid/x),")


def test_email() -> None:
    assert ("EMAIL", "first.last+tag@sub.example.invalid") in found(
        "mail first.last+tag@sub.example.invalid now"
    )
    assert "EMAIL" not in types("user@localhost and @handle and a..b@example.invalid")


def test_dob_requires_context() -> None:
    assert "DATE_OF_BIRTH" not in types("Meeting on 12/03/2024")
    assert ("DATE_OF_BIRTH", "12/03/1988") in found("DOB 12/03/1988")


# --- secrets -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("make", "entity_type"),
    [
        (lambda s: s.aws_key(), "CLOUD_KEY"),
        (lambda s: s.github_token(), "API_KEY"),
        (lambda s: s.slack_token(), "API_KEY"),
        (lambda s: s.stripe_key(), "API_KEY"),
        (lambda s: s.google_key(), "API_KEY"),
        (lambda s: s.jwt(), "ACCESS_TOKEN"),
        (lambda s: s.private_key(), "PRIVATE_KEY"),
    ],
)
def test_provider_tokens_anywhere(make, entity_type) -> None:  # type: ignore[no-untyped-def]
    value = make(Synth(21))
    assert (entity_type, value) in found(f"note: {value} (rotate)")


def test_assigned_secrets_and_placeholders() -> None:
    pw = "Xk9#mQ2!vL7p"
    for line in (f"password={pw}", f"DB_PASS: {pw}", f'"client_secret": "{pw}"', f"pwd = '{pw}'"):
        assert ("PASSWORD", pw) in found(line), line
    for line in (
        "password=${DB_PASSWORD}",
        "api_key = os.environ['API_KEY']",
        "token: <your-token>",
        "password: ********",
        "secret = get_secret('db')",
        "PASSWORD=changeme",
        "Secret: classified",
        "The password must have 12 characters.",
    ):
        assert not {"PASSWORD", "API_KEY"} & types(line), line


def test_connection_strings() -> None:
    assert ("CONNECTION_STRING", "p4ss-W0rd") in found(
        "postgres://app:p4ss-W0rd@db.example.invalid/prod"
    )
    assert ("CONNECTION_STRING", "Zq8!rT5x") in found(
        "Server=db;Database=hr;User Id=sa;Password=Zq8!rT5x;"
    )
    # The password in a URL is a secret, not an e-mail address.
    assert "EMAIL" not in types("postgres://app:p4ss-W0rd@db.example.invalid/prod")


def test_truncated_private_key_is_still_found() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow" + "A" * 200
    assert "PRIVATE_KEY" in types(text)


def test_hashes_and_uuids_are_not_secrets() -> None:
    s = Synth(8)
    text = f"sha {s.sha(64)} uuid {s.uuid()} md5 {s.sha(32)} commit {s.sha(40)}"
    assert types(text) == set()


def test_detectors_are_linear_on_hostile_input() -> None:
    """No catastrophic backtracking on long identifier-like runs."""
    import time

    hostile = [
        "a_" * 50_000 + "password",
        "secret" + "-" * 100_000,
        "1" * 200_000,
        "1 " * 100_000,
        "@" * 50_000 + "a" * 50_000,
        "http://" + "a." * 50_000,
        "x" * 100_000 + "@example.invalid",
    ]
    for text in hostile:
        started = time.perf_counter()
        found(text)
        assert time.perf_counter() - started < 5.0
