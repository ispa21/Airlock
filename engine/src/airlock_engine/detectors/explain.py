"""Plain-language reasons why a detector flagged something.

Shown next to each finding in the privacy report. Reasons describe the rule
that matched (a checksum, a format, a context word, a company rule), never
the value itself.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

_REASONS: Final[dict[str, str]] = {
    "regex.email": "Has the form of an e-mail address (name@domain).",
    "regex.phone": "A phone number that is valid under its country's numbering rules.",
    "regex.ipv4": "A valid IPv4 address (version numbers are ignored).",
    "regex.ipv6": "A valid IPv6 address.",
    "regex.url": "A web address.",
    "regex.date_of_birth": "A date next to a word such as 'DOB', 'date of birth' or 'born'.",
    "regex.pan": "Has the structure of an Indian PAN: 5 letters, 4 digits, 1 letter, with a valid "
    "holder-type letter.",
    "regex.aadhaar": "A 12-digit number that passes the Aadhaar checksum (Verhoeff).",
    "regex.gstin": "A 15-character GSTIN with a valid state code, an embedded PAN and a correct "
    "check character.",
    "regex.ifsc": "Has the structure of an IFSC bank branch code.",
    "regex.card": "A card number that passes the Luhn check and belongs to a card network's range.",
    "regex.bank_account": "A long number next to a word such as 'account', 'A/c' or 'bank'.",
    "regex.iban": "An IBAN whose check digits are correct (mod 97).",
    "secret.private_key": "A private key block (-----BEGIN … PRIVATE KEY-----).",
    "secret.aws_access_key": "Matches the format of an AWS access key id.",
    "secret.github_token": "Matches the format of a GitHub access token.",
    "secret.gitlab_token": "Matches the format of a GitLab access token.",
    "secret.slack_token": "Matches the format of a Slack token.",
    "secret.slack_webhook": "A Slack incoming-webhook address, which works like a password.",
    "secret.stripe_key": "Matches the format of a Stripe API key.",
    "secret.google_api_key": "Matches the format of a Google API key.",
    "secret.openai_key": "Matches the format of an OpenAI API key.",
    "secret.anthropic_key": "Matches the format of an Anthropic API key.",
    "secret.generic_sk_key": "Matches the common 'sk-' format of API secret keys.",
    "secret.sendgrid_key": "Matches the format of a SendGrid API key.",
    "secret.twilio_key": "Matches the format of a Twilio API key.",
    "secret.npm_token": "Matches the format of an npm access token.",
    "secret.azure_storage_key": "An Azure storage account key in a connection string.",
    "secret.azure_sas": "An Azure shared-access signature.",
    "secret.jwt": "A signed access token (JWT) with a valid header.",
    "secret.url_credentials": "A password written inside a web address (user:password@host).",
    "secret.connection_password": "A password inside a database connection string.",
    "secret.bearer_token": "A token after 'Bearer', as used in authorization headers.",
    "secret.assigned": "A value given to a setting named like a password, secret, token or key.",
    "custom.exact": "Matches one of your company rules exactly.",
    "custom.case_insensitive": "Matches one of your company rules, in any letter case.",
    "custom.normalized": "Matches one of your company rules, ignoring case, accents and "
    "separators.",
    "custom.regex": "Matches the pattern of one of your company rules.",
}

#: Short names for the corroborating-detector line.
_SHORT: Final[dict[str, str]] = {
    "ner.spacy": "language model",
}


def detector_name(detector: str) -> str:
    if detector in _SHORT:
        return _SHORT[detector]
    if detector.startswith("custom."):
        return "company rule"
    if detector.startswith("secret"):
        return "secret pattern"
    return detector.split(".", 1)[-1].replace("_", " ") + " pattern"


def explain(detector: str, entity_label: str, corroborated_by: Sequence[str] = ()) -> str:
    if detector.startswith("ner."):
        reason = (
            f"The on-device language model recognised this as a "
            f"{entity_label[:1].lower() + entity_label[1:]}."
        )
    else:
        reason = _REASONS.get(detector, f"Matches the known format of a {entity_label.lower()}.")
    others = list(dict.fromkeys(detector_name(d) for d in corroborated_by if d != detector))
    if others:
        reason += " Also found by: " + ", ".join(others) + "."
    return reason
