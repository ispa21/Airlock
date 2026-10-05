"""Labelled synthetic corpus for detector precision/recall gates.

Each sample is a text plus the exact spans that must be found. Negative
samples (invoice numbers, timestamps, versions, hashes, UUIDs, spreadsheet
arithmetic, ...) carry no labels, so anything detected in them is a false
positive.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from synthetic import Synth


@dataclass
class Sample:
    text: str
    labels: list[tuple[int, int, str]] = field(default_factory=list)
    context: str = ""


#: entity → (value generator name, templates). ``{v}`` is the value.
POSITIVE_TEMPLATES: dict[str, tuple[str, list[str]]] = {
    "EMAIL": (
        "email",
        [
            "Please write to {v} before Friday.",
            "Contact: {v}",
            "<td>{v}</td>",
            "cc: {v}; bcc: none",
            'From: "Ops" <{v}>',
        ],
    ),
    "PHONE": (
        "mobile_in",
        [
            "Phone: {v}, ext 12.",
            "Call me on {v} after 6 pm.",
            "Mobile: {v}",
            "WhatsApp {v} for updates",
            "Tel {v} (office)",
            "Reach the site manager at {v}.",
        ],
    ),
    "PHONE_INTL": (
        "phone_intl",
        [
            "London office: {v}",
            "Dial {v} for support.",
        ],
    ),
    "IP_ADDRESS": (
        "ipv4",
        [
            "The database runs on {v} port 5432.",
            "Allowed source: {v}/32",
            "ssh admin@{v}",
            "host={v}",
        ],
    ),
    "IP_ADDRESS_V6": (
        "ipv6",
        [
            "Gateway {v} is unreachable.",
            "listen [{v}]:443",
        ],
    ),
    "URL": (
        "url",
        [
            "See {v} for the plan.",
            "Link: {v}",
            "(details at {v})",
        ],
    ),
    "DATE_OF_BIRTH": (
        "dob",
        [
            "DOB: {v}",
            "Date of birth {v}",
            "born on {v} in Pune",
        ],
    ),
    "PAN": (
        "pan",
        [
            "PAN {v}, GST pending.",
            "PAN: {v}",
            "Vendor PAN {v} verified.",
            "{v}",
            "Permanent Account Number - {v}",
        ],
    ),
    "AADHAAR": (
        "aadhaar",
        [
            "Aadhaar {v}, verified.",
            "Aadhaar {v}",
            "UID: {v}",
            "Identity proof {v} submitted.",
        ],
    ),
    "AADHAAR_PLAIN": (
        "aadhaar_plain",
        [
            "Aadhaar No. {v}",
            "aadhar: {v}",
        ],
    ),
    "GSTIN": (
        "gstin",
        [
            "GSTIN: {v}",
            "Supplier GST {v}",
            "{v}",
        ],
    ),
    "IFSC": (
        "ifsc",
        [
            "IFSC {v}",
            "Branch code: {v}",
            "NEFT via {v}",
        ],
    ),
    "BANK_ACCOUNT": (
        "bank_account",
        [
            "Pay to account no {v}, IFSC below.",
            "A/c no. {v}",
            "Account number: {v}",
            "Credit to bank account {v} by Monday.",
            "Beneficiary acct {v}",
        ],
    ),
    "CREDIT_CARD": (
        "card",
        [
            "Cards: {v}, expiring soon.",
            "Card {v} exp 09/27",
            "Charge {v} for the renewal.",
            "Visa: {v}",
            "{v}",
        ],
    ),
    "IBAN": (
        "iban",
        [
            "IBAN {v}",
            "Pay to {v} (Barclays)",
        ],
    ),
    "CLOUD_KEY": (
        "aws_key",
        [
            "aws_access_key_id = {v}",
            "export AWS_ACCESS_KEY_ID={v}",
            "Key {v} was rotated.",
        ],
    ),
    "API_KEY": (
        "github_token",
        [
            "GITHUB_TOKEN={v}",
            "Use {v} to push.",
            '"token": "{v}"',
        ],
    ),
    "API_KEY_SLACK": ("slack_token", ["slack bot: {v}", "SLACK={v}"]),
    "API_KEY_STRIPE": ("stripe_key", ['stripe.api_key = "{v}"', "Live key {v}"]),
    "API_KEY_GOOGLE": ("google_key", ["maps key {v}", "GOOGLE_API_KEY: {v}"]),
    "ACCESS_TOKEN": ("jwt", ["Authorization: Bearer {v}", "id_token={v}", "jwt {v}"]),
    "PRIVATE_KEY": ("private_key", ["{v}", "key.pem contents:\n{v}\n"]),
    "PASSWORD": (
        "password",
        [
            "password={v}",
            "DB_PASSWORD: {v}",
            '"client_secret": "{v}"',
            "smtp_pass = '{v}'",
            "Password: {v}",
        ],
    ),
    "CONNECTION_STRING": (
        "url_password",
        [
            "DATABASE_URL=postgres://app_user:{v}@db.example.invalid:5432/prod",
            "mongodb://svc:{v}@mongo1.example.invalid,mongo2.example.invalid/?ssl=true",
            "Server=db01.example.invalid;Database=Payroll;User Id=sa;Password={v};",
            "jdbc:sqlserver://h.example.invalid;databaseName=x;user=u;password={v};",
        ],
    ),
    "CLOUD_KEY_AZURE": (
        "azure_key",
        [
            "DefaultEndpointsProtocol=https;AccountName=synthetic;AccountKey={v};"
            "EndpointSuffix=core.windows.net",
        ],
    ),
}

#: Templates whose label entity differs from the dictionary key.
_ENTITY_OF = {
    "PHONE_INTL": "PHONE",
    "IP_ADDRESS_V6": "IP_ADDRESS",
    "AADHAAR_PLAIN": "AADHAAR",
    "API_KEY_SLACK": "API_KEY",
    "API_KEY_STRIPE": "API_KEY",
    "API_KEY_GOOGLE": "API_KEY",
    "CLOUD_KEY_AZURE": "CLOUD_KEY",
}


def _generator(s: Synth, name: str) -> Callable[[], str]:
    if name == "aadhaar_plain":
        return lambda: s.aadhaar(grouped=False)
    fn: Callable[[], str] = getattr(s, name)
    return fn


def positives(seed: int = 11, per_template: int = 12) -> list[Sample]:
    s = Synth(seed)
    out: list[Sample] = []
    for key, (gen_name, templates) in POSITIVE_TEMPLATES.items():
        entity_type = _ENTITY_OF.get(key, key)
        gen = _generator(s, gen_name)
        for template in templates:
            for _ in range(per_template):
                value = gen()
                head, _, tail = template.partition("{v}")
                text = head + value + tail
                out.append(Sample(text, [(len(head), len(head) + len(value), entity_type)]))
    # Column-header context (spreadsheets): the header names the id.
    for _ in range(per_template):
        out.append(Sample(s.bank_account(), [(0, None, "BANK_ACCOUNT")], context="Account No"))  # type: ignore[list-item]
    for sample in out:
        sample.labels = [(a, len(sample.text) if b is None else b, t) for a, b, t in sample.labels]
    return out


def negatives(seed: int = 13, per_template: int = 12) -> list[Sample]:
    s = Synth(seed)
    r = s.r
    makers: list[Callable[[], str]] = [
        lambda: f"Invoice INV-{r.randint(2019, 2026)}-{r.randint(1, 99999):05d} is due.",
        lambda: f"Order #{r.randint(6_000_000_000, 9_999_999_999)} shipped",
        lambda: f"Ref no. {r.randint(6_000_000_000, 9_999_999_999)}",
        lambda: (
            f"Ticket {r.randint(100000, 999999)} closed on 2024-0{r.randint(1, 9)}-1{r.randint(0, 9)}"
        ),
        lambda: (
            f"2024-0{r.randint(1, 9)}-{r.randint(10, 28)}T{r.randint(10, 23)}:{r.randint(10, 59)}:"
            f"{r.randint(10, 59)}.{r.randint(100, 999)}Z request completed"
        ),
        lambda: f"[{r.randint(10, 23)}:{r.randint(10, 59)}:{r.randint(10, 59)}] worker started",
        lambda: (
            f"Upgraded to v{r.randint(1, 9)}.{r.randint(0, 20)}.{r.randint(0, 99)}.{r.randint(0, 9)}"
        ),
        lambda: f"version {r.randint(1, 12)}.{r.randint(0, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}",
        lambda: f"Build 10.0.{r.randint(10000, 22999)}.{r.randint(100, 4000)}",
        lambda: f"commit {s.sha(40)}",
        lambda: f"sha256: {s.sha(64)}",
        lambda: f"md5 {s.sha(32)}",
        lambda: f"id: {s.uuid()}",
        lambda: f"=SUM(A{r.randint(1, 50)}:A{r.randint(51, 99)})*{r.randint(2, 9)}",
        lambda: (
            f"Total: ₹{r.randint(1, 99)},{r.randint(100, 999)},{r.randint(100, 999)}.{r.randint(10, 99)}"
        ),
        lambda: f"{r.randint(1000, 9999)} x {r.randint(10, 99)} = {r.randint(100000, 999999)}",
        lambda: (
            f"ISBN 978-{r.randint(0, 9)}-{r.randint(100, 999)}-{r.randint(10000, 99999)}-{r.randint(0, 9)}"
        ),
        lambda: f"Serial: SN{r.randint(10**11, 10**12 - 1)}",
        lambda: f"Policy number {r.randint(10**11, 10**12 - 1)}",
        lambda: f"Tracking AWB {r.randint(10**11, 10**12 - 1)}",
        lambda: (
            f"Employee count grew from {r.randint(100, 999)} to {r.randint(1000, 9999)} in FY24."
        ),
        lambda: f"Coordinates {r.uniform(8, 30):.6f}, {r.uniform(68, 90):.6f}",
        lambda: f"Room B{r.randint(100, 999)}, Floor {r.randint(1, 20)}",
        lambda: "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
        lambda: f"The password policy requires {r.randint(8, 16)} characters.",
        lambda: "Set password: ${DB_PASSWORD} in the deployment template.",
        lambda: "api_key = os.environ['API_KEY']",
        lambda: "token: <your-token-here>",
        lambda: "secret: classified",
        lambda: "PASSWORD=changeme",
        lambda: f"PO-{r.randint(10**9, 10**10 - 1)} approved",
        lambda: f"Call duration 00:{r.randint(10, 59)}:{r.randint(10, 59)}",
        lambda: f"Use the CODEWORD{r.randint(1000, 9999)} discount",
        lambda: f"Q{r.randint(1, 4)} revenue up {r.randint(1, 40)}.{r.randint(0, 9)}% YoY",
        lambda: f"Ratio 1:{r.randint(2, 9)}:{r.randint(2, 9)}",
        lambda: "MAC 00:1A:2B:3C:4D:5E is whitelisted",
        lambda: f"Valid till 31/12/20{r.randint(25, 30)}",
        lambda: (
            f"Base64 chunk {s._s('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 40)}"
        ),
        lambda: f"Room booking ABCDE{r.randint(1000, 9999)}",
    ]
    return [Sample(maker()) for maker in makers for _ in range(per_template)]
