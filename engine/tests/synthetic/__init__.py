"""Seeded generators of synthetic, checksum-valid identifiers.

Nothing here is real personal data. E-mail domains use the reserved
``.invalid`` TLD, and ids are random but pass their checksums so the
detectors treat them as genuine. Credential-shaped tokens are assembled at
run time from random characters, so no literal token is committed to the
repository (and secret scanners have nothing to flag).
"""

from __future__ import annotations

import base64
import json
import random
import string

from airlock_engine.detectors.checksums import (
    PAN_HOLDER_TYPES,
    gstin_check_char,
    luhn_check_digit,
    verhoeff_check_digit,
)

UPPER = string.ascii_uppercase
DIGITS = string.digits
ALNUM = string.ascii_letters + string.digits

FIRST_NAMES = [
    "Aarav",
    "Priya",
    "Rohan",
    "Ananya",
    "Vikram",
    "Meera",
    "Arjun",
    "Kavya",
    "Ishaan",
    "Diya",
    "John",
    "Maria",
    "Chen",
    "Fatima",
    "Lucas",
    "Sofia",
]
LAST_NAMES = [
    "Sharma",
    "Patel",
    "Iyer",
    "Reddy",
    "Nair",
    "Gupta",
    "Khan",
    "Das",
    "Mehta",
    "Rao",
    "Smith",
    "Garcia",
    "Wang",
    "Ali",
    "Silva",
    "Rossi",
]


class Synth:
    def __init__(self, seed: int = 7) -> None:
        self.r = random.Random(seed)

    def _s(self, alphabet: str, n: int) -> str:
        return "".join(self.r.choice(alphabet) for _ in range(n))

    # --- personal / contact ------------------------------------------------
    def name(self) -> str:
        return f"{self.r.choice(FIRST_NAMES)} {self.r.choice(LAST_NAMES)}"

    def email(self) -> str:
        first, last = self.r.choice(FIRST_NAMES).lower(), self.r.choice(LAST_NAMES).lower()
        local = self.r.choice(
            [
                f"{first}.{last}",
                f"{first}{self.r.randint(1, 99)}",
                f"{first[0]}{last}",
                f"{first}_{last}+billing",
            ]
        )
        domain = self.r.choice(["example.invalid", "corp.example.invalid", "mail.test.invalid"])
        return f"{local}@{domain}"

    def mobile_in(self) -> str:
        digits = self.r.choice("6789") + self._s(DIGITS, 9)
        style = self.r.randrange(4)
        if style == 0:
            return f"+91 {digits[:5]} {digits[5:]}"
        if style == 1:
            return f"+91-{digits}"
        if style == 2:
            return f"{digits[:5]} {digits[5:]}"
        return f"0{digits}"

    def phone_intl(self) -> str:
        return self.r.choice(
            [
                f"+44 20 7946 0{self._s(DIGITS, 3)}",
                f"+1 (415) 555-01{self._s(DIGITS, 2)}",
                f"+61 2 9374 4{self._s(DIGITS, 3)}",
                f"+49 30 901820{self._s(DIGITS, 2)}",
            ]
        )

    def ipv4(self) -> str:
        return self.r.choice(
            [
                f"10.{self.r.randint(0, 255)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
                f"192.168.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
                f"172.{self.r.randint(16, 31)}.{self.r.randint(0, 255)}.{self.r.randint(1, 254)}",
                f"203.0.113.{self.r.randint(1, 254)}",
            ]
        )

    def ipv6(self) -> str:
        groups = [format(self.r.randint(0, 0xFFFF), "x") for _ in range(4)]
        return self.r.choice(
            [
                f"2001:db8::{groups[0]}:{groups[1]}",
                f"fe80::{':'.join(groups)}",
                "2001:db8:" + ":".join(groups) + ":1:2",
            ]
        )

    def url(self) -> str:
        host = self.r.choice(["intranet", "wiki", "jira", "portal", "files"])
        path = self.r.choice(["/projects/q3", "/hr/payroll?id=42", "/docs/plan.pdf", ""])
        return f"https://{host}.example.invalid{path}"

    def dob(self) -> str:
        d, m, y = self.r.randint(1, 28), self.r.randint(1, 12), self.r.randint(1950, 2005)
        return self.r.choice(
            [
                f"{d:02d}/{m:02d}/{y}",
                f"{y}-{m:02d}-{d:02d}",
                f"{d} {['Jan', 'March', 'July', 'Oct'][m % 4]} {y}",
            ]
        )

    # --- India ids -----------------------------------------------------------
    def pan(self) -> str:
        return (
            self._s(UPPER, 3)
            + self.r.choice(PAN_HOLDER_TYPES)
            + self._s(UPPER, 1)
            + f"{self.r.randint(1, 9999):04d}"
            + self._s(UPPER, 1)
        )

    def aadhaar(self, grouped: bool = True) -> str:
        payload = self.r.choice("23456789") + self._s(DIGITS, 10)
        digits = payload + verhoeff_check_digit(payload)
        if not grouped:
            return digits
        sep = self.r.choice([" ", "-"])
        return f"{digits[:4]}{sep}{digits[4:8]}{sep}{digits[8:]}"

    def gstin(self) -> str:
        payload = f"{self.r.randint(1, 37):02d}" + self.pan() + self.r.choice("123456789") + "Z"
        return payload + gstin_check_char(payload)

    def ifsc(self) -> str:
        bank = self.r.choice(["HDFC", "ICIC", "SBIN", "UTIB", "KKBK", "PUNB"])
        return f"{bank}0{self._s(DIGITS, 6)}"

    def bank_account(self) -> str:
        return self.r.choice("123456789") + self._s(DIGITS, self.r.randint(8, 15))

    def card(self) -> str:
        prefix, length = self.r.choice(
            [
                ("4", 16),
                ("51", 16),
                ("2221", 16),
                ("37", 15),
                ("6521", 16),
                ("6011", 16),
                ("3530", 16),
            ]
        )
        payload = prefix + self._s(DIGITS, length - len(prefix) - 1)
        digits = payload + luhn_check_digit(payload)
        if length == 15:
            return self.r.choice([digits, f"{digits[:4]} {digits[4:10]} {digits[10:]}"])
        return self.r.choice(
            [
                digits,
                " ".join(digits[i : i + 4] for i in range(0, 16, 4)),
                "-".join(digits[i : i + 4] for i in range(0, 16, 4)),
            ]
        )

    def iban(self) -> str:
        bban = "WEST" + self._s(DIGITS, 14)
        check = 98 - int("".join(str(int(c, 36)) for c in bban + "GB00")) % 97
        raw = f"GB{check:02d}{bban}"
        return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4))

    # --- secrets -------------------------------------------------------------
    def aws_key(self) -> str:
        return "AK" + "IA" + self._s(UPPER + "234567", 16)

    def github_token(self) -> str:
        return "gh" + self.r.choice("pous") + "_" + self._s(ALNUM, 36)

    def slack_token(self) -> str:
        return (
            "xo"
            + "xb-"
            + self._s(DIGITS, 11)
            + "-"
            + self._s(DIGITS, 12)
            + "-"
            + self._s(ALNUM, 24)
        )

    def stripe_key(self) -> str:
        return "sk" + "_live_" + self._s(ALNUM, 24)

    def google_key(self) -> str:
        return "AI" + "za" + self._s(ALNUM + "_-", 35)

    def jwt(self) -> str:
        def b64(obj: dict[str, object]) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).decode().rstrip("=")

        return (
            b64({"alg": "HS256", "typ": "JWT"})
            + "."
            + b64({"sub": self._s(DIGITS, 8), "name": "Synthetic"})
            + "."
            + self._s(ALNUM + "_-", 43)
        )

    def private_key(self) -> str:
        body = "\n".join(self._s(ALNUM + "+/", 64) for _ in range(6))
        kind = self.r.choice(["RSA ", "EC ", "OPENSSH ", ""])
        return f"-----BEGIN {kind}PRIVATE KEY-----\n{body}\n-----END {kind}PRIVATE KEY-----"

    def password(self) -> str:
        return self._s(ALNUM, 6) + self.r.choice("!@#$%^&*") + self._s(ALNUM, 5)

    def url_password(self) -> str:
        return self._s(ALNUM, 7) + self.r.choice("!*$-") + self._s(ALNUM, 5)

    def azure_key(self) -> str:
        return self._s(ALNUM + "+/", 86) + "=="

    # --- negatives -----------------------------------------------------------
    def uuid(self) -> str:
        h = self._s("0123456789abcdef", 32)
        return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-a{h[17:20]}-{h[20:]}"

    def sha(self, n: int = 64) -> str:
        return self._s("0123456789abcdef", n)
