"""Airlock licence tool: create signing keys, issue and check licences.

A licence is one line of text, easy to paste from an e-mail or save as a
``.airlock-license`` file:

    AIRLOCK1.<key id>.<payload>.<signature>

``payload`` is base64url (no padding) of UTF-8 JSON; ``signature`` is the
Ed25519 signature of those exact payload bytes, base64url. The JSON:

    {
      "license_id": "lic_7Q3K9X2M",
      "plan": "lifetime",
      "customer": "Acme Pvt Ltd",
      "email": "it@acme.example",        # optional
      "seats": 10,
      "features": [],
      "issued_at": "2026-10-06T00:00:00Z",
      "expiry": null,                     # lifetime licences never expire
      "updates_until": null,              # optional ISO date
      "machine": null                     # optional: bound to one machine code
    }

The desktop host verifies licences offline with the public keys listed in
``licensing/public-keys.json``. The private key never leaves the issuer's
machine (``licensing/keys/`` is git-ignored) and is never shipped.

Usage:
    python licensing/airlock_license.py keygen --id airlock-2026
    python licensing/airlock_license.py issue --key licensing/keys/airlock-2026.key \\
        --customer "Acme Pvt Ltd" --seats 10 [--email it@acme.example] \\
        [--machine ABCD-EFGH-...] [--updates-until 2027-10-06] [--out acme.airlock-license]
    python licensing/airlock_license.py verify <token or file>
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import secrets
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

PREFIX = "AIRLOCK1"
HERE = Path(__file__).resolve().parent
PUBLIC_KEYS = HERE / "public-keys.json"
KEY_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,31}$")
MACHINE_CODE = re.compile(r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){4}$")


class LicenseError(ValueError):
    pass


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(text: str) -> bytes:
    if not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise LicenseError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def new_license_id() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "lic_" + "".join(secrets.choice(alphabet) for _ in range(10))


def payload_for(
    *,
    customer: str,
    seats: int,
    email: str | None = None,
    machine: str | None = None,
    updates_until: str | None = None,
    license_id: str | None = None,
    issued_at: datetime | None = None,
) -> dict[str, Any]:
    if not customer.strip() or len(customer) > 200:
        raise LicenseError("customer must be 1-200 characters")
    if not 1 <= seats <= 100_000:
        raise LicenseError("seats must be between 1 and 100000")
    if machine is not None and not MACHINE_CODE.match(machine):
        raise LicenseError("machine code must look like ABCD-EFGH-IJKL-MNOP-QRST")
    if updates_until is not None:
        datetime.strptime(updates_until, "%Y-%m-%d")
    stamp = (issued_at or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "license_id": license_id or new_license_id(),
        "plan": "lifetime",
        "customer": customer.strip(),
        "email": email,
        "seats": seats,
        "features": [],
        "issued_at": stamp,
        "expiry": None,
        "updates_until": updates_until,
        "machine": machine,
    }


def sign(payload: dict[str, Any], key: Ed25519PrivateKey, key_id: str) -> str:
    if not KEY_ID.match(key_id):
        raise LicenseError("key id must be lower-case letters, digits and hyphens")
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return ".".join((PREFIX, key_id, b64(body), b64(key.sign(body))))


def extract_token(text: str) -> str:
    """The licence line in a file or an e-mail body (other lines are ignored)."""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(PREFIX + "."):
            return line
    raise LicenseError("no Airlock licence found in this text")


def verify(token: str, keys: dict[str, Ed25519PublicKey]) -> dict[str, Any]:
    parts = extract_token(token).split(".")
    if len(parts) != 4 or parts[0] != PREFIX:
        raise LicenseError("malformed licence")
    _, key_id, body_b64, sig_b64 = parts
    key = keys.get(key_id)
    if key is None:
        raise LicenseError("this licence was not issued by a known Airlock key")
    body, signature = unb64(body_b64), unb64(sig_b64)
    try:
        key.verify(signature, body)
    except InvalidSignature as exc:
        raise LicenseError("the licence signature is not valid") from exc
    payload: dict[str, Any] = json.loads(body.decode("utf-8"))
    return payload


def load_private(path: Path) -> tuple[Ed25519PrivateKey, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    key = Ed25519PrivateKey.from_private_bytes(unb64(data["ed25519_private"]))
    return key, str(data["id"])


def public_b64(key: Ed25519PrivateKey) -> str:
    raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b64(raw)


def load_public_keys(path: Path = PUBLIC_KEYS) -> dict[str, Ed25519PublicKey]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        entry["id"]: Ed25519PublicKey.from_public_bytes(unb64(entry["ed25519"]))
        for entry in data.get("keys", [])
    }


def _keygen(args: argparse.Namespace) -> int:
    if not KEY_ID.match(args.id):
        raise LicenseError("key id must be lower-case letters, digits and hyphens")
    folder = HERE / "keys"
    folder.mkdir(exist_ok=True)
    target = folder / f"{args.id}.key"
    if target.exists():
        raise LicenseError(f"{target} already exists")
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    )
    target.write_text(json.dumps({"id": args.id, "ed25519_private": b64(raw)}), encoding="utf-8")
    target.chmod(0o600)
    entry = {"id": args.id, "ed25519": public_b64(key)}
    print(f"private key: {target}  (keep it offline; never commit it)")
    print("add this entry to licensing/public-keys.json, then rebuild the app:")
    print(json.dumps(entry))
    return 0


def _issue(args: argparse.Namespace) -> int:
    key, key_id = load_private(Path(args.key))
    payload = payload_for(
        customer=args.customer,
        seats=args.seats,
        email=args.email,
        machine=args.machine,
        updates_until=args.updates_until,
    )
    token = sign(payload, key, key_id)
    if args.out:
        Path(args.out).write_text(
            f"Airlock licence for {payload['customer']} ({payload['license_id']})\n{token}\n",
            encoding="utf-8",
        )
        print(f"wrote {args.out}")
    else:
        print(token)
    return 0


def _verify(args: argparse.Namespace) -> int:
    source = Path(args.licence)
    text = source.read_text(encoding="utf-8") if source.is_file() else args.licence
    keys = load_public_keys(Path(args.keys)) if args.keys else load_public_keys()
    print(json.dumps(verify(text, keys), indent=2, ensure_ascii=False))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Airlock licence tool")
    sub = parser.add_subparsers(dest="command", required=True)
    keygen = sub.add_parser("keygen", help="create a signing key pair")
    keygen.add_argument("--id", required=True)
    issue = sub.add_parser("issue", help="issue a licence")
    issue.add_argument("--key", required=True)
    issue.add_argument("--customer", required=True)
    issue.add_argument("--seats", type=int, default=1)
    issue.add_argument("--email")
    issue.add_argument("--machine")
    issue.add_argument("--updates-until")
    issue.add_argument("--out")
    check = sub.add_parser("verify", help="check a licence")
    check.add_argument("licence")
    check.add_argument("--keys")
    args = parser.parse_args(argv)
    try:
        return {"keygen": _keygen, "issue": _issue, "verify": _verify}[args.command](args)
    except LicenseError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
