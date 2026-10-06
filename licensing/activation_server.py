"""Reference activation server for Airlock lifetime licences.

The app calls it only when a user clicks "Activate" with a licence key. It
sends the key, the machine code (a one-way hash of the computer's ID, never
the ID itself) and the app version; the server answers with a licence bound
to that machine, signed with the issuer key. Nothing else is ever sent, and
the privacy engine is never involved.

Run it behind an HTTPS reverse proxy (the app refuses plain HTTP):

    python licensing/activation_server.py add-key --db activations.db --customer "Acme" --seats 10
    python licensing/activation_server.py serve --db activations.db \\
        --signing-key licensing/keys/airlock-2026.key --port 8080
    python licensing/activation_server.py list --db activations.db
    python licensing/activation_server.py release --db activations.db \\
        --key ALK-... --machine ABCD-...

Licence keys are stored as SHA-256 hashes, so a copy of the database does not
reveal them. Standard library only, plus ``cryptography`` for signing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sqlite3
import sys
import threading
import time
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from airlock_license import (
    MACHINE_CODE,
    LicenseError,
    load_private,
    payload_for,
    sign,
)

KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
MAX_BODY = 4096
RATE_LIMIT = 20  # requests per minute per client address

SCHEMA = """
CREATE TABLE IF NOT EXISTS licence_keys (
  key_hash TEXT PRIMARY KEY,
  license_id TEXT NOT NULL UNIQUE,
  customer TEXT NOT NULL,
  email TEXT,
  seats INTEGER NOT NULL,
  updates_until TEXT,
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS activations (
  key_hash TEXT NOT NULL REFERENCES licence_keys(key_hash),
  machine TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  PRIMARY KEY (key_hash, machine)
);
"""


def key_hash(key: str) -> str:
    return hashlib.sha256(key.strip().upper().encode("ascii", "ignore")).hexdigest()


def new_key() -> str:
    groups = ["".join(secrets.choice(KEY_ALPHABET) for _ in range(5)) for _ in range(4)]
    return "ALK-" + "-".join(groups)


def connect(path: str) -> sqlite3.Connection:
    db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
    db.executescript(SCHEMA)
    return db


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class Activations:
    def __init__(self, db: sqlite3.Connection, signing_key_path: Path | None) -> None:
        self.db = db
        self.lock = threading.Lock()
        self.signing = load_private(signing_key_path) if signing_key_path else None

    def add_key(
        self, customer: str, seats: int, email: str | None, updates_until: str | None
    ) -> str:
        payload_for(customer=customer, seats=seats, email=email, updates_until=updates_until)
        key = new_key()
        license_id = "lic_" + "".join(secrets.choice(KEY_ALPHABET) for _ in range(10))
        self.db.execute(
            "INSERT INTO licence_keys VALUES (?, ?, ?, ?, ?, ?, 0, ?)",
            (key_hash(key), license_id, customer, email, seats, updates_until, now()),
        )
        return key

    def activate(self, key: str, machine: str) -> tuple[int, dict[str, Any]]:
        if not MACHINE_CODE.match(machine) or not key.upper().startswith("ALK-"):
            return 400, {"error": "bad_request", "message": "The request is not valid."}
        assert self.signing is not None
        digest = key_hash(key)
        with self.lock:
            row = self.db.execute(
                "SELECT license_id, customer, email, seats, updates_until, revoked "
                "FROM licence_keys WHERE key_hash = ?",
                (digest,),
            ).fetchone()
            if row is None or row[5]:
                return 404, {
                    "error": "unknown_key",
                    "message": "This licence key is not valid.",
                }
            license_id, customer, email, seats, updates_until, _ = row
            known = self.db.execute(
                "SELECT 1 FROM activations WHERE key_hash = ? AND machine = ?", (digest, machine)
            ).fetchone()
            if known is None:
                used = self.db.execute(
                    "SELECT COUNT(*) FROM activations WHERE key_hash = ?", (digest,)
                ).fetchone()[0]
                if used >= seats:
                    return 409, {
                        "error": "no_seats_left",
                        "message": f"This licence is active on {used} of {seats} computers.",
                    }
                self.db.execute(
                    "INSERT INTO activations VALUES (?, ?, ?)", (digest, machine, now())
                )
        key_obj, key_id = self.signing
        payload = payload_for(
            customer=customer,
            seats=seats,
            email=email,
            machine=machine,
            updates_until=updates_until,
            license_id=license_id,
        )
        return 200, {"license": sign(payload, key_obj, key_id)}


def make_handler(service: Activations) -> type[BaseHTTPRequestHandler]:
    recent: dict[str, deque[float]] = defaultdict(deque)

    class Handler(BaseHTTPRequestHandler):
        server_version = "airlock-activation/1"

        def log_message(self, format: str, *args: Any) -> None:
            # Request lines only: no bodies, so no keys or machine codes in logs.
            sys.stderr.write(f"{self.address_string()} {self.command} {self.path}\n")

        def _send(self, status: int, body: dict[str, Any]) -> None:
            data = json.dumps(body).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self) -> None:
            client = self.client_address[0]
            window = recent[client]
            stamp = time.monotonic()
            while window and stamp - window[0] > 60:
                window.popleft()
            if len(window) >= RATE_LIMIT:
                self._send(429, {"error": "rate_limited", "message": "Try again in a minute."})
                return
            window.append(stamp)
            if self.path != "/v1/activate":
                self._send(404, {"error": "not_found", "message": "Unknown endpoint."})
                return
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= MAX_BODY:
                self._send(400, {"error": "bad_request", "message": "The request is not valid."})
                return
            try:
                body = json.loads(self.rfile.read(length))
                key, machine = str(body["license_key"]), str(body["machine"])
            except (ValueError, KeyError, TypeError):
                self._send(400, {"error": "bad_request", "message": "The request is not valid."})
                return
            try:
                status, answer = service.activate(key, machine)
            except LicenseError:
                status, answer = 500, {"error": "server_error", "message": "Try again later."}
            self._send(status, answer)

    return Handler


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Airlock activation server")
    sub = parser.add_subparsers(dest="command", required=True)
    serve = sub.add_parser("serve")
    serve.add_argument("--db", required=True)
    serve.add_argument("--signing-key", required=True)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    add = sub.add_parser("add-key")
    add.add_argument("--db", required=True)
    add.add_argument("--customer", required=True)
    add.add_argument("--seats", type=int, default=1)
    add.add_argument("--email")
    add.add_argument("--updates-until")
    listing = sub.add_parser("list")
    listing.add_argument("--db", required=True)
    release = sub.add_parser("release")
    release.add_argument("--db", required=True)
    release.add_argument("--key", required=True)
    release.add_argument("--machine", required=True)
    args = parser.parse_args(argv)

    db = connect(args.db)
    if args.command == "add-key":
        key = Activations(db, None).add_key(
            args.customer, args.seats, args.email, args.updates_until
        )
        print(key)
    elif args.command == "list":
        for row in db.execute(
            "SELECT k.license_id, k.customer, k.seats, COUNT(a.machine) FROM licence_keys k "
            "LEFT JOIN activations a ON a.key_hash = k.key_hash GROUP BY k.key_hash"
        ):
            print(f"{row[0]}  {row[1]}  {row[3]}/{row[2]} seats used")
    elif args.command == "release":
        db.execute(
            "DELETE FROM activations WHERE key_hash = ? AND machine = ?",
            (key_hash(args.key), args.machine),
        )
        print("released")
    else:
        service = Activations(db, Path(args.signing_key))
        server = ThreadingHTTPServer((args.host, args.port), make_handler(service))
        print(f"listening on {args.host}:{args.port} (put HTTPS in front of it)")
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
