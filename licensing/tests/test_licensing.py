"""Licence tool and reference activation server."""

from __future__ import annotations

import http.client
import json
import sys
import threading
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import activation_server as server
from airlock_license import (
    LicenseError,
    b64,
    extract_token,
    payload_for,
    sign,
    unb64,
    verify,
)

MACHINE = "ABCD-EFGH-IJKL-MNOP-QRST"
SEED = bytes(range(32))  # test key only; never in public-keys.json
KEY = Ed25519PrivateKey.from_private_bytes(SEED)
KEYS = {"test-key": KEY.public_key()}


def issue(**kw: object) -> str:
    payload = payload_for(customer="Acme Pvt Ltd", seats=3, **kw)  # type: ignore[arg-type]
    return sign(payload, KEY, "test-key")


def test_issue_and_verify_round_trip() -> None:
    token = issue(email="it@acme.example", machine=MACHINE, updates_until="2027-10-06")
    payload = verify(token, KEYS)
    assert payload["customer"] == "Acme Pvt Ltd" and payload["seats"] == 3
    assert payload["plan"] == "lifetime" and payload["expiry"] is None
    assert payload["machine"] == MACHINE and payload["license_id"].startswith("lic_")
    assert token.startswith("AIRLOCK1.test-key.") and token.count(".") == 3


def test_the_licence_line_is_found_in_any_text() -> None:
    token = issue()
    text = f"Hello,\n\nhere is your licence:\n\n  {token}  \n\nThanks"
    assert extract_token(text) == token
    with pytest.raises(LicenseError):
        extract_token("no licence here")


def test_tampering_and_unknown_keys_are_refused() -> None:
    token = issue()
    prefix, key_id, body, sig = token.split(".")
    changed = json.loads(unb64(body))
    changed["seats"] = 1000
    forged = ".".join((prefix, key_id, b64(json.dumps(changed).encode()), sig))
    with pytest.raises(LicenseError, match="signature"):
        verify(forged, KEYS)
    other = Ed25519PrivateKey.generate()
    with pytest.raises(LicenseError, match="signature"):
        verify(sign(payload_for(customer="X", seats=1), other, "test-key"), KEYS)
    with pytest.raises(LicenseError, match="known"):
        verify(token.replace("test-key", "other-key", 1), KEYS)
    with pytest.raises(LicenseError):
        verify("AIRLOCK1.test-key.!!!.???", KEYS)


def test_payload_validation() -> None:
    with pytest.raises(LicenseError):
        payload_for(customer="", seats=1)
    with pytest.raises(LicenseError):
        payload_for(customer="A", seats=0)
    with pytest.raises(LicenseError):
        payload_for(customer="A", seats=1, machine="not-a-code")
    fixed = payload_for(
        customer="A", seats=1, license_id="lic_X", issued_at=datetime(2026, 1, 2, tzinfo=UTC)
    )
    assert fixed["issued_at"] == "2026-01-02T00:00:00Z"


@pytest.fixture
def running(tmp_path: Path):  # type: ignore[no-untyped-def]
    key_file = tmp_path / "test.key"
    key_file.write_text(json.dumps({"id": "test-key", "ed25519_private": b64(SEED)}))
    service = server.Activations(server.connect(str(tmp_path / "a.db")), key_file)
    httpd = server.ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(service))
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield service, httpd.server_address[1]
    httpd.shutdown()


def post(port: int, body: object) -> tuple[int, dict[str, object]]:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    data = json.dumps(body).encode()
    conn.request("POST", "/v1/activate", data, {"Content-Type": "application/json"})
    response = conn.getresponse()
    return response.status, json.loads(response.read())


def test_activation_binds_licences_and_counts_seats(running) -> None:  # type: ignore[no-untyped-def]
    service, port = running
    key = service.add_key("Acme Pvt Ltd", 2, None, None)
    assert key.startswith("ALK-") and len(key) == 27
    # Stored hashed: the key itself is not in the database.
    assert key not in str(list(service.db.execute("SELECT * FROM licence_keys")))

    status, body = post(port, {"license_key": key, "machine": MACHINE})
    assert status == 200
    payload = verify(str(body["license"]), KEYS)
    assert payload["machine"] == MACHINE and payload["seats"] == 2
    # The same machine again: same licence id, no extra seat.
    status, again = post(port, {"license_key": key.lower(), "machine": MACHINE})
    assert (
        status == 200 and verify(str(again["license"]), KEYS)["license_id"] == payload["license_id"]
    )
    assert post(port, {"license_key": key, "machine": "BBBB-EFGH-IJKL-MNOP-QRST"})[0] == 200
    status, full = post(port, {"license_key": key, "machine": "CCCC-EFGH-IJKL-MNOP-QRST"})
    assert status == 409 and full["error"] == "no_seats_left"


def test_activation_rejects_bad_requests(running) -> None:  # type: ignore[no-untyped-def]
    _, port = running
    assert post(port, {"license_key": "ALK-AAAAA-AAAAA-AAAAA-AAAAA", "machine": MACHINE})[0] == 404
    assert post(port, {"license_key": "nope", "machine": MACHINE})[0] == 400
    assert post(port, {"license_key": "ALK-AAAAA-AAAAA-AAAAA-AAAAA", "machine": "x"})[0] == 400
    assert post(port, {"machine": MACHINE})[0] == 400
