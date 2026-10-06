"""text.protect and the browser-extension bridge (native messaging, Phase 11)."""

from __future__ import annotations

import io
import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from airlock_engine import safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc import native_messaging
from airlock_engine.ipc.native_messaging import NativeMessagingServer, encode, serve
from synthetic import Synth
from test_api_scan import call, req, result_of

S = Synth(1111)
EMAIL = S.email()
PAN = S.pan()
PW = S.password()
ORIGIN = next(iter(native_messaging.ALLOWED_ORIGINS))
PROMPT = (
    f"Summarise this for the board. Owner: {EMAIL}, PAN {PAN}.\n"
    f"db_password = {PW}\nEscalations go to {EMAIL} as well."
)


def frames(*messages: dict[str, Any]) -> io.BytesIO:
    return io.BytesIO(b"".join(encode(m) for m in messages))


def read_frames(data: bytes) -> list[dict[str, Any]]:
    out, pos = [], 0
    while pos < len(data):
        (length,) = struct.unpack("<I", data[pos : pos + 4])
        message = json.loads(data[pos + 4 : pos + 4 + length])
        if "id" in message:  # skip progress notifications
            out.append(message)
        pos += 4 + length
    return out


def test_text_protect_masks_redacts_blocked_items_and_leaks_nothing(tmp_path: Path) -> None:
    stream = io.StringIO()
    original = safelog.log
    safelog.log = safelog.SafeLogger(stream, level="debug")
    try:
        rs = call(build_registry(tmp_path), req(1, "text.protect", text=PROMPT, ner=False))
    finally:
        safelog.log = original
    result = result_of(rs, 1)
    protected = result["text"]
    for value in (EMAIL, PAN, PW):
        assert value not in protected
        assert value not in json.dumps(result)
        assert value not in stream.getvalue()
    assert protected.count("[EMAIL_1]") == 2  # every repeat, one consistent placeholder
    assert "[PAN_1]" in protected and "[REDACTED]" in protected
    assert protected.startswith("Summarise this for the board.")
    assert result["blocked"] == 1 and result["changed"] >= 3
    assert result["profile"]["id"] == "company-default"
    assert {f["entity_type"] for f in result["findings"]} >= {"EMAIL", "PAN", "PASSWORD"}
    assert '"event":"text_protected"' in stream.getvalue()


def test_text_protect_validates_and_respects_the_allow_list(tmp_path: Path) -> None:
    from airlock_engine.storage import Storage

    Storage(tmp_path).allow_list.add("EMAIL", EMAIL)
    registry = build_registry(tmp_path)
    result = result_of(call(registry, req(1, "text.protect", text=PROMPT, ner=False)), 1)
    assert EMAIL in result["text"]  # the user marked it "not sensitive"
    assert result_of(call(registry, req(2, "text.protect", text="", ner=False)), 2)["text"] == ""
    rs = call(
        registry,
        req(3, "text.protect", text="x" * 200_001),
        req(4, "text.protect", text=PROMPT, profile_id=7),
        req(5, "text.protect", text=PROMPT, profile_id="nope", ner=False),
    )
    errors = {r["id"]: r["error"] for r in rs if "error" in r}
    assert errors[3]["code"] == errors[4]["code"] == -32602
    assert errors[5]["data"]["kind"] == "profile_not_found"


def test_text_protect_applies_company_rules(tmp_path: Path) -> None:
    registry = build_registry(tmp_path)
    call(
        registry,
        req(
            1,
            "rules.create",
            kind="normalized",
            pattern="Project Nightjar",
            category_id="INTERNAL_PROJECT",
        ),
    )
    text = "Draft the launch note for project  NIGHTJAR. Project Nightjar ships in May."
    result = result_of(call(registry, req(2, "text.protect", text=text, ner=False)), 2)
    assert "nightjar" not in result["text"].lower()
    assert {f["entity_type"] for f in result["findings"]} == {"INTERNAL_PROJECT"}
    assert "Nightjar" not in json.dumps(result["findings"])


def test_bridge_frames_and_allows_only_the_extension_methods(tmp_path: Path) -> None:
    out = io.BytesIO()
    reader = frames(
        {"jsonrpc": "2.0", "id": 1, "method": "system.health", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "text.protect",
            "params": {"text": PROMPT, "ner": False},
        },
        {"jsonrpc": "2.0", "id": 3, "method": "scan.start", "params": {"path": "/etc/passwd"}},
        {"jsonrpc": "2.0", "id": 4, "method": "export.save", "params": {}},
        {"jsonrpc": "2.0", "id": 5, "method": "vault.restore", "params": {}},
    )
    assert serve(build_registry(tmp_path), ORIGIN, reader, out) == 0
    replies = {r["id"]: r for r in read_frames(out.getvalue())}
    assert replies[1]["result"]["network_isolation"] in (True, False)
    assert EMAIL not in replies[2]["result"]["text"]
    for refused in (3, 4, 5):
        assert replies[refused]["error"]["code"] == -32601


def test_bridge_refuses_other_origins_and_oversized_messages(tmp_path: Path) -> None:
    out = io.BytesIO()
    hello = {"jsonrpc": "2.0", "id": 1, "method": "system.health", "params": {}}
    assert (
        serve(build_registry(tmp_path), "chrome-extension://someoneelse/", frames(hello), out) == 2
    )
    assert out.getvalue() == b""

    big = struct.pack("<I", native_messaging.MAX_INCOMING + 1) + b"x" * (
        native_messaging.MAX_INCOMING + 1
    )
    out = io.BytesIO()
    server = NativeMessagingServer(build_registry(tmp_path), io.BytesIO(big + encode(hello)), out)
    server.serve_forever()
    replies = read_frames(out.getvalue())
    assert replies[0]["error"]["code"] == -32002
    assert replies[1]["result"]["status"] == "ok"


@pytest.mark.subprocess
def test_the_engine_starts_as_a_native_messaging_host(tmp_path: Path) -> None:
    """Exactly how Chrome starts it: the extension origin as the first argument."""
    messages = encode({"jsonrpc": "2.0", "id": 1, "method": "system.hello", "params": {}})
    messages += encode(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "text.protect",
            "params": {"text": PROMPT, "ner": False},
        }
    )
    env = {"XDG_DATA_HOME": str(tmp_path), "LOCALAPPDATA": str(tmp_path), "PATH": ""}
    done = subprocess.run(
        [sys.executable, "-m", "airlock_engine", ORIGIN, "--parent-window=0"],
        input=messages,
        capture_output=True,
        timeout=120,
        env={**env, "SYSTEMROOT": "C:\\Windows"} if sys.platform == "win32" else env,
        check=False,
    )
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-2000:]
    replies = {r["id"]: r for r in read_frames(done.stdout)}
    assert replies[1]["result"]["network_isolation"] is True
    assert replies[2]["result"]["blocked"] == 1
    assert EMAIL.encode() not in done.stdout and PW.encode() not in done.stderr
    assert b'"event":"bridge_started"' in done.stderr


def test_extension_id_engine_and_host_manifest_agree() -> None:
    """The ID derived from the extension's public key must be the one the
    engine and the installed host manifest allow."""
    import base64
    import hashlib

    root = Path(__file__).resolve().parents[2]
    manifest = json.loads((root / "apps/extension/manifest.json").read_text(encoding="utf-8"))
    digest = hashlib.sha256(base64.b64decode(manifest["key"])).hexdigest()[:32]
    extension_id = "".join(chr(ord("a") + int(c, 16)) for c in digest)
    origin = f"chrome-extension://{extension_id}/"
    assert origin in native_messaging.ALLOWED_ORIGINS
    host = json.loads(
        (root / "apps/desktop/src-tauri/windows/native-messaging-host.json").read_text("utf-8")
    )
    assert host["name"] == "com.airlock.engine" and host["type"] == "stdio"
    assert host["allowed_origins"] == [origin]
    assert host["path"] == "engine\\airlock-engine.exe"
    assert "nativeMessaging" in manifest["permissions"]
    assert "connect-src 'none'" in manifest["content_security_policy"]["extension_pages"]
