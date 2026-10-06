"""Smoke test for the browser-extension bridge of an installed engine.

Does what Chrome or Edge does: reads the native-messaging host manifest,
starts the engine it names with the extension's origin, and exchanges
length-prefixed messages with it. Checks that the extension's methods work,
that other methods and other origins are refused, and that the engine exits
when the browser closes the connection.

Usage:  python packaging/bridge_smoke.py <path to com.airlock.engine host manifest>
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

EXTENSION_ORIGIN = "chrome-extension://cbihflandcpahjbogbficbpidmpdgcce/"
EMAIL = "dana.reyes@example.invalid"
SECRET = "Zq8vT2pLm4Wx9"  # noqa: S105 - synthetic test value
PROMPT = f"Ask {EMAIL} to rotate the key.\ndb_password = {SECRET}\n"


def engine_path(manifest_path: Path) -> Path:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert manifest["name"] == "com.airlock.engine", manifest
    assert manifest["type"] == "stdio", manifest
    assert manifest["allowed_origins"] == [EXTENSION_ORIGIN], manifest["allowed_origins"]
    path = Path(manifest["path"])
    # Chrome and Edge resolve a relative path against the manifest's folder (Windows).
    return path if path.is_absolute() else manifest_path.parent / path


def start(exe: Path, origin: str) -> subprocess.Popen[bytes]:
    # Chrome passes the origin first; on Windows it adds --parent-window.
    return subprocess.Popen(
        [str(exe), origin, "--parent-window=0"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )


def send(proc: subprocess.Popen[bytes], message: dict[str, Any]) -> None:
    assert proc.stdin is not None
    body = json.dumps(message).encode("utf-8")
    proc.stdin.write(struct.pack("<I", len(body)) + body)
    proc.stdin.flush()


def receive(proc: subprocess.Popen[bytes], request_id: int) -> dict[str, Any]:
    assert proc.stdout is not None
    while True:
        header = proc.stdout.read(4)
        if len(header) < 4:
            raise RuntimeError("the engine closed the connection")
        (length,) = struct.unpack("<I", header)
        message: dict[str, Any] = json.loads(proc.stdout.read(length))
        if message.get("id") == request_id:
            return message


def call(proc: subprocess.Popen[bytes], request_id: int, method: str, **params: Any) -> Any:
    send(proc, {"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
    return receive(proc, request_id)


def main() -> int:
    exe = engine_path(Path(sys.argv[1]).resolve())
    assert exe.is_file(), f"the host manifest names a missing engine: {exe}"
    print(f"host manifest names {exe.name}; origin {EXTENSION_ORIGIN}")

    proc = start(exe, EXTENSION_ORIGIN)
    try:
        health = call(proc, 1, "system.health")["result"]
        assert health["network_isolation"], health
        profiles = call(proc, 2, "profiles.list")["result"]
        assert profiles["profiles"], profiles
        protected = call(proc, 3, "text.protect", text=PROMPT)["result"]
        assert EMAIL not in protected["text"] and SECRET not in protected["text"], "value left"
        assert "EMAIL_001" in protected["text"] and protected["blocked"] >= 1, protected
        assert protected["check"]["status"] == "safe", protected["check"]
        print(f"text.protect: {protected['text']!r}")
        refused = call(proc, 4, "scan.start", path=str(exe))
        assert refused["error"]["code"] == -32601, refused
        print("methods outside the extension's list are refused")
    finally:
        assert proc.stdin is not None
        proc.stdin.close()  # the browser closing the port
    code = proc.wait(timeout=30)
    assert code == 0, f"engine exit code {code} after the browser closed the port"
    print("engine exited when the connection closed")

    other = start(exe, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/")
    assert other.stdin is not None
    other.stdin.close()
    assert other.wait(timeout=30) == 2, "another extension's origin was not refused"
    print("other extensions are refused")
    print("bridge smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
