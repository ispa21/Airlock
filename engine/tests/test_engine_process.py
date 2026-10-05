"""Spawns the real engine exactly as the desktop host does."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.subprocess


class Engine:
    def __init__(self) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "airlock_engine", "--log-level", "debug"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self._next = 0

    def call(self, method: str, **params: Any) -> dict[str, Any]:
        assert self.proc.stdin and self.proc.stdout
        self._next += 1
        msg = {"jsonrpc": "2.0", "id": self._next, "method": method, "params": params}
        self.proc.stdin.write(json.dumps(msg).encode() + b"\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            assert line, "engine closed stdout"
            reply = json.loads(line)
            if reply.get("id") == self._next:
                return reply

    def close(self) -> tuple[int, str]:
        assert self.proc.stdin
        self.proc.stdin.close()  # EOF => graceful exit
        code = self.proc.wait(timeout=20)
        assert self.proc.stderr
        return code, self.proc.stderr.read().decode()


def test_engine_roundtrip_and_clean_exit(sample_files: dict[str, Path]) -> None:
    engine = Engine()
    hello = engine.call("system.hello", protocol_version="1.0")["result"]
    assert hello["compatible"] and hello["network_isolation"] is True

    inspected = engine.call("document.inspect", path=str(sample_files["csv"]))["result"]
    assert inspected["format"] == "csv"

    health = engine.call("system.health")["result"]
    assert health["status"] == "ok" and health["blocked_network_attempts"] == 0

    code, stderr = engine.close()
    assert code == 0
    # stderr carries only structured, allowlisted JSON log records.
    records = [json.loads(line) for line in stderr.splitlines() if line.strip()]
    assert any(r["event"] == "engine_started" for r in records)
    assert all("dropped_fields" not in r for r in records)
    # Neither the file name, its directory nor its contents reach the logs.
    assert "customers" not in stderr
    assert str(sample_files["csv"].parent) not in stderr
    assert "test.user@example.invalid" not in stderr


def test_stdout_pollution_cannot_corrupt_protocol() -> None:
    """print() and raw writes to fd 1 after start-up go to stderr, not the pipe."""
    script = textwrap.dedent(
        """
        import os, sys
        from airlock_engine import cli
        reader, writer = cli._claim_stdio()
        print("stray print from a library")
        os.write(1, b"native write to fd 1\\n")
        sys.stdout.flush()
        writer.write(b'{"frame":1}\\n'); writer.flush()
        """
    )
    proc = subprocess.run(
        [sys.executable, "-c", script], input=b"", capture_output=True, timeout=30
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout == b'{"frame":1}\n'
    assert b"stray print" in proc.stderr and b"native write" in proc.stderr


def test_version_flag() -> None:
    out = subprocess.run(
        [sys.executable, "-m", "airlock_engine", "--version"], capture_output=True, text=True
    )
    assert out.stdout.startswith("airlock-engine ")
