"""The guard is a permanent audit hook, so each case runs in a fresh interpreter."""

from __future__ import annotations

import socket
import subprocess
import sys
import textwrap

import pytest


def _ipv6_available() -> bool:
    try:
        socket.socket(socket.AF_INET6).close()
    except OSError:
        return False
    return True


def _run(body: str) -> subprocess.CompletedProcess[str]:
    script = "from airlock_engine.security import network_guard\nnetwork_guard.install()\n"
    script += textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=60
    )


@pytest.mark.parametrize(
    "attempt",
    [
        "import socket; socket.getaddrinfo('example.com', 443)",
        "import socket; socket.gethostbyname('example.com')",
        "import socket; socket.create_connection(('93.184.216.34', 443), timeout=2)",
        "import socket; s = socket.socket(); s.connect(('1.1.1.1', 53))",
        "import socket; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'x', ('8.8.8.8', 53))",
        "import urllib.request; urllib.request.urlopen('https://api.openai.com/v1/models', timeout=2)",
        "import http.client; c = http.client.HTTPSConnection('api.anthropic.com', timeout=2); c.request('GET', '/')",
        pytest.param(
            "import socket; socket.socket(socket.AF_INET6).connect(('2606:4700:4700::1111', 53, 0, 0))",
            marks=pytest.mark.skipif(not _ipv6_available(), reason="no IPv6 stack"),
        ),
    ],
)
def test_outbound_network_is_blocked(attempt: str) -> None:
    proc = _run(
        f"""
        from airlock_engine.security.network_guard import NetworkAccessBlocked
        try:
            {attempt}
        except NetworkAccessBlocked:
            print("BLOCKED")
        except Exception as exc:
            print("OTHER", type(exc).__name__)
        else:
            print("ALLOWED")
        """
    )
    assert proc.stdout.strip() == "BLOCKED", proc.stdout + proc.stderr


def test_loopback_and_socketpair_still_work() -> None:
    proc = _run(
        """
        import socket
        a, b = socket.socketpair()
        a.sendall(b"ping"); assert b.recv(4) == b"ping"
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        cli = socket.create_connection(srv.getsockname(), timeout=2)
        print("OK")
        """
    )
    assert proc.stdout.strip() == "OK", proc.stderr


def test_proxy_variables_are_removed() -> None:
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import os\nfrom airlock_engine.security import network_guard\n"
            "network_guard.install()\nprint(os.environ.get('HTTPS_PROXY'), os.environ.get('http_proxy'))",
        ],
        capture_output=True,
        text=True,
        timeout=60,
        env={**__import__("os").environ, "HTTPS_PROXY": "http://127.0.0.1:9", "http_proxy": "x"},
    )
    assert proc.stdout.strip() == "None None"
