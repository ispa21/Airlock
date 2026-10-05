"""Runtime enforcement that the privacy engine never talks to the network.

Installed once at engine start-up as a CPython audit hook. Audit hooks cannot
be removed, and they fire for every socket operation made through Python
(``socket``, ``ssl``, ``http.client``, ``urllib``, ``requests``, model
downloaders, telemetry, ...). Any attempt to resolve a remote host or connect
to a non-loopback address raises :class:`NetworkAccessBlocked` before a packet
is sent.

Loopback stays allowed because the standard library uses it internally on
Windows (``socket.socketpair``); proxy environment variables are removed so a
local proxy cannot be used as a relay.

This is defence in depth. The installer can additionally add a Windows
Firewall outbound-block rule for the engine executable (see docs/SECURITY.md).
"""

from __future__ import annotations

import ipaddress
import os
import sys
from typing import Any, Final

_PROXY_VARS: Final = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
)
_LOOPBACK_NAMES: Final = frozenset({"localhost", "localhost.", ""})

_installed = False
_blocked_attempts = 0


class NetworkAccessBlocked(PermissionError):
    """Raised when engine code attempts outbound network access."""


def _is_loopback(host: object) -> bool:
    if host is None:  # passive lookups (binding), no name resolution happens
        return True
    if isinstance(host, bytes):
        host = host.decode("ascii", "ignore")
    if not isinstance(host, str):
        return False
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host.split("%", 1)[0]).is_loopback
    except ValueError:
        return False


def _address_is_local(address: Any) -> bool:
    # AF_UNIX paths (str/bytes that are not hosts) and AF_INET/AF_INET6 tuples.
    if isinstance(address, tuple) and address:
        return _is_loopback(address[0])
    # A non-tuple address is a filesystem/abstract socket: local by definition.
    return isinstance(address, str | bytes)


def _block() -> None:
    global _blocked_attempts
    _blocked_attempts += 1
    raise NetworkAccessBlocked(
        "Network access is disabled inside the Airlock engine. "
        "Documents are processed entirely on this device."
    )


def _hook(event: str, args: tuple[Any, ...]) -> None:
    if not event.startswith(("socket.", "urllib.")):
        return
    if event in (
        "socket.getaddrinfo",
        "socket.gethostbyname",
        "socket.gethostbyname_ex",
        "socket.gethostbyaddr",
    ):
        if not _is_loopback(args[0]):
            _block()
    elif event in ("socket.connect", "socket.sendto", "socket.sendmsg"):
        # args are (socket, address); sendmsg passes None when connected.
        address = args[-1]
        if address is not None and not _address_is_local(address):
            _block()
    elif event == "urllib.Request":
        _block()


def install() -> None:
    """Install the guard. Idempotent; cannot be undone for the process lifetime."""
    global _installed
    if _installed:
        return
    for var in _PROXY_VARS:
        os.environ.pop(var, None)
    sys.addaudithook(_hook)
    _installed = True


def is_installed() -> bool:
    return _installed


def blocked_attempts() -> int:
    return _blocked_attempts
