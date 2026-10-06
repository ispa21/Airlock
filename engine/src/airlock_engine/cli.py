"""Engine entry point. Launched by the desktop host as a child process."""

from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
from pathlib import Path
from typing import BinaryIO

from airlock_engine import __version__, safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc import native_messaging
from airlock_engine.ipc.server import StdioServer
from airlock_engine.security import network_guard
from airlock_engine.storage import default_data_dir


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="airlock-engine",
        description="Airlock local privacy engine (JSON-RPC over stdio).",
    )
    parser.add_argument("--version", action="version", version=f"airlock-engine {__version__}")
    parser.add_argument(
        "--log-level", choices=("debug", "info", "warning", "error"), default="info"
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=None,
        help="Per-user folder for the settings database (default: the platform app-data folder).",
    )
    parser.add_argument(
        "--memory-only",
        action="store_true",
        help="Keep company rules in memory only (nothing is written to disk).",
    )
    return parser.parse_args(argv)


def _claim_stdio() -> tuple[BinaryIO, BinaryIO]:
    """Take exclusive ownership of the protocol pipes.

    The real stdin/stdout are duplicated onto private descriptors. File
    descriptor 1 is then pointed at stderr and descriptor 0 at the null
    device, so a stray ``print()`` or a native library writing to stdout can
    never corrupt a protocol frame, and nothing else can consume requests.
    """
    proto_in_fd = os.dup(sys.stdin.fileno())
    proto_out_fd = os.dup(sys.stdout.fileno())
    os.dup2(sys.stderr.fileno(), sys.stdout.fileno())
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, sys.stdin.fileno())
    os.close(devnull)
    sys.stdout = sys.stderr
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(proto_in_fd, os.O_BINARY)
        msvcrt.setmode(proto_out_fd, os.O_BINARY)
    # Buffered streams: readline() on a raw FileIO would cost a syscall per byte.
    # The server flushes after every frame.
    return os.fdopen(proto_in_fd, "rb"), os.fdopen(proto_out_fd, "wb")


def main(argv: list[str] | None = None) -> int:
    # Required for extraction workers in the frozen (PyInstaller) build.
    multiprocessing.freeze_support()
    raw_args = sys.argv[1:] if argv is None else argv
    if raw_args and native_messaging.is_extension_origin(raw_args[0]):
        return _bridge(raw_args[0])
    args = _parse_args(argv)
    # Network isolation first, before any other module has a chance to run.
    network_guard.install()
    safelog.configure(args.log_level)
    reader, writer = _claim_stdio()
    safelog.log.info("engine_started", version=__version__, pid=os.getpid())
    data_dir = None if args.memory_only else (args.data_dir or default_data_dir())
    server = StdioServer(build_registry(data_dir), reader, writer)
    return server.serve_forever()


def _bridge(origin: str) -> int:
    """Started by Chrome or Edge for the Airlock extension (native messaging).

    Uses the same per-user data folder as the desktop app, so company rules,
    profiles and "not sensitive" decisions apply in the browser too.
    """
    network_guard.install()
    safelog.configure("info")
    reader, writer = _claim_stdio()
    registry = build_registry(default_data_dir())
    return native_messaging.serve(registry, origin, reader, writer)
