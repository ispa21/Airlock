"""Engine entry point. Launched by the desktop host as a child process."""

from __future__ import annotations

import argparse
import multiprocessing
import os
import sys
from typing import BinaryIO

from airlock_engine import __version__, safelog
from airlock_engine.api import build_registry
from airlock_engine.ipc.server import StdioServer
from airlock_engine.security import network_guard


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="airlock-engine",
        description="Airlock local privacy engine (JSON-RPC over stdio).",
    )
    parser.add_argument("--version", action="version", version=f"airlock-engine {__version__}")
    parser.add_argument(
        "--log-level", choices=("debug", "info", "warning", "error"), default="info"
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
    args = _parse_args(argv)
    # Network isolation first, before any other module has a chance to run.
    network_guard.install()
    safelog.configure(args.log_level)
    reader, writer = _claim_stdio()
    safelog.log.info("engine_started", version=__version__, pid=os.getpid())
    server = StdioServer(build_registry(), reader, writer)
    return server.serve_forever()
