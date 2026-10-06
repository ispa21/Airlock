"""Register the Airlock engine as a native-messaging host for development.

Windows installs do this automatically (installer registry keys). On Linux and
macOS, or with a development engine, run:

    python apps/extension/scripts/register_host.py                  # Chrome + Chromium (+ Edge)
    python apps/extension/scripts/register_host.py --user-data-dir /tmp/profile
    python apps/extension/scripts/register_host.py --engine /path/to/airlock-engine

It writes a small launcher (the browser passes the extension origin to it)
and the host manifest naming only the Airlock extension's origin.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HOST_NAME = "com.airlock.engine"
TEMPLATE = ROOT / "apps" / "desktop" / "src-tauri" / "windows" / "native-messaging-host.json"


def browser_dirs() -> list[Path]:
    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
        names = ["Google/Chrome", "Chromium", "Microsoft Edge"]
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
        names = ["google-chrome", "chromium", "microsoft-edge"]
    return [base / name / "NativeMessagingHosts" for name in names]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--engine", help="engine executable (default: the development venv)")
    parser.add_argument("--user-data-dir", help="register only for this browser profile folder")
    parser.add_argument("--data-dir", help="Airlock data folder for the engine (XDG_DATA_HOME)")
    args = parser.parse_args()

    launcher = ROOT / "apps" / "extension" / ".host" / "airlock-engine-host"
    launcher.parent.mkdir(exist_ok=True)
    if args.engine:
        command = f'exec "{Path(args.engine).resolve()}" "$@"'
    else:
        python = ROOT / "engine" / ".venv" / "bin" / "python"
        command = f'cd "{ROOT / "engine"}" && exec "{python}" -m airlock_engine "$@"'
    env = f'export XDG_DATA_HOME="{Path(args.data_dir).resolve()}"\n' if args.data_dir else ""
    launcher.write_text(f"#!/bin/sh\n{env}{command}\n", encoding="utf-8")
    launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP)

    manifest = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    manifest["path"] = str(launcher)  # absolute on Linux and macOS
    targets = (
        [Path(args.user_data_dir) / "NativeMessagingHosts"]
        if args.user_data_dir
        else browser_dirs()
    )
    for folder in targets:
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"{HOST_NAME}.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"registered {folder / (HOST_NAME + '.json')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
