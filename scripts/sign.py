"""Sign one file with the operator's code-signing command.

AIRLOCK_SIGN_COMMAND holds the command line, with {file} where the file
goes; it runs through the shell, so Windows quoting works as typed. Used by
scripts/package.py for the engine and, through Tauri's signCommand, for the
app and the installer. Without the variable nothing is signed.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def sign(path: Path) -> bool:
    template = os.environ.get("AIRLOCK_SIGN_COMMAND", "").strip()
    if not template:
        print(f"note: not signing {path.name} (AIRLOCK_SIGN_COMMAND is not set)")
        return False
    print(f"+ signing {path.name}", flush=True)
    subprocess.run(template.replace("{file}", f'"{path}"'), shell=True, check=True)  # noqa: S602
    return True


if __name__ == "__main__":
    sign(Path(sys.argv[1]))
