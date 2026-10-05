"""Write THIRD_PARTY_NOTICES.txt for the installer.

Lists every component that ships with Airlock, with its licence and the
licence texts the component itself carries:

* the engine's Python runtime dependencies (run this with the engine's
  Python: ``uv run --directory engine python ../scripts/notices.py OUT``),
* the desktop host's Rust crates (normal dependencies, via cargo metadata),
* the UI's npm production packages,
* components bundled outside those package managers.

Usage: python scripts/notices.py <output file>
"""

from __future__ import annotations

import importlib.metadata as md
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TAURI = ROOT / "apps" / "desktop" / "src-tauri"
DESKTOP = ROOT / "apps" / "desktop"
LICENCE_FILE = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE|COPYRIGHT|AUTHORS)[^/]*$", re.I)
RULE = "=" * 78
_COPYLEFT = re.compile(r"\b(A?GPL|LGPL|SSPL)", re.I)
_PERMISSIVE = re.compile(r"MIT|BSD|Apache|ISC|Zlib|Unicode|CC0|0BSD|MPL|BSL-1\.0|Unlicense", re.I)


def copyleft_only(expression: str) -> bool:
    """True when a licence expression offers no permissive choice."""
    if not _COPYLEFT.search(expression):
        return False
    choices = re.split(r"\s+OR\s+|/", expression)
    return not any(_PERMISSIVE.search(c) and not _COPYLEFT.search(c) for c in choices)


PROBLEMS: list[str] = []

EXTRA = [
    (
        "PyInstaller bootloader",
        "GPL-2.0-or-later WITH Bootloader-exception",
        "The bootloader that starts airlock-engine.exe is from PyInstaller. Its licence "
        "includes an exception that allows distributing the bundled program under any "
        "licence; see https://github.com/pyinstaller/pyinstaller/blob/develop/COPYING.txt",
    ),
    (
        "Microsoft Edge WebView2 Runtime",
        "Microsoft Software License Terms",
        "Installed or updated by the WebView2 bootstrapper or offline installer that the "
        "Airlock installer runs when the runtime is missing.",
    ),
]


def _python_closure() -> dict[str, md.Distribution]:
    seen: dict[str, md.Distribution] = {}
    stack = ["airlock-engine"]
    while stack:
        name = re.split(r"[\s;<>=!~\[(]", stack.pop(), maxsplit=1)[0].lower().replace("_", "-")
        if name in seen:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue
        seen[name] = dist
        stack += [r for r in dist.requires or [] if "extra ==" not in r]
    seen.pop("airlock-engine", None)
    return dict(sorted(seen.items()))


def _python_section() -> list[str]:
    out = []
    for dist in _python_closure().values():
        meta = dist.metadata
        licence = meta.get("License-Expression") or meta.get("License") or ""
        if len(licence) > 120:
            licence = licence.splitlines()[0][:120]
        classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or []
                       if c.startswith("License ::")]  # fmt: skip
        texts = []
        for file in dist.files or []:
            if LICENCE_FILE.search(str(file)):
                try:
                    texts.append(Path(str(dist.locate_file(file))).read_text("utf-8", "replace"))
                except OSError:
                    continue
        out.append(
            _entry(f"{meta['Name']} {dist.version}", licence or ", ".join(classifiers), texts)
        )
    return out


def _rust_section() -> list[str]:
    raw = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--filter-platform",
         "x86_64-pc-windows-msvc", "--manifest-path", str(TAURI / "Cargo.toml")],
        capture_output=True, check=True, text=True,
    ).stdout  # fmt: skip
    data = json.loads(raw)
    packages = {p["id"]: p for p in data["packages"]}
    nodes = {n["id"]: n for n in data["resolve"]["nodes"]}
    root = data["resolve"]["root"]
    shipped, stack = set(), [root]
    while stack:
        node = nodes[stack.pop()]
        for dep in node["deps"]:
            if any(k["kind"] is None for k in dep["dep_kinds"]) and dep["pkg"] not in shipped:
                shipped.add(dep["pkg"])
                stack.append(dep["pkg"])
    out = []
    for pid in sorted(shipped, key=lambda i: packages[i]["name"]):
        package = packages[pid]
        folder = Path(package["manifest_path"]).parent
        texts = [
            f.read_text("utf-8", "replace")
            for f in sorted(folder.iterdir())
            if f.is_file() and LICENCE_FILE.search(f.name)
        ]
        licence = package.get("license") or ""
        if copyleft_only(licence):
            PROBLEMS.append(f"{package['name']} ({licence})")
        out.append(_entry(f"{package['name']} {package['version']}", licence, texts))
    return out


def _npm_section() -> list[str]:
    lock = json.loads((DESKTOP / "package-lock.json").read_text("utf-8"))
    out = []
    for path, info in sorted(lock.get("packages", {}).items()):
        if not path or info.get("dev") or info.get("devOptional"):
            continue
        folder = DESKTOP / path
        name = path.split("node_modules/")[-1]
        texts = []
        if folder.is_dir():
            texts = [
                f.read_text("utf-8", "replace")
                for f in sorted(folder.iterdir())
                if f.is_file() and LICENCE_FILE.search(f.name)
            ]
        licence = info.get("license", "")
        if copyleft_only(licence):
            PROBLEMS.append(f"{name} ({licence})")
        out.append(_entry(f"{name} {info.get('version', '')}", licence, texts))
    return out


def _entry(title: str, licence: str, texts: list[str]) -> str:
    body = (
        "\n\n".join(t.strip() for t in texts if t.strip())
        or "(no licence file shipped with the package)"
    )
    return f"{RULE}\n{title}\nLicence: {licence or 'see below'}\n{RULE}\n\n{body}\n"


def main() -> int:
    output = Path(sys.argv[1])
    parts = [
        "AIRLOCK - THIRD-PARTY SOFTWARE NOTICES\n\n"
        "Airlock includes the open-source components listed below. Each is used under its\n"
        "own licence, reproduced here. Copyleft components (GPL, AGPL, LGPL, SSPL) are not\n"
        "shipped; the MPL-2.0 components are distributed unmodified.\n",
        "\n# Engine (Python)\n",
        *_python_section(),
        "\n# Desktop host (Rust)\n",
        *_rust_section(),
        "\n# Interface (JavaScript)\n",
        *_npm_section(),
        "\n# Other bundled components\n",
        *[_entry(name, licence, [text]) for name, licence, text in EXTRA],
    ]
    if PROBLEMS:
        sys.exit(f"copyleft-only components would ship: {PROBLEMS}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text("\n".join(parts), encoding="utf-8")
    print(f"notices: {output} ({output.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
