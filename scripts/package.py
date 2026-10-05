"""Build the Airlock installer (Windows) or a local bundle for testing.

Steps:
 1. Freeze the engine with PyInstaller (engine/packaging/airlock-engine.spec).
 2. Smoke-test the frozen engine over stdio (language model, OCR, PDF, verify).
 3. Sign the engine executable when AIRLOCK_SIGN_COMMAND is set.
 4. Copy it to apps/desktop/src-tauri/resources/engine and record its SHA-256,
    which is compiled into the host: the app then runs only that engine.
 5. Build the desktop app and the NSIS installer (Tauri), signed through the
    same command when it is set; optionally also the offline-WebView2 variant.

Usage (from the repository root):
    python scripts/package.py                    # installer with the WebView2 bootstrapper
    python scripts/package.py --offline-webview  # also an installer with WebView2 inside
    python scripts/package.py --engine-only      # steps 1-4 (any OS)

AIRLOCK_SIGN_COMMAND is a command line with {file} where the file goes, e.g.
    signtool sign /fd SHA256 /tr <timestamp URL> /td SHA256 /f cert.pfx /p %PASS% {file}
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sign import sign

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "engine"
DESKTOP = ROOT / "apps" / "desktop"
TAURI = DESKTOP / "src-tauri"
EXE = "airlock-engine.exe" if os.name == "nt" else "airlock-engine"


def run(cmd: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    print("+", " ".join(cmd), flush=True)
    subprocess.run(cmd, cwd=cwd, env=env, check=True)


def tool(name: str) -> str:
    found = shutil.which(name) or shutil.which(f"{name}.cmd")
    if not found:
        sys.exit(f"{name} not found on PATH")
    return found


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


#: Files that must never ship (copyleft and unused): ReportLab's GPL sample
#: font and OpenCV's LGPL FFmpeg video plugin.
FORBIDDEN = ("DarkGarden", "opencv_videoio_ffmpeg")
#: On Linux the OpenCV wheel links FFmpeg into cv2 itself, so a Linux build
#: (used only for testing) cannot drop it; Windows builds must be clean.
LINUX_ONLY = ("libavcodec", "libavformat", "libavutil", "libswscale", "libswresample")


def check_bundle(folder: Path) -> None:
    names = [p.name for p in folder.rglob("*") if p.is_file()]
    bad = sorted({n for n in names if any(f in n for f in FORBIDDEN)})
    if os.name == "nt":
        bad += sorted({n for n in names if n.startswith(LINUX_ONLY)})
    if bad:
        sys.exit(f"the engine bundle contains files that must not ship: {bad}")
    print(f"bundle check: {len(names)} files, none forbidden")


def build_engine(skip_smoke: bool) -> Path:
    uv = tool("uv")
    run([uv, "sync", "--locked", "--group", "package"], cwd=ENGINE)
    run(
        [uv, "run", "pyinstaller", "packaging/airlock-engine.spec", "--noconfirm", "--clean"],
        cwd=ENGINE,
    )
    frozen = ENGINE / "dist" / "airlock-engine"
    check_bundle(frozen)
    if not skip_smoke:
        run([uv, "run", "python", "packaging/smoke.py", str(frozen / EXE)], cwd=ENGINE)
    sign(frozen / EXE)
    target = TAURI / "resources" / "engine"
    if target.exists():
        shutil.rmtree(target)
    shutil.copytree(frozen, target)
    digest = sha256(target / EXE)
    (TAURI / "resources" / "engine.sha256").write_text(digest + "\n", encoding="ascii")
    print(f"engine SHA-256 {digest}")
    return target / EXE


def build_app(engine_exe: Path, offline_webview: bool) -> list[Path]:
    npm, npx = tool("npm"), tool("npx")
    run([npm, "ci"], cwd=DESKTOP)
    notices = TAURI / "resources" / "THIRD_PARTY_NOTICES.txt"
    run(
        [tool("uv"), "run", "python", str(ROOT / "scripts" / "notices.py"), str(notices)],
        cwd=ENGINE,
    )
    env = dict(os.environ, AIRLOCK_ENGINE_SHA256=sha256(engine_exe))
    configs = ["--config", "src-tauri/tauri.bundle.conf.json"]
    if os.environ.get("AIRLOCK_SIGN_COMMAND", "").strip():
        # Tauri signs the app and the installer through scripts/sign.py.
        command = {"cmd": sys.executable, "args": [str(ROOT / "scripts" / "sign.py"), "%1"]}
        (TAURI / "tauri.sign.conf.json").write_text(
            json.dumps({"bundle": {"windows": {"signCommand": command}}}), encoding="utf-8"
        )
        configs += ["--config", "src-tauri/tauri.sign.conf.json"]
    run([npx, "tauri", "build", *configs], cwd=DESKTOP, env=env)
    out = TAURI / "target" / "release" / "bundle" / "nsis"
    installers = sorted(out.glob("*-setup.exe"))
    if offline_webview and installers:
        standard = installers[0]
        kept = standard.with_name(standard.stem + "-webview-bootstrapper.exe")
        shutil.move(standard, kept)
        run(
            [npx, "tauri", "bundle", "--bundles", "nsis", *configs,
             "--config", "src-tauri/tauri.offline.conf.json"],
            cwd=DESKTOP,
            env=env,
        )  # fmt: skip
        offline = sorted(out.glob("*-setup.exe"))[0]
        shutil.move(offline, offline.with_name(offline.stem + "-offline.exe"))
        shutil.move(kept, standard)
        installers = sorted(out.glob("*-setup*.exe"))
    for installer in installers:
        print(f"installer: {installer} ({installer.stat().st_size // (1024 * 1024)} MB)")
    return installers


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--engine-only", action="store_true")
    parser.add_argument("--skip-smoke", action="store_true")
    parser.add_argument("--offline-webview", action="store_true")
    args = parser.parse_args()
    engine_exe = build_engine(args.skip_smoke)
    if not args.engine_only:
        build_app(engine_exe, args.offline_webview)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
