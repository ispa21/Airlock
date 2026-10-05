# PyInstaller spec for the frozen Airlock engine (onedir).
#
# Build:  uv run --group package pyinstaller packaging/airlock-engine.spec --noconfirm
# Output: dist/airlock-engine/airlock-engine[.exe] plus dist/airlock-engine/_internal/
#
# Everything the engine needs at run time is inside that folder: Python, the
# spaCy English model, the OCR models, PDFium and the Vera fonts used to
# rebuild PDFs. Nothing is downloaded at run time.
#
# Licensing (see docs/THIRD_PARTY.md): only ReportLab's Bitstream Vera fonts
# are bundled; its GPL-licensed DarkGarden font and the other sample fonts are
# left out, and so is OpenCV's FFmpeg video plugin on Windows (LGPL, unused).
# scripts/package.py fails a Windows build that still contains either. The
# PyInstaller bootloader is GPL with an exception that allows shipping the
# result under any licence.
# ruff: noqa

import os
import sys
from pathlib import Path

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_submodules,
    copy_metadata,
    get_package_paths,
)

ROOT = Path(SPECPATH).parent  # engine/
ICON = ROOT.parent / "apps" / "desktop" / "src-tauri" / "icons" / "icon.ico"

# spaCy finds its pipeline components and the model through package metadata
# (entry points), so the metadata has to travel with the code.
METADATA = [
    "spacy",
    "spacy-legacy",
    "spacy-loggers",
    "thinc",
    "srsly",
    "catalogue",
    "confection",
    "weasel",
    "en_core_web_sm",
    "rapidocr",
    "onnxruntime",
    "pypdfium2",
    "phonenumbers",
    "cryptography",
    "airlock-engine",
]

datas = []
for name in METADATA:
    datas += copy_metadata(name)
datas += collect_data_files("en_core_web_sm")
datas += collect_data_files("rapidocr")
datas += collect_data_files("phonenumbers")

_, reportlab_dir = get_package_paths("reportlab")
fonts = Path(reportlab_dir) / "fonts"
datas += [
    (str(fonts / name), "reportlab/fonts")
    for name in ("Vera.ttf", "VeraBd.ttf", "VeraIt.ttf", "VeraBI.ttf", "bitstream-vera-license.txt")
]

hiddenimports = collect_submodules("airlock_engine") + [
    "en_core_web_sm",
    "spacy.lang.en",
    "spacy_legacy",
    "spacy_loggers",
    "srsly.msgpack.util",
]

a = Analysis(
    [str(ROOT / "packaging" / "engine_main.py")],
    pathex=[str(ROOT / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "matplotlib",
        "IPython",
        "pytest",
        "docx",
        "openpyxl",
        "pptx",
        "torch",
        "tensorflow",
        "PyInstaller",
    ],
    noarchive=False,
)


#: English, plus the languages spaCy's registry imports while loading any
#: pipeline (their custom tokenizers are registered at import time).
_KEEP_LANGUAGES = {"en", "xx", "ja", "ko", "th", "vi", "zh"}


def _keep(name: str) -> bool:
    """Drop spaCy's other languages (most of its size)."""
    name = name.replace(os.sep, "/").replace(".", "/")
    if name.startswith("spacy/lang/"):
        rest = name[len("spacy/lang/") :]
        sub = rest.split("/", 1)[0]
        is_language_package = "/" in rest or sub in _LANG_PACKAGES
        return not is_language_package or sub in _KEEP_LANGUAGES
    # ReportLab sample fonts other than Vera (DarkGarden is GPL).
    if name.startswith("reportlab/fonts/") and "Vera" not in name and "bitstream" not in name:
        return False
    return True


_spacy_lang = Path(get_package_paths("spacy")[1]) / "lang"
_LANG_PACKAGES = {p.name for p in _spacy_lang.iterdir() if p.is_dir() and p.name != "__pycache__"}

a.pure = [entry for entry in a.pure if _keep(entry[0])]
a.datas = [entry for entry in a.datas if _keep(entry[0])]
# OpenCV's FFmpeg video plugin (LGPL) is loaded only to read video files,
# which Airlock never does. On Windows it is a separate DLL: leave it out.
a.binaries = [entry for entry in a.binaries if "opencv_videoio_ffmpeg" not in entry[0]]

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="airlock-engine",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,  # compressed executables trip antivirus heuristics
    console=True,  # the engine speaks JSON-RPC over stdio; the host hides the window
    icon=str(ICON) if sys.platform == "win32" and ICON.exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="airlock-engine",
)
