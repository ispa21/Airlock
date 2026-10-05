"""Every runtime dependency must be open source under a permissive licence.

Copyleft licences that would impose terms on Airlock itself (GPL, AGPL, LGPL,
SSPL) are rejected. MPL-2.0 is file-level and allowed for unmodified use.
"""

from __future__ import annotations

import importlib.metadata as md
import re

FORBIDDEN = re.compile(
    r"\b(A?GPL|LGPL|GNU (Affero |Lesser )?General Public|SSPL|Commons Clause)\b", re.I
)
PERMISSIVE = re.compile(
    r"MIT|BSD|Apache|PSF|Python Software Foundation|ISC|MPL|Zlib|CC0|0BSD|HPND|CMU", re.I
)


def _licence(dist: md.Distribution) -> str:
    meta = dist.metadata
    parts = [meta.get("License-Expression") or "", meta.get("License") or ""]
    parts += [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return " | ".join(p for p in parts if p)


def _runtime_closure(root: str) -> dict[str, md.Distribution]:
    seen: dict[str, md.Distribution] = {}
    stack = [root]
    while stack:
        name = re.split(r"[\s;<>=!~\[(]", stack.pop(), maxsplit=1)[0].lower().replace("_", "-")
        if name in seen:
            continue
        try:
            dist = md.distribution(name)
        except md.PackageNotFoundError:
            continue  # optional / platform-specific requirement not installed
        seen[name] = dist
        for requirement in dist.requires or []:
            if "extra ==" not in requirement:
                stack.append(requirement)
    return seen


def test_runtime_dependencies_are_permissively_licensed() -> None:
    closure = _runtime_closure("airlock-engine")
    assert "pypdfium2" in closure and "rapidocr" in closure
    problems = {}
    for name, dist in closure.items():
        if name == "airlock-engine":
            continue
        licence = _licence(dist)
        if FORBIDDEN.search(licence) or not PERMISSIVE.search(licence):
            problems[name] = licence
    assert not problems, problems


def test_known_copyleft_libraries_are_absent() -> None:
    closure = _runtime_closure("airlock-engine")
    for banned in ("pymupdf", "fitz", "pdftotext", "poppler", "ghostscript", "pytesseract"):
        assert banned not in closure
