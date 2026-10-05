"""Text, configuration, code, CSV and TSV: same encoding, same line endings."""

from __future__ import annotations

from airlock_engine.documents.sanitize_plan import SanitizePlan
from airlock_engine.documents.text.adapter import decode_text
from airlock_engine.masking.sweep import Sweeper, splice


def sanitize_text(data: bytes, plan: SanitizePlan, sweeper: Sweeper) -> bytes:
    encoding = plan.adapter_state.get("encoding")
    if encoding:
        text = data.decode(encoding)
    else:
        text, encoding = decode_text(data)

    # Exact edits (plain text keeps one segment per chunk: "char/<offset>").
    edits: list[tuple[int, int, str]] = []
    for part, path, start, end, replacement in plan.edits:
        if part != "text" or not path.startswith("char/"):
            continue  # cells and other locators are covered by the sweep
        base = int(path[5:])
        lo, hi = base + start, base + end
        if 0 <= lo < hi <= len(text):
            sweeper.hits[text[lo:hi]] += 1
            edits.append((lo, hi, replacement))
    if edits:
        text = splice(text, edits)

    if plan.adapter_state.get("delimiter") is not None or "table" in {e[0] for e in plan.edits}:
        # CSV quoting doubles quotes inside quoted cells; sweep that form too.
        extra = [(v.replace('"', '""'), t) for v, t in sweeper.replacements.items() if '"' in v]
        if extra:
            text = Sweeper(extra).apply(text)
    text = sweeper.apply(text)
    return text.encode(encoding)
