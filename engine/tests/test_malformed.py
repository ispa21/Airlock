"""Mutation fuzzing: damaged files yield a result or an AirlockError, quickly.

Runs in-process for speed. In production every extraction also runs in the
isolated worker, which turns any other exception into an actionable error.
"""

from __future__ import annotations

import random
import time

import pytest

import builders
from airlock_engine.core.errors import AirlockError
from airlock_engine.extraction.pipeline import extract_bytes

SEEDS = range(25)


@pytest.fixture(scope="module")
def samples() -> dict[str, bytes]:
    return {
        "docx": builders.build_docx(),
        "xlsx": builders.build_xlsx(),
        "pptx": builders.build_pptx(),
        "pdf": builders.build_pdf(),
        "png": builders.png_bytes(builders.text_image("x", size=(64, 64))),
        "csv": b"a,b\n" + b"1,2\n" * 50,
    }


def _mutations(data: bytes, seed: int) -> list[bytes]:
    rng = random.Random(seed)
    out = [data[: rng.randrange(1, len(data))]]  # truncation
    flipped = bytearray(data)
    for _ in range(rng.randrange(1, 40)):
        flipped[rng.randrange(len(flipped))] = rng.randrange(256)
    out.append(bytes(flipped))
    start = rng.randrange(len(data))
    out.append(data[:start] + bytes(rng.randrange(256) for _ in range(64)) + data[start + 64 :])
    return out


@pytest.mark.parametrize("fmt", ["docx", "xlsx", "pptx", "pdf", "png", "csv"])
def test_mutated_files_never_hang_or_escape(samples: dict[str, bytes], fmt: str) -> None:
    unexpected: list[str] = []
    for seed in SEEDS:
        for mutated in _mutations(samples[fmt], seed):
            started = time.monotonic()
            try:
                extract_bytes(mutated, fmt, ocr_factory=None)
            except AirlockError:
                pass
            except Exception as exc:
                unexpected.append(type(exc).__name__)
            assert time.monotonic() - started < 10, "extraction must not hang"
    # Damage must be reported as an actionable AirlockError by the adapter itself;
    # the worker's catch-all is a safety net, not the error path.
    assert unexpected == []
