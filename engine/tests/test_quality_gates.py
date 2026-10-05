"""Per-entity precision/recall gates on the labelled synthetic corpus.

Thresholds are those in docs/TESTING.md. A regression below any of them
fails CI. Run with ``-s`` to print the metrics table.
"""

from __future__ import annotations

from collections import Counter

import pytest

from airlock_engine.core.models import ExtractedDocument, Locator, TextSegment
from airlock_engine.detectors.entities import BUILTIN_ENTITIES, QualityClass
from airlock_engine.detectors.pipeline import DetectionEngine
from synthetic.corpus import Sample, negatives, positives

GATES: dict[QualityClass, tuple[float, float]] = {  # (recall, precision)
    QualityClass.SECRET: (0.99, 0.90),
    QualityClass.CHECKSUMMED_ID: (0.99, 0.98),
    QualityClass.CONTACT: (0.98, 0.95),
    QualityClass.CONTEXTUAL_ID: (0.95, 0.95),
}


def _document(samples: list[Sample]) -> ExtractedDocument:
    return ExtractedDocument(
        format="txt",
        segments=tuple(
            TextSegment(i, s.text, Locator("text", str(i)), context=s.context)
            for i, s in enumerate(samples)
        ),
    )


def evaluate(samples: list[Sample]) -> tuple[Counter[str], Counter[str], Counter[str]]:
    outcome = DetectionEngine().run(_document(samples))
    found: dict[int, set[tuple[int, int, str]]] = {}
    for item in outcome.detected:
        d = item.detection
        found.setdefault(d.segment_id, set()).add((d.start, d.end, d.entity_type))
    tp: Counter[str] = Counter()
    fp: Counter[str] = Counter()
    fn: Counter[str] = Counter()
    for i, sample in enumerate(samples):
        got = found.get(i, set())
        expected = set(sample.labels)
        for label in expected:
            (tp if label in got else fn)[label[2]] += 1
        for det in got - expected:
            fp[det[2]] += 1
    return tp, fp, fn


@pytest.fixture(scope="module")
def metrics() -> dict[str, tuple[int, int, int]]:
    samples = positives() + negatives()
    tp, fp, fn = evaluate(samples)
    types = set(tp) | set(fp) | set(fn)
    table = {t: (tp[t], fp[t], fn[t]) for t in sorted(types)}
    print("\nentity              TP    FP    FN  recall  precision")
    for t, (a, b, c) in table.items():
        recall = a / (a + c) if a + c else 1.0
        precision = a / (a + b) if a + b else 1.0
        print(f"{t:18} {a:4d} {b:5d} {c:5d}   {recall:.3f}    {precision:.3f}")
    return table


def test_corpus_is_large_enough() -> None:
    samples = positives()
    counts = Counter(t for s in samples for _, _, t in s.labels)
    gated = {e.id for e in BUILTIN_ENTITIES.values() if e.quality in GATES}
    assert gated <= set(counts), gated - set(counts)
    assert min(counts[t] for t in gated) >= 24
    assert len(negatives()) >= 400


@pytest.mark.parametrize(
    "entity_type",
    sorted(e.id for e in BUILTIN_ENTITIES.values() if e.quality in GATES),
)
def test_gate(entity_type: str, metrics: dict[str, tuple[int, int, int]]) -> None:
    tp, fp, fn = metrics.get(entity_type, (0, 0, 0))
    min_recall, min_precision = GATES[BUILTIN_ENTITIES[entity_type].quality]
    recall = tp / (tp + fn) if tp + fn else 0.0
    precision = tp / (tp + fp) if tp + fp else 1.0
    assert recall >= min_recall, f"{entity_type} recall {recall:.3f} < {min_recall}"
    assert precision >= min_precision, f"{entity_type} precision {precision:.3f} < {min_precision}"


def test_false_positive_suite_is_clean() -> None:
    """Invoice numbers, timestamps, versions, hashes, UUIDs and arithmetic."""
    samples = negatives()
    outcome = DetectionEngine().run(_document(samples))
    noisy = Counter(item.detection.entity_type for item in outcome.detected)
    # A handful of contact-class hits on adversarial lines is tolerated by the
    # precision gate above; checksummed ids and secrets must never fire here.
    for entity_type, count in noisy.items():
        quality = BUILTIN_ENTITIES[entity_type].quality
        assert quality not in (QualityClass.SECRET, QualityClass.CHECKSUMMED_ID), (
            entity_type,
            count,
        )


def test_heldout_documents_meet_the_same_gates() -> None:
    """Realistic mixed documents (e-mails, .env files, logs, JSON) that were
    written separately from the tuning templates."""
    from synthetic.heldout import heldout

    tp, fp, fn = evaluate(heldout())
    for entity_type in set(tp) | set(fp) | set(fn):
        min_recall, min_precision = GATES.get(BUILTIN_ENTITIES[entity_type].quality, (0.0, 0.0))
        a, b, c = tp[entity_type], fp[entity_type], fn[entity_type]
        recall = a / (a + c) if a + c else 1.0
        precision = a / (a + b) if a + b else 1.0
        assert recall >= min_recall and precision >= min_precision, (entity_type, a, b, c)
