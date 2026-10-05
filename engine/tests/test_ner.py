"""NER: the real local spaCy model, label mapping and span clean-up."""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap

import pytest

from airlock_engine.core.interfaces import NerEntity, NerProvider
from airlock_engine.core.models import ExtractedDocument, Locator, SegmentKind, TextSegment
from airlock_engine.detectors.ner import NerDetector, SpacyNerProvider
from airlock_engine.detectors.pipeline import DetectionEngine


@pytest.fixture(scope="module")
def spacy_provider() -> SpacyNerProvider:
    provider = SpacyNerProvider()
    provider.load(provider.default_model_dir())
    return provider


def seg(text: str, i: int = 0, kind: SegmentKind = SegmentKind.BODY) -> TextSegment:
    return TextSegment(i, text, Locator("t", str(i)), kind=kind)


def test_real_model_finds_people_orgs_and_places(spacy_provider: SpacyNerProvider) -> None:
    text = (
        "Priya Patel from Infosys met John Smith in Mumbai to review "
        "the $2 million budget with Tata Consultancy Services."
    )
    got = {
        (text[d.start : d.end], d.entity_type)
        for d in NerDetector(spacy_provider).detect(seg(text))
    }
    assert ("Priya Patel", "PERSON") in got
    assert ("John Smith", "PERSON") in got
    assert ("Mumbai", "LOCATION") in got
    assert ("Tata Consultancy Services", "ORGANIZATION") in got
    assert all(0 < d.confidence < 0.9 for d in NerDetector(spacy_provider).detect(seg(text)))


def test_long_segments_are_chunked(spacy_provider: SpacyNerProvider) -> None:
    filler = "The quarterly numbers were reviewed again. " * 3000  # > one chunk
    text = filler + "Afterwards Rahul Sharma signed the report."
    got = {
        (text[d.start : d.end], d.entity_type)
        for d in NerDetector(spacy_provider).detect(seg(text))
    }
    assert ("Rahul Sharma", "PERSON") in got


def test_model_loads_offline_with_network_guard() -> None:
    """Fresh interpreter: guard first, then load and run the model."""
    code = textwrap.dedent(
        """
        import json
        from airlock_engine.security import network_guard
        network_guard.install()
        from airlock_engine.detectors.ner import SpacyNerProvider
        p = SpacyNerProvider()
        p.load(p.default_model_dir())
        ents = p.entities("Meera Nair joined Wipro in Bengaluru.")
        print(json.dumps({"labels": sorted({e.label for e in ents}),
                          "blocked": network_guard.blocked_attempts()}))
        """
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, timeout=300, check=True
    )
    result = json.loads(out.stdout.strip().splitlines()[-1])
    assert "PERSON" in result["labels"]
    assert result["blocked"] == 0


class FakeNer(NerProvider):
    name = "fake"

    def __init__(self, spans: list[tuple[str, str]]) -> None:
        self.spans = spans

    def load(self, model_dir):  # type: ignore[no-untyped-def]
        pass

    def entities(self, text: str) -> list[NerEntity]:
        out = []
        for value, label in self.spans:
            i = text.find(value)
            if i >= 0:
                out.append(NerEntity(label, i, i + len(value), 1.0))
        return out


def test_span_cleanup_and_filters() -> None:
    text = "Report by (Anil Kumar's) team, 2024 and x"
    ner = FakeNer(
        [("(Anil Kumar's)", "PERSON"), ("2024", "PERSON"), ("x", "ORG"), ("team", "CARDINAL")]
    )
    got = [(text[d.start : d.end], d.entity_type) for d in NerDetector(ner).detect(seg(text))]
    assert got == [("Anil Kumar", "PERSON")]


def test_link_segments_are_skipped() -> None:
    ner = FakeNer([("Anil Kumar", "PERSON")])
    assert list(NerDetector(ner).detect(seg("Anil Kumar", kind=SegmentKind.LINK))) == []


def test_deterministic_match_suppresses_overlapping_ner() -> None:
    text = "Mail anil.kumar@example.invalid today"
    ner = FakeNer([("anil.kumar@example.invalid", "ORG")])
    doc = ExtractedDocument("txt", (seg(text),))
    outcome = DetectionEngine(ner=ner).run(doc)
    assert [i.detection.entity_type for i in outcome.detected] == ["EMAIL"]
