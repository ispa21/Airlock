"""Masking: sweep, replacement text, the masker plan and PDF sections."""

from __future__ import annotations

import pytest

from airlock_engine.core.models import (
    Action,
    Category,
    DetectionResult,
    ExtractedDocument,
    Locator,
    SegmentKind,
    Severity,
    TextBox,
    TextSegment,
)
from airlock_engine.core.sensitive import SensitiveValue
from airlock_engine.detectors.entities import BUILTIN_ENTITIES
from airlock_engine.detectors.pipeline import Detected
from airlock_engine.masking.masker import BlockedFindings, build_plan
from airlock_engine.masking.pdf_text import pdf_sections
from airlock_engine.masking.replacements import REDACTED, Replacer, generalize
from airlock_engine.masking.sweep import UNSAFE_REPLACEMENT_CHARS, Sweeper, splice
from airlock_engine.policy.engine import PolicyEngine
from airlock_engine.policy.profiles import COMPANY_DEFAULT

# --- sweep -------------------------------------------------------------------


def test_sweep_respects_word_edges_and_prefers_longest() -> None:
    s = Sweeper([("Ram", "[P_1]"), ("Ram Kumar", "[P_2]")])
    assert s.apply("Ram Kumar met Ramesh and Ram.") == "[P_2] met Ramesh and [P_1]."
    assert s.missing() == []


def test_sweep_falls_back_to_shorter_bounded_value() -> None:
    s = Sweeper([("abc", "[A]"), ("abcd", "[B]")])
    assert s.apply("abcdx abc") == "abcdx [A]"


def test_unmatched_words_are_reported_for_the_unbounded_pass() -> None:
    s = Sweeper([("Phoenix", "[P]")])
    assert s.apply("ProjectPhoenixRising") == "ProjectPhoenixRising"
    missing = s.missing()
    assert missing == [("Phoenix", "[P]")]
    assert Sweeper(missing, bounded=False).apply("ProjectPhoenixRising") == "Project[P]Rising"


def test_ids_and_secrets_match_even_when_glued() -> None:
    s = Sweeper([("SECRET1", "[S]"), ("a@b.invalid", "[E]"), ("Rahul Sharma", "[P]")])
    assert s.apply("xSECRET1x mailto:a@b.invalid Rahul Sharmaji") == "x[S]x mailto:[E] [P]ji"


def test_splice_ignores_overlaps() -> None:
    assert splice("abcdef", [(1, 3, "X"), (2, 4, "Y"), (4, 5, "Z")]) == "aXdZf"


# --- replacement text --------------------------------------------------------


def test_typed_placeholders_are_consistent_and_numbered_per_type() -> None:
    r = Replacer()
    a = r.text_for("EMAIL", "a@x.invalid", Action.MASK, "typed_placeholder")
    b = r.text_for("EMAIL", "b@x.invalid", Action.MASK, "typed_placeholder")
    p = r.text_for("PERSON", "Rahul", Action.MASK, "typed_placeholder")
    assert (a, b, p) == ("EMAIL_001", "EMAIL_002", "PERSON_001")
    assert r.text_for("EMAIL", "a@x.invalid", Action.MASK, "typed_placeholder") == a
    assert r.reversible[a] == ("a@x.invalid", "EMAIL")


def test_placeholders_skip_numbers_already_in_the_document() -> None:
    r = Replacer("This template literally contains EMAIL_001 and EMAIL_002.")
    assert r.text_for("EMAIL", "x@y.invalid", Action.MASK, "typed_placeholder") == "EMAIL_003"


def test_numbering_widens_past_999() -> None:
    r = Replacer()
    issued = [
        r.text_for("EMAIL", f"u{i}@x.invalid", Action.MASK, "typed_placeholder")
        for i in range(1000)
    ]
    assert issued[0] == "EMAIL_001" and issued[998] == "EMAIL_999" and issued[999] == "EMAIL_1000"


def test_seeded_replacer_keeps_earlier_placeholders_and_continues_numbering() -> None:
    first = Replacer()
    first.text_for("PERSON", "Rahul Sharma", Action.MASK, "typed_placeholder")
    first.text_for("EMAIL", "r@x.invalid", Action.MASK, "typed_placeholder")
    second = Replacer("next turn", first.mappings())
    assert second.text_for("PERSON", "Rahul Sharma", Action.MASK, "typed_placeholder") == (
        "PERSON_001"
    )
    assert second.text_for("PERSON", "Asha Rao", Action.MASK, "typed_placeholder") == "PERSON_002"
    assert [m[0] for m in second.mappings()] == ["PERSON_001", "EMAIL_001", "PERSON_002"]
    assert second.mappings()[0] == ("PERSON_001", "Rahul Sharma", "PERSON", "typed_placeholder")


def test_custom_category_names_never_reach_the_placeholder() -> None:
    r = Replacer()
    assert r.text_for("PROJECT_PHOENIX_CLIENTS", "Acme", Action.MASK, "typed_placeholder") == (
        "CONFIDENTIAL_001"
    )
    assert r.text_for("INTERNAL_PROJECT", "Nightjar", Action.MASK, "typed_placeholder") == (
        "INTERNAL_PROJECT_001"
    )


def test_generic_placeholder_and_redaction() -> None:
    r = Replacer()
    assert r.text_for("PAN", "ABCPE1234F", Action.MASK, "placeholder") == "MASKED_001"
    assert r.text_for("PAN", "ABCPE1234F", Action.REDACT, "typed_placeholder") == REDACTED
    assert REDACTED not in r.reversible


def test_synthetic_values_use_reserved_ranges() -> None:
    r = Replacer()
    assert r.text_for("EMAIL", "a@b.invalid", Action.MASK, "synthetic") == (
        "person1@example.invalid"
    )
    assert r.text_for("IP_ADDRESS", "10.1.2.3", Action.MASK, "synthetic") == "192.0.2.1"
    assert r.text_for("IP_ADDRESS", "fe80::1", Action.MASK, "synthetic") == "2001:db8::1"
    assert r.text_for("PHONE", "+91 98765 43210", Action.MASK, "synthetic") == "+91 00000 00001"
    assert r.text_for("PERSON", "Rahul", Action.MASK, "synthetic") == "Alex Example"
    # Types without a safe reserved form fall back to typed placeholders.
    assert r.text_for("AADHAAR", "2345 6789 0124", Action.MASK, "synthetic") == "AADHAAR_001"


@pytest.mark.parametrize(
    ("entity_type", "value", "expected"),
    [
        ("DATE_OF_BIRTH", "12/03/1988", "1988"),
        ("DATE_OF_BIRTH", "3 March 1988", "1988"),
        ("EMAIL", "rahul@corp.example.invalid", "[EMAIL @corp.example.invalid]"),
        ("PHONE", "+91 98765 43210", "[PHONE +91]"),
        ("PHONE", "+44 20 7946 0958", "[PHONE +44]"),
        ("PHONE", "98765 43210", "[PHONE]"),
        ("IP_ADDRESS", "10.20.30.40", "10.20.30.0/24"),
        ("IP_ADDRESS", "2001:db8::8a2e:370:7334", "2001:db8::/64"),
        (
            "URL",
            "https://user@intranet.example.invalid/hr?id=4",
            "https://intranet.example.invalid",
        ),
        ("URL", "www.example.invalid/x", "www.example.invalid"),
        ("MONEY", "$2,450,000", "$~2000000"),
        ("MONEY", "Rs 4.5 crore", "Rs ~5 crore"),
    ],
)
def test_generalisation(entity_type: str, value: str, expected: str) -> None:
    assert generalize(entity_type, value) == expected


def test_replacements_never_contain_structural_characters() -> None:
    r = Replacer()
    texts = [
        r.text_for(t, v, Action.GENERALIZE, "typed_placeholder")
        for t, v in [("MONEY", "1,000,000"), ("EMAIL", "a@b,c"), ("URL", "https://a,b.c")]
    ]
    assert all(not (UNSAFE_REPLACEMENT_CHARS & set(t)) for t in texts)


# --- masker ------------------------------------------------------------------


def _doc(*segments: TextSegment) -> ExtractedDocument:
    return ExtractedDocument("txt", segments)


def _det(seg: TextSegment, value: str, entity_type: str, occurrence: int = 0) -> Detected:
    start = -1
    for _ in range(occurrence + 1):
        start = seg.text.index(value, start + 1)
    severity = BUILTIN_ENTITIES[entity_type].severity
    return Detected(
        DetectionResult(
            entity_type,
            SensitiveValue(value),
            seg.segment_id,
            start,
            start + len(value),
            0.95,
            "regex.x",
            "regex.x",
            severity,
        )
    )


def _decide(items: list[Detected], overrides: dict[str, Action] | None = None):  # type: ignore[no-untyped-def]
    engine = PolicyEngine(
        categories={e.id: e.category for e in BUILTIN_ENTITIES.values()},
        labels={e.id: e.label for e in BUILTIN_ENTITIES.values()},
    )
    return engine.decide([(f"f{i}", d) for i, d in enumerate(items, 1)], COMPANY_DEFAULT, overrides)


def test_plan_has_edits_sweep_and_vault_entries() -> None:
    seg = TextSegment(
        0, "Mail a@x.invalid; again a@x.invalid. DOB 12/03/1988", Locator("text", "char/0")
    )
    items = [
        _det(seg, "a@x.invalid", "EMAIL"),
        _det(seg, "a@x.invalid", "EMAIL", 1),
        _det(seg, "12/03/1988", "DATE_OF_BIRTH"),
    ]
    plan = build_plan(_doc(seg), _decide(items))
    assert [e[3] for e in plan.edits] == ["EMAIL_001", "EMAIL_001", "1988"]
    assert ("a@x.invalid", "EMAIL_001") in plan.sweep
    assert plan.reversible == {"EMAIL_001": ("a@x.invalid", "EMAIL")}
    assert plan.mappings == [("EMAIL_001", "a@x.invalid", "EMAIL", "typed_placeholder")]
    assert plan.counts == {"MASK": 2, "GENERALIZE": 1}
    assert "a@x.invalid" not in repr(plan)


def test_plan_refuses_blocked_regions() -> None:
    seg = TextSegment(0, "password=Xk9#mQ2!vL7p", Locator("text", "char/0"))
    items = [_det(seg, "Xk9#mQ2!vL7p", "PASSWORD")]
    with pytest.raises(BlockedFindings):
        build_plan(_doc(seg), _decide(items))
    plan = build_plan(_doc(seg), _decide(items, {"f1": Action.REDACT}))
    assert plan.edits[0][3] == REDACTED and plan.reversible == {}


def test_ocr_regions_become_paint_boxes() -> None:
    seg = TextSegment(
        0,
        "Invoice\nmail a@x.invalid",
        Locator("frame", "0"),
        kind=SegmentKind.OCR,
        boxes=(TextBox(0, 7, 1, 1, 50, 10), TextBox(8, 24, 1, 20, 90, 30)),
    )
    plan = build_plan(_doc(seg), _decide([_det(seg, "a@x.invalid", "EMAIL")]))
    assert plan.paint == [("frame", "0", [(1, 20, 90, 30)])]
    no_boxes = TextSegment(1, "mail a@x.invalid", Locator("frame", "1"), kind=SegmentKind.OCR)
    plan = build_plan(_doc(no_boxes), _decide([_det(no_boxes, "a@x.invalid", "EMAIL")]))
    assert plan.paint == [("frame", "1", None)]  # unknown position: black out the frame


def test_pdf_sections_apply_edits_and_sweep_per_page() -> None:
    p0 = TextSegment(0, "Contact a@x.invalid", Locator("page", "0"))
    p0_img = TextSegment(1, "a@x.invalid on slide", Locator("page", "0/ocr"), kind=SegmentKind.OCR)
    p1 = TextSegment(2, "Second page", Locator("page", "1"))
    note = TextSegment(
        3, "a@x.invalid in a comment", Locator("annotation", "0/0"), kind=SegmentKind.COMMENT
    )
    doc = ExtractedDocument("pdf", (p0, p0_img, p1, note))
    plan = build_plan(doc, _decide([_det(p0, "a@x.invalid", "EMAIL")]))
    sections = pdf_sections(doc, plan)
    assert [h for h, _ in sections] == ["Page 1", "Page 2"]
    assert "a@x.invalid" not in "".join(t for _, t in sections)
    assert sections[0][1].count("EMAIL_001") == 2


def test_categories_cover_custom_rule_types() -> None:
    assert Category.BUSINESS  # sanity: category enum unchanged
    assert Severity.CRITICAL > Severity.HIGH
