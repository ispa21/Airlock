"""Local restoration of AI responses (Phase 12, masking/restore.py)."""

from __future__ import annotations

import pytest

from airlock_engine.masking.restore import Restorer

MAPPING = {
    "PERSON_001": "Rahul Sharma",
    "PERSON_0010": "Asha Rao",
    "PROJECT_001": "Project Phoenix",
    "EMAIL_001": "rahul.sharma@example.invalid",
    "[EMAIL_1]": "old.copy@example.invalid",  # a copy made before Phase 12
    "Alex Example": "Vikram Iyer",  # a synthetic stand-in
}


def restore(text: str) -> str:
    return Restorer(MAPPING).restore(text).text


@pytest.mark.parametrize(
    ("response", "expected"),
    [
        ("PERSON_001 is managing PROJECT_001", "Rahul Sharma is managing Project Phoenix"),
        ("PERSON_001's plan.", "Rahul Sharma's plan."),
        ("Thanks, PERSON_001.", "Thanks, Rahul Sharma."),
        ("(PERSON_001)", "(Rahul Sharma)"),
        ("**PERSON_001**", "**Rahul Sharma**"),
        ("PERSON\\_001 said", "Rahul Sharma said"),  # Markdown-escaped underscore
        ("PERSON_0010 and PERSON_001", "Asha Rao and Rahul Sharma"),
        (
            "Mail [EMAIL_1] or EMAIL_001",
            "Mail old.copy@example.invalid or rahul.sharma@example.invalid",
        ),
        ("Ask Alex Example.", "Ask Vikram Iyer."),
    ],
)
def test_known_placeholders_are_restored(response: str, expected: str) -> None:
    assert restore(response) == expected


@pytest.mark.parametrize(
    "response",
    [
        "PERSON_0011 is someone else",
        "XPERSON_001 is not a placeholder",
        "PERSON_001A is not either",
        "person_001 is lower case",
        "PERSON_001_B joins two tokens",
        "Alex Examples is a different name",
    ],
)
def test_partial_matches_are_never_restored(response: str) -> None:
    assert restore(response) == response


def test_unknown_placeholders_stay_and_are_reported() -> None:
    result = Restorer(MAPPING).restore(
        "PERSON_001 met PERSON_999 and [PERSON_77]; ISO_9001 is a standard. PERSON_999 again."
    )
    assert result.text == (
        "Rahul Sharma met PERSON_999 and [PERSON_77]; ISO_9001 is a standard. PERSON_999 again."
    )
    assert result.unknown == ["PERSON_999", "[PERSON_77]"]
    assert result.restored == 1


def test_repeats_are_consistent_and_counted() -> None:
    result = Restorer(MAPPING).restore("PERSON_001, PERSON_001's and PERSON_001.")
    assert result.text == "Rahul Sharma, Rahul Sharma's and Rahul Sharma."
    assert result.restored == 3 and result.found == {"PERSON_001": 3}


def test_special_characters_in_originals_are_inserted_literally() -> None:
    mapping = {"CONFIDENTIAL_001": r"Acme (India) $1 \g<0> [x]+", "EMAIL_001": "a\\b@x.invalid"}
    result = Restorer(mapping).restore("CONFIDENTIAL_001 / EMAIL_001")
    assert result.text == r"Acme (India) $1 \g<0> [x]+ / a\b@x.invalid"


def test_restored_values_are_not_restored_again() -> None:
    # An original that looks like another placeholder must stay as it is.
    result = Restorer({"PERSON_001": "PERSON_002", "PERSON_002": "Asha"}).restore("PERSON_001")
    assert result.text == "PERSON_002" and result.restored == 1


def test_analyze_counts_without_changing_anything() -> None:
    text = "PERSON_001 and EMAIL_001, PERSON_001 again, PERSON_404."
    result = Restorer(MAPPING).analyze(text)
    assert result.text == text and result.restored == 0
    assert result.found == {"PERSON_001": 2, "EMAIL_001": 1}
    assert result.unknown == ["PERSON_404"]
    assert "Rahul" not in repr(result)


def test_empty_mapping_restores_nothing() -> None:
    result = Restorer({}).restore("PERSON_001")
    assert result.text == "PERSON_001" and result.unknown == ["PERSON_001"]
