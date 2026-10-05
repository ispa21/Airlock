from __future__ import annotations

import os
import zipfile
from pathlib import Path

import pytest

from airlock_engine.core.errors import AirlockError
from airlock_engine.security.input_files import validate_input_file


@pytest.mark.parametrize(
    ("key", "fmt"),
    [
        ("pdf", "pdf"),
        ("csv", "csv"),
        ("txt", "txt"),
        ("png", "png"),
        ("env", "env"),
        ("docx", "docx"),
        ("xlsx", "xlsx"),
        ("pptx", "pptx"),
    ],
)
def test_valid_files_are_accepted(sample_files: dict[str, Path], key: str, fmt: str) -> None:
    validated = validate_input_file(str(sample_files[key]))
    assert validated.spec.format_id == fmt
    assert validated.size_bytes == sample_files[key].stat().st_size


def test_validation_never_modifies_the_file(sample_files: dict[str, Path]) -> None:
    path = sample_files["docx"]
    before = (path.read_bytes(), path.stat().st_mtime_ns)
    validate_input_file(str(path))
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def _kind(raw: object, **kw: int) -> str:
    with pytest.raises(AirlockError) as info:
        validate_input_file(raw, **kw)
    err = info.value
    # Every error must explain itself (PRD §34) and not echo the path.
    assert err.message and err.next_step
    assert err.original_affected is False
    if isinstance(raw, str) and len(raw) > 3:
        assert raw not in err.message and raw not in err.next_step
    return err.kind


def test_missing_relative_and_bad_paths(tmp_path: Path) -> None:
    assert _kind(str(tmp_path / "nope.pdf")) == "file_not_found"
    assert _kind("relative/report.pdf") == "file_not_found"
    assert _kind("") == "file_not_found"
    assert _kind(None) == "file_not_found"
    assert _kind(str(tmp_path / "a\x00.pdf")) == "not_a_file"
    assert _kind("\\\\.\\PhysicalDrive0") == "not_a_file"


def test_directory_is_rejected(tmp_path: Path) -> None:
    folder = tmp_path / "folder.pdf"
    folder.mkdir()
    assert _kind(str(folder)) == "not_a_file"


def test_empty_and_oversized(tmp_path: Path) -> None:
    empty = tmp_path / "empty.txt"
    empty.touch()
    assert _kind(str(empty)) == "file_empty"
    big = tmp_path / "big.txt"
    big.write_bytes(b"a" * (2 * 1024 * 1024 + 1))
    assert _kind(str(big), max_bytes=2 * 1024 * 1024) == "file_too_large"


def test_unknown_extension(tmp_path: Path) -> None:
    f = tmp_path / "thing.xyz"
    f.write_text("hi")
    assert _kind(str(f)) == "unsupported_format"


def test_renamed_executable_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "invoice.pdf"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert _kind(str(f)) == "format_mismatch"
    t = tmp_path / "readme.txt"
    t.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)
    assert _kind(str(t)) == "format_mismatch"


def test_zip_renamed_to_docx_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "contract.docx"
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("readme.txt", "hello")
    assert _kind(str(f)) == "format_mismatch"


def test_xlsx_renamed_to_docx_is_rejected(tmp_path: Path) -> None:
    from conftest import make_ooxml

    f = make_ooxml(tmp_path / "contract.docx", "xl/workbook.xml")
    assert _kind(str(f)) == "format_mismatch"


def test_corrupt_zip_is_rejected(tmp_path: Path) -> None:
    f = tmp_path / "deck.pptx"
    f.write_bytes(b"PK\x03\x04" + os.urandom(64))
    assert _kind(str(f)) == "format_mismatch"


def test_password_protected_office_file(tmp_path: Path) -> None:
    f = tmp_path / "salaries.xlsx"
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    f.write_bytes(header + "EncryptionInfo".encode("utf-16-le") + b"\x00" * 64)
    assert _kind(str(f)) == "encrypted_document"


def test_legacy_office_named_as_ooxml(tmp_path: Path) -> None:
    f = tmp_path / "old.docx"
    f.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 600)
    assert _kind(str(f)) == "format_mismatch"


def test_unicode_file_names(tmp_path: Path) -> None:
    f = tmp_path / "रिपोर्ट — été.txt"
    f.write_text("synthetic", encoding="utf-8")
    assert validate_input_file(str(f)).spec.format_id == "txt"


def test_utf16_text_is_accepted(tmp_path: Path) -> None:
    f = tmp_path / "export.csv"
    f.write_text("a,b\n1,2\n", encoding="utf-16")
    assert validate_input_file(str(f)).spec.format_id == "csv"


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs privileges on Windows")
def test_symlink_is_resolved(tmp_path: Path, sample_files: dict[str, Path]) -> None:
    link = tmp_path / "link.pdf"
    link.symlink_to(sample_files["pdf"])
    assert validate_input_file(str(link)).path == sample_files["pdf"].resolve()
