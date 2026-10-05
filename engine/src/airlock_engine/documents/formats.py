"""Format registry and content sniffing.

A file is only accepted when its *contents* match its extension. Treating the
extension as untrusted closes a class of attacks where a hostile file is
renamed to reach a more permissive parser, and it stops encrypted Office files
from being silently "scanned" as empty documents.
"""

from __future__ import annotations

import zipfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import BinaryIO, Final

from airlock_engine.core import errors


class Family(StrEnum):
    DOCUMENT = "document"
    SPREADSHEET = "spreadsheet"
    PRESENTATION = "presentation"
    IMAGE = "image"
    TEXT = "text"
    CONFIG = "config"
    CODE = "code"


class Support(StrEnum):
    #: Extraction and sanitization are implemented in this build.
    AVAILABLE = "available"
    #: Recognised and on the V1 roadmap; adapter not yet implemented.
    PLANNED = "planned"
    #: Recognised but not planned for V1 (legacy binary or future formats).
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True, slots=True)
class FormatSpec:
    format_id: str
    label: str
    family: Family
    extensions: tuple[str, ...]
    support: Support


_YES: Final = Support.AVAILABLE
_NO: Final = Support.UNSUPPORTED

_SPECS: Final[tuple[FormatSpec, ...]] = (
    FormatSpec("pdf", "PDF document", Family.DOCUMENT, ("pdf",), _YES),
    FormatSpec("docx", "Word document", Family.DOCUMENT, ("docx",), _YES),
    FormatSpec("docm", "Word document with macros", Family.DOCUMENT, ("docm",), _YES),
    FormatSpec("xlsx", "Excel workbook", Family.SPREADSHEET, ("xlsx",), _YES),
    FormatSpec("xlsm", "Excel workbook with macros", Family.SPREADSHEET, ("xlsm",), _YES),
    FormatSpec("pptx", "PowerPoint presentation", Family.PRESENTATION, ("pptx",), _YES),
    FormatSpec("pptm", "PowerPoint with macros", Family.PRESENTATION, ("pptm",), _YES),
    FormatSpec("csv", "CSV spreadsheet", Family.SPREADSHEET, ("csv",), _YES),
    FormatSpec("tsv", "TSV spreadsheet", Family.SPREADSHEET, ("tsv",), _YES),
    FormatSpec("txt", "Text file", Family.TEXT, ("txt", "md", "log"), _YES),
    FormatSpec("png", "PNG image", Family.IMAGE, ("png",), _YES),
    FormatSpec("jpeg", "JPEG image", Family.IMAGE, ("jpg", "jpeg"), _YES),
    FormatSpec("webp", "WebP image", Family.IMAGE, ("webp",), _YES),
    FormatSpec("tiff", "TIFF image", Family.IMAGE, ("tif", "tiff"), _YES),
    FormatSpec("json", "JSON file", Family.CONFIG, ("json",), _YES),
    FormatSpec("yaml", "YAML file", Family.CONFIG, ("yaml", "yml"), _YES),
    FormatSpec("xml", "XML file", Family.CONFIG, ("xml",), _YES),
    FormatSpec("toml", "TOML file", Family.CONFIG, ("toml",), _YES),
    FormatSpec("ini", "INI file", Family.CONFIG, ("ini", "cfg", "conf"), _YES),
    FormatSpec("env", "Environment file", Family.CONFIG, ("env",), _YES),
    FormatSpec(
        "code",
        "Source code",
        Family.CODE,
        (
            "py", "js", "ts", "jsx", "tsx", "java", "c", "h", "cpp", "hpp", "cs", "go",
            "rs", "php", "rb", "swift", "kt", "sql", "sh", "ps1",
        ),
        _YES,
    ),
    # Recognised so we can give a precise message, not yet handled.
    FormatSpec("doc", "Legacy Word document", Family.DOCUMENT, ("doc",), _NO),
    FormatSpec("xls", "Legacy Excel workbook", Family.SPREADSHEET, ("xls",), _NO),
    FormatSpec("ppt", "Legacy PowerPoint", Family.PRESENTATION, ("ppt",), _NO),
    FormatSpec("rtf", "Rich Text document", Family.DOCUMENT, ("rtf",), _NO),
    FormatSpec("odt", "OpenDocument text", Family.DOCUMENT, ("odt",), _NO),
    FormatSpec("ods", "OpenDocument spreadsheet", Family.SPREADSHEET, ("ods",), _NO),
    FormatSpec("odp", "OpenDocument presentation", Family.PRESENTATION, ("odp",), _NO),
    FormatSpec("eml", "E-mail message", Family.DOCUMENT, ("eml",), _NO),
    FormatSpec("msg", "Outlook message", Family.DOCUMENT, ("msg",), _NO),
)  # fmt: skip

_BY_EXTENSION: Final[dict[str, FormatSpec]] = {
    ext: spec for spec in _SPECS for ext in spec.extensions
}

_HEAD_BYTES: Final = 64 * 1024
_MAX_ZIP_ENTRIES: Final = 20_000
_OLE2_MAGIC: Final = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_ZIP_MAGIC: Final = b"PK\x03\x04"
# "EncryptionInfo" as a UTF-16LE OLE2 directory entry name.
_OLE_ENCRYPTION_INFO: Final = "EncryptionInfo".encode("utf-16-le")
_OOXML_MAIN_PART: Final = {
    "docx": "word/document.xml",
    "xlsx": "xl/workbook.xml",
    "pptx": "ppt/presentation.xml",
}
_OOXML_ALIASES: Final = {"docm": "docx", "xlsm": "xlsx", "pptm": "pptx"}
_ODF_MIMETYPES: Final = {
    "odt": b"application/vnd.oasis.opendocument.text",
    "ods": b"application/vnd.oasis.opendocument.spreadsheet",
    "odp": b"application/vnd.oasis.opendocument.presentation",
}
_TEXTUAL: Final = frozenset({Family.TEXT, Family.CONFIG, Family.CODE})


def all_specs() -> tuple[FormatSpec, ...]:
    return _SPECS


def spec_for_extension(extension: str) -> FormatSpec | None:
    return _BY_EXTENSION.get(extension.lower().lstrip("."))


def extension_of(path: Path) -> str:
    return extension_of_name(path.name)


def extension_of_name(name: str) -> str:
    name = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    # ".env", ".env.local", "production.env" are all environment files.
    if name == ".env" or name.startswith(".env."):
        return "env"
    stem, dot, ext = name.rpartition(".")
    return ext if dot and stem else ""


def sniff(path: Path, spec: FormatSpec) -> None:
    """Raise an :class:`AirlockError` unless ``path``'s bytes match ``spec``."""
    with path.open("rb") as handle:
        sniff_stream(handle, spec, extension_of(path))


def sniff_stream(handle: BinaryIO, spec: FormatSpec, ext: str) -> None:
    """Like :func:`sniff` for an open, seekable binary stream (e.g. an embedded file)."""
    handle.seek(0)
    head = handle.read(_HEAD_BYTES)
    if spec.format_id in _OOXML_MAIN_PART or spec.format_id in _OOXML_ALIASES:
        _sniff_ooxml(handle, head, spec, ext)
    elif spec.format_id in _ODF_MIMETYPES:
        _sniff_odf(handle, head, spec, ext)
    elif spec.format_id in ("doc", "xls", "ppt", "msg"):
        _require(head.startswith(_OLE2_MAGIC), ext, _describe(head))
    else:
        _sniff_simple(head, spec, ext)


def detect_format(head: bytes, names: set[str] | None = None) -> str | None:
    """Best-effort format id from content alone (used for embedded files)."""
    if b"%PDF-" in head[:1024]:
        return "pdf"
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if head.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "webp"
    if head[:4] in (b"II*\x00", b"MM\x00*"):
        return "tiff"
    if names is not None and "[Content_Types].xml" in names:
        for format_id, main in _OOXML_MAIN_PART.items():
            if main in names:
                return format_id
    return None


def _sniff_simple(head: bytes, spec: FormatSpec, ext: str) -> None:
    fid = spec.format_id
    if fid == "pdf":
        _require(b"%PDF-" in head[:1024], ext, _describe(head))
    elif fid == "png":
        _require(head.startswith(b"\x89PNG\r\n\x1a\n"), ext, _describe(head))
    elif fid == "jpeg":
        _require(head.startswith(b"\xff\xd8\xff"), ext, _describe(head))
    elif fid == "webp":
        _require(head[:4] == b"RIFF" and head[8:12] == b"WEBP", ext, _describe(head))
    elif fid == "tiff":
        _require(head[:4] in (b"II*\x00", b"MM\x00*"), ext, _describe(head))
    elif fid == "rtf":
        _require(head.lstrip().startswith(b"{\\rtf"), ext, _describe(head))
    elif fid == "eml" or spec.family in _TEXTUAL or spec.family is Family.SPREADSHEET:
        _require(_looks_textual(head), ext, _describe(head))


def _sniff_ooxml(handle: BinaryIO, head: bytes, spec: FormatSpec, ext: str) -> None:
    if head.startswith(_OLE2_MAGIC):
        # Password-protected OOXML is stored inside an OLE2 container.
        handle.seek(0)
        if _OLE_ENCRYPTION_INFO in handle.read(8 * 1024 * 1024):
            raise errors.encrypted_document()
        raise errors.format_mismatch(ext, "a legacy Office file")
    _require(head.startswith(_ZIP_MAGIC), ext, _describe(head))
    names = _zip_names(handle, ext)
    main_part = _OOXML_MAIN_PART[_OOXML_ALIASES.get(spec.format_id, spec.format_id)]
    _require(
        "[Content_Types].xml" in names and main_part in names,
        ext,
        "a different kind of Office file" if "[Content_Types].xml" in names else "a ZIP archive",
    )


def _sniff_odf(handle: BinaryIO, head: bytes, spec: FormatSpec, ext: str) -> None:
    _require(head.startswith(_ZIP_MAGIC), ext, _describe(head))
    names = _zip_names(handle, ext)
    _require("mimetype" in names, ext, "a ZIP archive")
    # ODF requires an uncompressed "mimetype" entry right after the header.
    _require(_ODF_MIMETYPES[spec.format_id] in head[:200], ext, "a different OpenDocument type")


def _zip_names(handle: BinaryIO, ext: str) -> set[str]:
    handle.seek(0)
    try:
        with zipfile.ZipFile(handle) as archive:
            infos = archive.infolist()
            if len(infos) > _MAX_ZIP_ENTRIES:
                raise errors.format_mismatch(ext, "an abnormally large archive")
            return {info.filename for info in infos}
    except (zipfile.BadZipFile, EOFError, ValueError) as exc:
        raise errors.format_mismatch(ext, "a damaged archive") from exc


def _looks_textual(head: bytes) -> bool:
    if head.startswith((b"\xff\xfe", b"\xfe\xff")):  # UTF-16 with BOM
        return True
    return b"\x00" not in head


def _describe(head: bytes) -> str:
    if head.startswith(b"%PDF-"):
        return "a PDF"
    if head.startswith(_ZIP_MAGIC):
        return "a ZIP archive or Office file"
    if head.startswith(_OLE2_MAGIC):
        return "a legacy Office file"
    if head.startswith((b"\x89PNG", b"\xff\xd8\xff", b"GIF8")) or head[8:12] == b"WEBP":
        return "an image"
    if head.startswith((b"MZ",)):
        return "a Windows program"
    if not _looks_textual(head):
        return "binary data"
    return "plain text"


def _require(condition: bool, ext: str, detected: str) -> None:
    if not condition:
        raise errors.format_mismatch(ext, detected)
