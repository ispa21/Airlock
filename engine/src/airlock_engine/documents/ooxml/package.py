"""Hardened access to an OOXML ZIP package."""

from __future__ import annotations

import io
import posixpath
import zipfile
import zlib
from dataclasses import dataclass
from typing import Final
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml import ElementTree as SafeET

from airlock_engine.core import errors
from airlock_engine.documents.ooxml.xml import local

MAX_ENTRIES: Final = 20_000
MAX_TOTAL_BYTES: Final = 2 * 1024 * 1024 * 1024
MAX_PART_BYTES: Final = 512 * 1024 * 1024
#: Parts that inflate more than this ratio (and are big) are treated as zip bombs.
MAX_RATIO: Final = 200
_RATIO_MIN_BYTES: Final = 16 * 1024 * 1024
_EXTERNAL: Final = "External"


@dataclass(frozen=True, slots=True)
class Relationship:
    rel_id: str
    rel_type: str
    target: str  # resolved part name for internal targets, raw target if external
    external: bool


class XmlUnreadable(Exception):
    """A part is not well-formed XML (or uses forbidden XML features)."""


class OoxmlPackage:
    def __init__(self, data: bytes, format_label: str) -> None:
        self.format_label = format_label
        try:
            self._zip = zipfile.ZipFile(io.BytesIO(data))
            infos = self._zip.infolist()
        except (zipfile.BadZipFile, NotImplementedError, ValueError, EOFError, OSError) as exc:
            raise errors.extraction_failed(format_label) from exc
        if len(infos) > MAX_ENTRIES:
            raise errors.unsafe_archive()
        total = 0
        for info in infos:
            total += info.file_size
            if info.file_size > MAX_PART_BYTES or total > MAX_TOTAL_BYTES:
                raise errors.unsafe_archive()
            if info.file_size > _RATIO_MIN_BYTES and (
                info.compress_size == 0 or info.file_size / info.compress_size > MAX_RATIO
            ):
                raise errors.unsafe_archive()
        self.names: list[str] = [i.filename for i in infos if not i.is_dir()]
        self._name_set = set(self.names)
        self._defaults: dict[str, str] = {}
        self._overrides: dict[str, str] = {}
        self._load_content_types()

    # ----------------------------------------------------------------- access
    def has(self, name: str) -> bool:
        return name in self._name_set

    def read(self, name: str) -> bytes:
        try:
            return self._zip.read(name)
        except (
            zipfile.BadZipFile,
            zlib.error,
            NotImplementedError,  # corrupted compression method / version fields
            KeyError,
            EOFError,
            OSError,
            ValueError,
        ) as exc:
            raise errors.extraction_failed(self.format_label) from exc

    def xml(self, name: str) -> Element:
        """Parse a part with DTDs and entity expansion forbidden."""
        return parse_xml(self.read(name))

    def content_type(self, name: str) -> str:
        override = self._overrides.get("/" + name.lstrip("/"))
        if override:
            return override
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        return self._defaults.get(ext, "")

    # ---------------------------------------------------------- relationships
    def rels_part(self, part: str) -> str:
        directory, base = posixpath.split(part)
        return posixpath.join(directory, "_rels", base + ".rels")

    def relationships(self, part: str = "") -> list[Relationship]:
        """Relationships of ``part`` (``""`` = package root)."""
        rels_name = "_rels/.rels" if not part else self.rels_part(part)
        if not self.has(rels_name):
            return []
        try:
            root = self.xml(rels_name)
        except XmlUnreadable:
            return []
        base = posixpath.dirname(part)
        result = []
        for el in root.iter():
            if local(el.tag) != "Relationship":
                continue
            target = el.get("Target", "")
            external = el.get("TargetMode") == _EXTERNAL
            if not external:
                if target.startswith("/"):
                    target = target.lstrip("/")
                else:
                    target = posixpath.normpath(posixpath.join(base, target))
            result.append(Relationship(el.get("Id", ""), el.get("Type", ""), target, external))
        return result

    def main_part(self) -> str | None:
        for rel in self.relationships():
            if rel.rel_type.endswith("/officeDocument") and self.has(rel.target):
                return rel.target
        return None

    def _load_content_types(self) -> None:
        if not self.has("[Content_Types].xml"):
            raise errors.extraction_failed(self.format_label)
        try:
            root = self.xml("[Content_Types].xml")
        except XmlUnreadable as exc:
            raise errors.extraction_failed(self.format_label) from exc
        for el in root.iter():
            name = local(el.tag)
            if name == "Default":
                self._defaults[el.get("Extension", "").lower()] = el.get("ContentType", "")
            elif name == "Override":
                self._overrides[el.get("PartName", "")] = el.get("ContentType", "")


def parse_xml(data: bytes) -> Element:
    try:
        root: Element = SafeET.fromstring(data, forbid_dtd=True)
    except (ParseError, DefusedXmlException, ValueError) as exc:
        raise XmlUnreadable from exc
    return root
