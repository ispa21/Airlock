"""Shared extraction flow for DOCX, XLSX and PPTX.

Each adapter extracts the parts it understands structurally, then every
remaining part is classified and walked generically. No part is skipped
unless it is on an explicit list of parts that never carry user content.
"""

from __future__ import annotations

import posixpath
import re
from abc import abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from airlock_engine.core import errors
from airlock_engine.core.interfaces import DocumentAdapter
from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.imaging import open_image
from airlock_engine.documents.ooxml.package import OoxmlPackage, XmlUnreadable
from airlock_engine.documents.ooxml.text import extract_markup_fallback, extract_part
from airlock_engine.extraction.context import ExtractionContext

#: Parts that hold only formatting or application state, never user text.
_NO_CONTENT: Final = re.compile(
    r"(^|/)(theme\d*|styles|stylesWithEffects|fontTable|webSettings|numbering|tableStyles|"
    r"presProps|viewProps|calcChain|commentsIds|commentsExtensible|itemProps\d*|"
    r"colors\d*|quickStyle\d*|layout\d*|style\d*|"
    r"\[Content_Types\])\.xml$",
    re.IGNORECASE,
)
_BINARY_NO_CONTENT: Final = re.compile(r"(\.odttf|\.fntdata|printerSettings\d*\.bin)$", re.I)
_OCR_EXTENSIONS: Final = frozenset({"png", "jpg", "jpeg", "gif", "bmp", "tif", "tiff", "webp"})
_XML_EXTENSIONS: Final = frozenset({"xml", "vml", "rels", "svg"})


@dataclass(frozen=True, slots=True)
class PartRole:
    kind: SegmentKind
    label: str
    extra_attrs: Mapping[str, SegmentKind] | None = None


def numbered(name: str, stem: str) -> str:
    """'word/header2.xml', 'Header' -> 'Header 2'."""
    match = re.search(r"(\d+)\.\w+$", name)
    return f"{stem} {match.group(1)}" if match else stem


class OoxmlAdapter(DocumentAdapter):
    format_label: str = "Office file"

    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        pkg = OoxmlPackage(data, self.format_label)
        main = pkg.main_part()
        if main is None:
            raise errors.extraction_failed(self.format_label)
        handled = self.extract_structured(pkg, ctx, main)
        images = 0
        remaining = [n for n in sorted(pkg.names) if n not in handled]
        for done, name in enumerate(remaining):
            ctx.progress("parts", done, len(remaining))
            if name.endswith(".rels"):
                self._extract_external_links(pkg, ctx, name)
                continue
            images += self._extract_other(pkg, ctx, name, images)
        ctx.progress("parts", len(remaining), len(remaining))

    # ----------------------------------------------------------- per format
    @abstractmethod
    def extract_structured(self, pkg: OoxmlPackage, ctx: ExtractionContext, main: str) -> set[str]:
        """Extract format-specific parts; return the part names handled."""

    @abstractmethod
    def classify(self, name: str, content_type: str) -> PartRole | None:
        """Role of a generic XML part, or None to skip it."""

    # --------------------------------------------------------------- shared
    def walk_part(
        self, pkg: OoxmlPackage, ctx: ExtractionContext, name: str, role: PartRole
    ) -> int:
        """Walk a part; malformed XML falls back to tag stripping (never skipped)."""
        try:
            root = pkg.xml(name)
        except XmlUnreadable:
            extract_markup_fallback(ctx, pkg.read(name), name, kind=role.kind, label=role.label)
            return 0
        return extract_part(
            ctx, root, name, kind=role.kind, label=role.label, extra_attrs=role.extra_attrs
        )

    def _extract_other(
        self, pkg: OoxmlPackage, ctx: ExtractionContext, name: str, images: int
    ) -> int:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        content_type = pkg.content_type(name)
        base = posixpath.basename(name)

        if base.lower() == "vbaproject.bin" or "vbaProject" in content_type:
            ctx.unextracted("macro", "Macros (VBA project)")
            return 0
        if "/embeddings/" in name:
            ctx.embedded(pkg.read(name), base, name, f"Embedded file {base}")
            return 0
        if content_type.startswith("image/") or ext in _OCR_EXTENSIONS | {"emf", "wmf"}:
            if ext == "svg" or content_type == "image/svg+xml":
                self.walk_part(pkg, ctx, name, PartRole(SegmentKind.OCR, "Vector image text"))
                return 0
            label = "Document thumbnail" if "thumbnail" in base.lower() else f"Image {images + 1}"
            if ext not in _OCR_EXTENSIONS:
                ctx.unextracted("image", f"{label} (format not readable)")
                return 1
            try:
                image = open_image(pkg.read(name))
            except errors.AirlockError:
                ctx.unextracted("image", label)
                return 1
            ctx.ocr_image(image, name, "0", label=label, embedded=True)
            return 1
        if ext in _XML_EXTENSIONS or content_type.endswith("xml"):
            if _NO_CONTENT.search(name):
                return 0
            role = self.classify(name, content_type)
            if role is None:
                return 0
            if ext == "vml":
                extract_markup_fallback(ctx, pkg.read(name), name, kind=role.kind, label=role.label)
            else:
                self.walk_part(pkg, ctx, name, role)
            return 0
        if _BINARY_NO_CONTENT.search(name):
            return 0
        ctx.unextracted("embedded_object", f"Unrecognised part {base}")
        return 0

    @staticmethod
    def _extract_external_links(pkg: OoxmlPackage, ctx: ExtractionContext, rels_name: str) -> None:
        # rels_name is "<dir>/_rels/<part>.rels"; recover the source part name.
        directory, base = posixpath.split(rels_name)
        source = posixpath.join(posixpath.dirname(directory), base[: -len(".rels")])
        source = "" if rels_name == "_rels/.rels" else source
        for rel in pkg.relationships(source):
            if rel.external and rel.target.strip():
                ctx.add(
                    rel.target,
                    rels_name,
                    f"rel/{rel.rel_id}",
                    kind=SegmentKind.LINK,
                    label="Links and external references",
                )


METADATA_ROLES: Final[Mapping[str, PartRole]] = {
    "docProps/core.xml": PartRole(SegmentKind.METADATA, "Document properties"),
    "docProps/app.xml": PartRole(SegmentKind.METADATA, "Document properties"),
    "docProps/custom.xml": PartRole(SegmentKind.METADATA, "Custom properties"),
}


def common_role(name: str) -> PartRole | None:
    """Roles shared by every OOXML format."""
    if name in METADATA_ROLES:
        return METADATA_ROLES[name]
    if name.startswith("customXml/"):
        return PartRole(SegmentKind.METADATA, "Custom XML data")
    if "/charts/" in name:
        return PartRole(SegmentKind.CHART, numbered(name, "Chart"))
    if "/diagrams/" in name:
        return PartRole(SegmentKind.BODY, numbered(name, "SmartArt"))
    if "/activeX/" in name:
        return PartRole(SegmentKind.METADATA, "Form controls")
    return None
