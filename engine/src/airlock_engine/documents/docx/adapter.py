"""Word documents (DOCX/DOCM)."""

from __future__ import annotations

import re
from typing import Final

from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.ooxml.base import OoxmlAdapter, PartRole, common_role, numbered
from airlock_engine.documents.ooxml.package import OoxmlPackage, XmlUnreadable
from airlock_engine.documents.ooxml.xml import attr, local
from airlock_engine.extraction.context import ExtractionContext

_SETTINGS: Final = re.compile(r"^word/settings\.xml$")


class DocxAdapter(OoxmlAdapter):
    formats = ("docx", "docm")
    format_label = "Word document"

    def extract_structured(self, pkg: OoxmlPackage, ctx: ExtractionContext, main: str) -> set[str]:
        paragraphs = self.walk_part(pkg, ctx, main, PartRole(SegmentKind.BODY, "Body"))
        ctx.count("paragraphs", paragraphs)
        handled = {main}
        settings = next((n for n in pkg.names if _SETTINGS.match(n)), None)
        if settings:
            self._extract_settings(pkg, ctx, settings)
            handled.add(settings)
        return handled

    def classify(self, name: str, content_type: str) -> PartRole | None:
        base = name.rsplit("/", 1)[-1].lower()
        if base.startswith("header"):
            return PartRole(SegmentKind.HEADER_FOOTER, numbered(name, "Header"))
        if base.startswith("footer"):
            return PartRole(SegmentKind.HEADER_FOOTER, numbered(name, "Footer"))
        if base.startswith("footnotes"):
            return PartRole(SegmentKind.NOTE, "Footnotes")
        if base.startswith("endnotes"):
            return PartRole(SegmentKind.NOTE, "Endnotes")
        if base.startswith("comments"):
            return PartRole(SegmentKind.COMMENT, "Comments")
        if base == "people.xml":
            return PartRole(SegmentKind.METADATA, "Reviewers")
        if "/glossary/" in name:
            return PartRole(SegmentKind.TEMPLATE, "Building blocks")
        role = common_role(name)
        if role is not None:
            return role
        return PartRole(SegmentKind.HIDDEN, "Other document data")

    @staticmethod
    def _extract_settings(pkg: OoxmlPackage, ctx: ExtractionContext, name: str) -> None:
        """Document variables and mail-merge sources (may hold queries or credentials)."""
        try:
            root = pkg.xml(name)
        except XmlUnreadable:
            return
        for index, el in enumerate(root.iter()):
            tag = local(el.tag)
            if tag == "docVar":
                ctx.add(
                    attr(el, "val") or "",
                    name,
                    f"e/{index}",
                    kind=SegmentKind.HIDDEN,
                    label="Document variables",
                )
            elif tag in ("connectString", "query", "dataSource", "udl", "src"):
                ctx.add(
                    attr(el, "val") or "",
                    name,
                    f"e/{index}",
                    kind=SegmentKind.LINK,
                    label="Mail merge data source",
                )
