"""PowerPoint presentations (PPTX/PPTM)."""

from __future__ import annotations

from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.ooxml.base import OoxmlAdapter, PartRole, common_role, numbered
from airlock_engine.documents.ooxml.package import OoxmlPackage, XmlUnreadable
from airlock_engine.documents.ooxml.xml import local, rel_id
from airlock_engine.extraction.context import ExtractionContext


class PptxAdapter(OoxmlAdapter):
    formats = ("pptx", "pptm")
    format_label = "PowerPoint presentation"

    def extract_structured(self, pkg: OoxmlPackage, ctx: ExtractionContext, main: str) -> set[str]:
        handled = {main}
        rels = {rel.rel_id: rel for rel in pkg.relationships(main)}
        try:
            presentation = pkg.xml(main)
        except XmlUnreadable:
            presentation = None

        slides: list[str] = []
        if presentation is not None:
            for el in presentation.iter():
                if local(el.tag) == "sldId":
                    rel = rels.get(rel_id(el))
                    if rel is not None and pkg.has(rel.target):
                        slides.append(rel.target)
        ctx.count("slides", len(slides))

        for number, part in enumerate(slides, start=1):
            ctx.progress("slides", number - 1, len(slides))
            hidden = self._is_hidden(pkg, part)
            label = f"Slide {number}" + (" (hidden)" if hidden else "")
            kind = SegmentKind.HIDDEN if hidden else SegmentKind.BODY
            self.walk_part(pkg, ctx, part, PartRole(kind, label))
            handled.add(part)
            for rel in pkg.relationships(part):
                if rel.rel_type.endswith("/notesSlide") and pkg.has(rel.target):
                    self.walk_part(
                        pkg, ctx, rel.target, PartRole(SegmentKind.NOTE, f"Slide {number} notes")
                    )
                    handled.add(rel.target)
        ctx.progress("slides", len(slides), len(slides))
        return handled

    @staticmethod
    def _is_hidden(pkg: OoxmlPackage, part: str) -> bool:
        try:
            return pkg.xml(part).get("show") in ("0", "false")
        except XmlUnreadable:
            return False

    def classify(self, name: str, content_type: str) -> PartRole | None:
        lowered = name.lower()
        base = lowered.rsplit("/", 1)[-1]
        if "/slides/" in lowered:
            return PartRole(SegmentKind.HIDDEN, numbered(name, "Slide not in the slide show"))
        if "/notesslides/" in lowered:
            return PartRole(SegmentKind.NOTE, "Speaker notes")
        if "/slidelayouts/" in lowered:
            return PartRole(SegmentKind.TEMPLATE, numbered(name, "Slide layout"))
        if "/slidemasters/" in lowered:
            return PartRole(SegmentKind.TEMPLATE, numbered(name, "Slide master"))
        if "/notesmasters/" in lowered or "/handoutmasters/" in lowered:
            return PartRole(SegmentKind.TEMPLATE, "Notes and handout masters")
        if "/comments/" in lowered:
            return PartRole(SegmentKind.COMMENT, "Comments")
        if base in ("commentauthors.xml", "authors.xml"):
            return PartRole(SegmentKind.METADATA, "Comment authors", {"name": SegmentKind.METADATA})
        if "/tags/" in lowered:
            return PartRole(
                SegmentKind.METADATA,
                "Add-in tags",
                {"name": SegmentKind.METADATA, "val": SegmentKind.METADATA},
            )
        role = common_role(name)
        if role is not None:
            return role
        return PartRole(SegmentKind.HIDDEN, "Other presentation data")
