"""Write a safe copy of a DOCX, XLSX or PPTX package.

Every part is handled the way extraction classified it:

* XML parts: values replaced by :mod:`rewrite` (paragraph runs, cells,
  attributes, external link targets);
* pictures with protected text found by OCR: painted over; metadata stripped;
* pictures Airlock could not read (EMF/WMF, damaged): replaced by a blank;
* embedded Office files and text files: sanitised recursively;
* embedded objects Airlock could not read: emptied;
* macros (VBA) and the document thumbnail: removed, with their relationships
  and content types, so Office opens the file without a repair prompt;
* author fields in the document properties: cleared (``strip_metadata``).

Every rewritten XML part must parse again, or the copy is refused.
"""

from __future__ import annotations

import io
import posixpath
import zipfile
from collections.abc import Callable, Mapping
from typing import Final

from airlock_engine.core import errors
from airlock_engine.documents.ooxml.base import _BINARY_NO_CONTENT, _NO_CONTENT, _OCR_EXTENSIONS
from airlock_engine.documents.ooxml.package import OoxmlPackage, XmlUnreadable, parse_xml
from airlock_engine.documents.ooxml.rewrite import RewriteError, rewrite_xml
from airlock_engine.documents.sanitize_plan import SanitizeOutput, SanitizePlan
from airlock_engine.masking.sweep import Sweeper

_XML_EXTENSIONS: Final = frozenset({"xml", "rels", "vml", "svg"})
#: Document-property elements that name people or organisations.
_PERSON_FIELDS: Final = frozenset({"creator", "lastModifiedBy", "Company", "Manager"})

Recurse = Callable[[bytes, str, SanitizePlan, Sweeper, int], SanitizeOutput]


def _extension(name: str) -> str:
    base = posixpath.basename(name)
    return base.rsplit(".", 1)[-1].lower() if "." in base else ""


def sanitize_ooxml(
    data: bytes,
    format_label: str,
    plan: SanitizePlan,
    sweeper: Sweeper,
    *,
    depth: int,
    recurse: Recurse,
) -> SanitizeOutput:
    from airlock_engine.documents.images.sanitize import blank_image, sanitize_image
    from airlock_engine.documents.imaging import open_image
    from airlock_engine.extraction.pipeline import embedded_format

    pkg = OoxmlPackage(data, format_label)
    out = SanitizeOutput(b"")
    removed_parts: set[str] = set()
    contents: dict[str, bytes] = {}
    paint_by_part: dict[str, dict[str, list[tuple[float, float, float, float]] | None]] = {}
    for (part, path), boxes in plan.paint.items():
        if "!/" not in part:
            paint_by_part.setdefault(part, {})[path] = boxes

    for name in pkg.names:
        base = posixpath.basename(name).lower()
        ext = _extension(name)
        content_type = pkg.content_type(name)
        raw = pkg.read(name)

        if base in ("vbaproject.bin", "vbadata.xml") or "vbaProject" in content_type:
            removed_parts.add(name)
            if base == "vbaproject.bin":
                out.removed.append(("macro", "Macros (VBA project)"))
            continue
        if name.lower().startswith("docprops/thumbnail"):
            removed_parts.add(name)
            out.removed.append(("thumbnail", "Document thumbnail"))
            continue
        if "/embeddings/" in name:
            fmt = embedded_format(raw, base)
            if fmt is not None and depth < 2 and fmt != "pdf":
                inner = recurse(raw, fmt, plan.embedded(name), sweeper, depth + 1)
                contents[name] = inner.data
                out.removed.extend(inner.removed)
            else:
                # Unreadable (or a PDF, which cannot be rebuilt in place): emptied.
                contents[name] = b""
                out.removed.append(("embedded_object", f"Embedded file {posixpath.basename(name)}"))
            continue
        if content_type.startswith("image/") or ext in _OCR_EXTENSIONS | {"emf", "wmf"}:
            if ext == "svg" or content_type == "image/svg+xml":
                contents[name] = _rewrite(raw, sweeper, name)
                continue
            if ext not in _OCR_EXTENSIONS:
                contents[name] = blank_image(ext)
                out.removed.append(
                    ("image", "Picture Airlock could not read (replaced by a blank)")
                )
                continue
            try:
                open_image(raw)
            except errors.AirlockError:
                contents[name] = blank_image(ext)
                out.removed.append(
                    ("image", "Picture Airlock could not read (replaced by a blank)")
                )
                continue
            paint = paint_by_part.get(name)
            if paint or plan.strip_metadata:
                contents[name], _ = sanitize_image(raw, ext, paint or {})
            else:
                contents[name] = raw
            continue
        if ext in _XML_EXTENSIONS or content_type.endswith("xml"):
            if name == "[Content_Types].xml" or _NO_CONTENT.search(name):
                contents[name] = raw
                continue
            contents[name] = _rewrite(
                raw,
                sweeper,
                name,
                spreadsheet="/worksheets/" in name or "/pivotCache" in name,
                clear=_PERSON_FIELDS
                if plan.strip_metadata and name.startswith("docProps/")
                else None,
            )
            continue
        if _BINARY_NO_CONTENT.search(name):
            contents[name] = raw
            continue
        contents[name] = b""
        out.removed.append(("embedded_object", f"Unrecognised part {posixpath.basename(name)}"))

    if removed_parts:
        _drop_references(pkg, contents, removed_parts)

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name in pkg.names:
            if name in removed_parts or name not in contents:
                continue
            zout.writestr(_zipinfo(name), contents[name])
    out.data = buffer.getvalue()
    return out


def _zipinfo(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def _rewrite(
    raw: bytes,
    sweeper: Sweeper,
    name: str,
    *,
    spreadsheet: bool = False,
    clear: frozenset[str] | None = None,
    drop: Callable[[str, Mapping[str, str]], bool] | None = None,
) -> bytes:
    try:
        well_formed = True
        parse_xml(raw)
    except XmlUnreadable:
        well_formed = False  # legacy VML: rewritten token by token, not re-validated
    new = rewrite_xml(
        raw, sweeper, spreadsheet=spreadsheet, clear_elements=clear or frozenset(), drop_tag=drop
    )
    if new is not raw and well_formed:
        try:
            parse_xml(new)
        except XmlUnreadable as exc:
            raise RewriteError(name) from exc
    return new


def _drop_references(pkg: OoxmlPackage, contents: dict[str, bytes], removed: set[str]) -> None:
    """Remove relationships and content-type overrides that point to removed parts."""
    removed |= {pkg.rels_part(name) for name in removed if pkg.has(pkg.rels_part(name))}
    no_sweep = Sweeper([])
    for name in list(contents):
        if name.endswith(".rels") and name not in removed:
            source_dir = posixpath.dirname(posixpath.dirname(name))
            if name == "_rels/.rels":
                source_dir = ""

            def points_to_removed(
                tag: str, attrs: Mapping[str, str], source_dir: str = source_dir
            ) -> bool:
                if tag != "Relationship" or attrs.get("TargetMode") == "External":
                    return False
                target = attrs.get("Target", "")
                resolved = (
                    target.lstrip("/")
                    if target.startswith("/")
                    else posixpath.normpath(posixpath.join(source_dir, target))
                )
                return resolved in removed

            contents[name] = _rewrite(contents[name], no_sweep, name, drop=points_to_removed)
    if "[Content_Types].xml" in contents:

        def override_removed(tag: str, attrs: Mapping[str, str]) -> bool:
            return tag == "Override" and attrs.get("PartName", "").lstrip("/") in removed

        contents["[Content_Types].xml"] = _rewrite(
            contents["[Content_Types].xml"], no_sweep, "[Content_Types].xml", drop=override_removed
        )
    for name in removed:
        contents.pop(name, None)
