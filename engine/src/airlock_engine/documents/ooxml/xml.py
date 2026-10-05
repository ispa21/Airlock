"""Namespace-agnostic helpers: match transitional and strict OOXML alike."""

from __future__ import annotations


def local(tag: object) -> str:
    if not isinstance(tag, str):
        return ""  # comments / processing instructions
    return tag.rsplit("}", 1)[-1] if tag.startswith("{") else tag


def family(tag: object) -> str:
    """'w' WordprocessingML, 'a' DrawingML, 's' SpreadsheetML, 'p' PresentationML, 'm' math."""
    if not isinstance(tag, str) or not tag.startswith("{"):
        return ""
    uri = tag[1 : tag.index("}")]
    if "wordprocessingml" in uri:
        return "w"
    if "spreadsheetml" in uri:
        return "s"
    if "presentationml" in uri:
        return "p"
    if "drawingml" in uri and uri.rstrip("/").endswith("main"):
        return "a"
    if "officeDocument/2006/math" in uri or uri.endswith("/math"):
        return "m"
    return ""


def attr(element: object, name: str) -> str | None:
    """Attribute by local name, whatever its namespace."""
    attrib = getattr(element, "attrib", {})
    for key, value in attrib.items():
        if local(key) == name:
            return str(value)
    return None


def rel_id(element: object) -> str:
    """The namespaced relationship id (``r:id``), not a plain ``id`` attribute."""
    attrib = getattr(element, "attrib", {})
    for key, value in attrib.items():
        if key.startswith("{") and "relationships" in key and local(key) == "id":
            return str(value)
    return ""
