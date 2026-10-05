"""Images (PNG, JPEG, WebP, TIFF): local OCR plus metadata.

Photos and scans often carry personal data outside the pixels: camera owner,
author fields, comments and GPS coordinates. Those are extracted too.
"""

from __future__ import annotations

from typing import Any, Final

from PIL import Image

from airlock_engine.core import errors
from airlock_engine.core.interfaces import DocumentAdapter
from airlock_engine.core.models import SegmentKind
from airlock_engine.documents.imaging import open_image
from airlock_engine.documents.ooxml.package import XmlUnreadable, parse_xml
from airlock_engine.documents.ooxml.text import extract_part
from airlock_engine.extraction.context import ExtractionContext

# Base IFD text tags.
_TEXT_TAGS: Final = {270: "Description", 315: "Artist", 33432: "Copyright"}
# Windows "XP" tags, UTF-16LE.
_XP_TAGS: Final = {
    40091: "Title",
    40092: "Comment",
    40093: "Author",
    40094: "Keywords",
    40095: "Subject",
}
# Exif sub-IFD.
_EXIF_IFD: Final = 0x8769
_EXIF_TAGS: Final = {37510: "User comment", 42032: "Camera owner", 42033: "Camera serial number"}
_GPS_IFD: Final = 0x8825
#: Non-text entries Pillow puts in ``Image.info``.
_TECHNICAL_INFO: Final = frozenset(
    {
        "dpi", "gamma", "transparency", "icc_profile", "exif", "xmp", "interlace", "aspect",
        "progression", "progressive", "jfif", "jfif_version", "jfif_unit", "jfif_density",
        "adobe", "adobe_transform", "compression", "duration", "loop", "background",
        "photoshop", "mp", "srgb", "chromaticity", "resolution", "bbox", "lossless",
    }
)  # fmt: skip


def _decode_xp(value: Any) -> str:
    raw = bytes(value) if not isinstance(value, bytes) else value
    return raw.decode("utf-16-le", errors="replace").rstrip("\x00")


def _decode_user_comment(value: Any) -> str:
    raw = bytes(value) if not isinstance(value, bytes) else value
    prefix, body = raw[:8], raw[8:]
    if prefix.startswith(b"UNICODE"):
        return body.decode("utf-16", errors="replace").rstrip("\x00")
    return body.decode("utf-8", errors="replace").rstrip("\x00 ")


def _gps_coordinate(values: Any, ref: Any) -> float | None:
    try:
        degrees, minutes, seconds = (float(v) for v in values)
    except (TypeError, ValueError, ZeroDivisionError):
        return None
    coordinate = degrees + minutes / 60 + seconds / 3600
    return -coordinate if str(ref).upper() in ("S", "W") else coordinate


class ImageAdapter(DocumentAdapter):
    formats = ("png", "jpeg", "webp", "tiff")

    def extract(self, data: bytes, ctx: ExtractionContext) -> None:
        image = open_image(data)
        self._metadata(image, ctx)
        frames = int(getattr(image, "n_frames", 1) or 1)
        if frames > ctx.options.max_pages:
            raise errors.content_too_large(f"more than {ctx.options.max_pages:,} pages")
        ctx.count("pages", frames)
        for index in range(frames):
            ctx.progress("ocr", index, frames)
            try:
                image.seek(index)
                frame = image.copy()
            except (OSError, ValueError, EOFError) as exc:
                raise errors.extraction_failed("image") from exc
            label = "Text in image" if frames == 1 else f"Page {index + 1} text"
            ctx.ocr_image(frame, "frame", str(index), label=label)
        ctx.progress("ocr", frames, frames)

    @staticmethod
    def _metadata(image: Image.Image, ctx: ExtractionContext) -> None:
        def add(text: str, path: str, label: str = "Image metadata") -> None:
            ctx.add(text.strip(), "metadata", path, kind=SegmentKind.METADATA, label=label)

        try:
            exif = image.getexif()
        except (OSError, ValueError, SyntaxError):
            exif = None
        if exif:
            for tag, name in _TEXT_TAGS.items():
                if isinstance(exif.get(tag), str):
                    add(exif[tag], f"exif/{tag}", f"Image metadata ({name})")
            for tag, name in _XP_TAGS.items():
                if exif.get(tag) is not None:
                    add(_decode_xp(exif[tag]), f"exif/{tag}", f"Image metadata ({name})")
            sub = exif.get_ifd(_EXIF_IFD)
            for tag, name in _EXIF_TAGS.items():
                value = sub.get(tag)
                if isinstance(value, bytes) and tag == 37510:
                    add(_decode_user_comment(value), f"exif/{tag}", f"Image metadata ({name})")
                elif isinstance(value, str):
                    add(value, f"exif/{tag}", f"Image metadata ({name})")
            gps = exif.get_ifd(_GPS_IFD)
            if gps:
                lat = _gps_coordinate(gps.get(2), gps.get(1))
                lon = _gps_coordinate(gps.get(4), gps.get(3))
                if lat is not None and lon is not None:
                    add(f"{lat:.6f}, {lon:.6f}", "gps", "Location where the photo was taken")

        for n, (key, value) in enumerate(image.info.items()):
            if key in _TECHNICAL_INFO:
                continue
            if isinstance(value, bytes):
                value = value.decode("utf-8", errors="replace")
            if isinstance(value, str):
                add(value, f"info/{n}", "Image comments")
        xmp = image.info.get("xmp")
        if xmp:
            try:
                root = parse_xml(xmp if isinstance(xmp, bytes) else str(xmp).encode())
            except XmlUnreadable:
                return
            extract_part(ctx, root, "xmp", kind=SegmentKind.METADATA, label="XMP metadata")
