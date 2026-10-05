"""Black out text found by OCR and drop every kind of image metadata.

Text inside a picture cannot be edited, so each OCR line that contains a
protected value is painted over. The image is then rebuilt from its pixels
alone, which removes EXIF (including GPS), XMP, ICC and PNG text chunks.
"""

from __future__ import annotations

import io
import struct
from collections.abc import Mapping, Sequence

from PIL import Image, ImageDraw, ImageSequence

from airlock_engine.documents.imaging import open_image

Box = tuple[float, float, float, float]
#: Extra pixels around each OCR line box, so anti-aliased edges are covered too.
_PAD = 3

_SAVE: Mapping[str, tuple[str, dict[str, object]]] = {
    "png": ("PNG", {"optimize": False}),
    "jpeg": ("JPEG", {"quality": 95}),
    "jpg": ("JPEG", {"quality": 95}),
    "webp": ("WEBP", {"quality": 95}),
    "tiff": ("TIFF", {"compression": "tiff_deflate"}),
    "tif": ("TIFF", {"compression": "tiff_deflate"}),
    "gif": ("GIF", {}),
    "bmp": ("BMP", {}),
}


def _clean_frame(frame: Image.Image, boxes: Sequence[Box] | None, whole: bool) -> Image.Image:
    mode = frame.mode
    if mode not in ("RGB", "RGBA", "L", "LA", "1", "CMYK"):
        mode = "RGBA" if "A" in mode or "transparency" in frame.info else "RGB"
        frame = frame.convert(mode)
    # Rebuild from raw pixels: no metadata of any kind survives.
    clean = Image.frombytes(mode, frame.size, frame.tobytes())
    if whole or boxes:
        draw = ImageDraw.Draw(clean)
        black: object = 0 if mode in ("L", "1") else (0, 0, 0, 0) if mode == "CMYK" else (0,) * 3
        if mode in ("RGBA",):
            black = (0, 0, 0, 255)
        if mode == "LA":
            black = (0, 255)
        if whole:
            draw.rectangle((0, 0, clean.width, clean.height), fill=black)  # type: ignore[arg-type]
        else:
            for x0, y0, x1, y1 in boxes or ():
                draw.rectangle(
                    (x0 - _PAD, y0 - _PAD, x1 + _PAD, y1 + _PAD),
                    fill=black,  # type: ignore[arg-type]
                )
    return clean


def sanitize_image(
    data: bytes, extension: str, paint: Mapping[str, Sequence[Box] | None]
) -> tuple[bytes, bool]:
    """Return (clean image bytes, whether metadata was present).

    ``paint`` maps a frame index ("0", "1"...) to boxes, or None to black out
    the whole frame.
    """
    image = open_image(data)
    had_metadata = bool(
        image.info.get("exif")
        or image.info.get("xmp")
        or image.info.get("icc_profile")
        or any(isinstance(v, str) for v in image.info.values())
    )
    fmt, options = _SAVE.get(extension.lower(), ("PNG", {}))
    frames = []
    for index, frame in enumerate(ImageSequence.Iterator(image)):
        key = str(index)
        frames.append(
            _clean_frame(frame.copy(), paint.get(key), key in paint and paint[key] is None)
        )
        if fmt != "TIFF":
            break  # only TIFF keeps several pages
    if fmt == "JPEG":
        frames = [f.convert("RGB") if f.mode not in ("RGB", "L", "CMYK") else f for f in frames]
    out = io.BytesIO()
    if len(frames) > 1:
        frames[0].save(out, format=fmt, save_all=True, append_images=frames[1:], **options)
    else:
        frames[0].save(out, format=fmt, **options)
    return out.getvalue(), had_metadata


def blank_image(extension: str) -> bytes:
    """A tiny blank image of the same format, for pictures Airlock cannot read."""
    ext = extension.lower()
    if ext == "emf":
        return _blank_emf()
    if ext == "wmf":
        return _blank_wmf()
    fmt, _ = _SAVE.get(ext, ("PNG", {}))
    out = io.BytesIO()
    Image.new("RGB" if fmt == "JPEG" else "RGBA", (1, 1), (255, 255, 255)).save(out, format=fmt)
    return out.getvalue()


def _blank_emf() -> bytes:
    header_size, eof_size = 108, 20
    total = header_size + eof_size
    header = struct.pack(
        "<II4i4iIIIIHHIIIii ii III ii".replace(" ", ""),
        1, header_size,           # EMR_HEADER
        0, 0, 1, 1,               # bounds
        0, 0, 100, 100,           # frame (0.01 mm)
        0x464D4520, 0x10000,      # " EMF", version
        total, 2, 1, 0,           # bytes, records, handles, reserved
        0, 0, 0,                  # description, palette entries
        1024, 768, 320, 240,      # device size (px, mm)
        0, 0, 0,                  # pixel format, OpenGL
        320000, 240000,           # device size (micrometres)
    )  # fmt: skip
    eof = struct.pack("<IIIII", 14, eof_size, 0, 16, eof_size)
    return header + eof


def _blank_wmf() -> bytes:
    # Placeable header (1 x 1 inch bounding box), then a header and EOF record.
    fields = (0xCDD7, 0x9AC6, 0, 0, 0, 1440, 1440, 1440, 0, 0)
    checksum = 0
    for word in fields:
        checksum ^= word
    placeable = struct.pack("<10H", *fields) + struct.pack("<H", checksum)
    words = 12
    header = struct.pack("<HHHIHIH", 1, 9, 0x0300, words, 0, 3, 0)
    eof = struct.pack("<IH", 3, 0)
    return placeable + header + eof
