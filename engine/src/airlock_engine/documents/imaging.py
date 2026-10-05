"""Safe image decoding shared by the image adapter and embedded pictures."""

from __future__ import annotations

import io
import warnings
from typing import Final

from PIL import Image

from airlock_engine.core import errors

#: Pillow raises DecompressionBombError above twice this many pixels.
MAX_IMAGE_PIXELS: Final = 100_000_000
Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS

OCR_DECODABLE: Final = frozenset({"PNG", "JPEG", "WEBP", "TIFF", "BMP", "GIF"})


def open_image(data: bytes) -> Image.Image:
    """Decode ``data`` with pixel limits. Raises AirlockError for bombs/corruption."""
    with warnings.catch_warnings():
        warnings.simplefilter("error", Image.DecompressionBombWarning)
        try:
            image = Image.open(io.BytesIO(data))
            if image.format not in OCR_DECODABLE:
                raise errors.extraction_failed("image")
            width, height = image.size
            if width * height > MAX_IMAGE_PIXELS:
                raise errors.content_too_large("an image with too many pixels")
            image.load()
        except (Image.DecompressionBombError, Image.DecompressionBombWarning) as exc:
            raise errors.content_too_large("an image with too many pixels") from exc
        except errors.AirlockError:
            raise
        except (OSError, ValueError, SyntaxError, EOFError) as exc:
            raise errors.extraction_failed("image") from exc
    return image
