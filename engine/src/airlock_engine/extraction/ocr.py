"""Local OCR providers.

RapidOCR (Apache-2.0) runs PP-OCR models through ONNX Runtime. The models ship
inside the ``rapidocr`` wheel, so nothing is downloaded; the network guard
would block any attempt.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

from airlock_engine.core.interfaces import OcrLine, OcrProvider

if TYPE_CHECKING:
    from PIL import Image


class RapidOcrProvider(OcrProvider):
    name = "rapidocr"

    def __init__(self) -> None:
        from rapidocr import RapidOCR

        self._engine = RapidOCR(params={"Global.log_level": "critical"})
        # RapidOCR installs its own console handler; route it through ours.
        for name in ("RapidOCR", "rapidocr"):
            logger = logging.getLogger(name)
            logger.handlers.clear()
            logger.propagate = True
            logger.setLevel(logging.ERROR)

    def recognize(self, image: Image.Image) -> Sequence[OcrLine]:
        # RapidOCR accepts PIL images at runtime although its hints omit them.
        engine: Any = self._engine
        result: Any = engine(image)
        texts = getattr(result, "txts", None) or ()
        scores = getattr(result, "scores", None) or ()
        boxes = getattr(result, "boxes", None)
        if boxes is None:
            return []
        lines: list[OcrLine] = []
        for text, score, quad in zip(texts, scores, boxes.tolist(), strict=False):
            xs = [float(p[0]) for p in quad]
            ys = [float(p[1]) for p in quad]
            lines.append(
                OcrLine(
                    text=str(text), score=float(score), box=(min(xs), min(ys), max(xs), max(ys))
                )
            )
        return lines


def default_ocr_provider() -> OcrProvider:
    return RapidOcrProvider()
