# Third-party software

Airlock ships only open-source components under permissive licences. The
policy is enforced by `engine/tests/test_licenses.py`, which fails if any
runtime dependency of the engine is GPL, AGPL, LGPL or SSPL licensed.

## Engine runtime (Python)

| Package | Licence | Purpose |
| --- | --- | --- |
| pypdfium2 (with PDFium) | Apache-2.0 / BSD-3-Clause | PDF reading and rendering |
| defusedxml | PSF-2.0 | Hardened XML parsing |
| Pillow | MIT-CMU (HPND) | Image decoding, EXIF |
| rapidocr (+ bundled PP-OCR models) | Apache-2.0 | Local OCR |
| onnxruntime | MIT | OCR inference |
| opencv-python-headless | Apache-2.0 | Image pre-processing for OCR |
| numpy | BSD-3-Clause | Arrays |
| shapely | BSD-3-Clause | OCR geometry |
| pyclipper | MIT | OCR geometry |
| omegaconf, antlr4-python3-runtime | BSD-3-Clause | OCR configuration |
| PyYAML, six, colorlog | MIT | OCR configuration and logging |
| protobuf, flatbuffers, packaging | BSD-3-Clause / Apache-2.0 | ONNX Runtime dependencies |
| requests, urllib3, idna, charset-normalizer | Apache-2.0 / MIT / BSD-3-Clause | Pulled in by rapidocr for optional model downloads. **Never used**: Airlock ships the models, and the network guard blocks any attempt. |
| certifi | MPL-2.0 | CA bundle pulled in by requests (unused, unmodified) |
| tqdm | MPL-2.0 AND MIT | Progress utility pulled in by rapidocr (unmodified) |

MPL-2.0 is a file-level licence. Distributing unmodified copies inside a
proprietary product is permitted, provided the licence notice and source
availability are preserved. The installer's notices file must carry these
notices (Phase 8).

## Desktop (Rust / TypeScript)

| Component | Licence |
| --- | --- |
| Tauri 2, tauri-plugin-dialog, wry, tao | Apache-2.0 / MIT |
| serde, serde_json | Apache-2.0 / MIT |
| React, React DOM | MIT |
| @tauri-apps/api, @tauri-apps/plugin-dialog | Apache-2.0 / MIT |

## Development only (not shipped)

python-docx (MIT), openpyxl (MIT), python-pptx (MIT) and reportlab (BSD) build
test fixtures; pytest (MIT), ruff (MIT), mypy (MIT), Vite (MIT), Vitest (MIT)
and Testing Library (MIT) are used for development and CI.

A complete notices file listing every transitive dependency with its licence
text is generated for the installer in Phase 8.
