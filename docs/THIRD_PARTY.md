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
| spaCy | MIT | Local named-entity recognition (Phase 3) |
| en_core_web_sm 3.8.0 (model) | MIT | English NER model, shipped inside the engine; installed from the spaCy release wheel, never downloaded at run time |
| thinc, blis, srsly, cymem, preshed, murmurhash, wasabi, weasel, catalogue, confection, spacy-legacy, spacy-loggers | MIT / BSD | spaCy runtime |
| pydantic, pydantic-core, annotated-types, typing-inspection, typing-extensions | MIT / PSF-2.0 | spaCy configuration |
| typer, click, rich, shellingham, markdown-it-py, mdurl, Pygments, jinja2, MarkupSafe, smart-open, cloudpathlib, wrapt, setuptools | MIT / BSD / ISC | Pulled in by spaCy's CLI and project tooling; not used by Airlock |
| phonenumbers | Apache-2.0 | Phone number validation with bundled metadata (offline) |
| regex | Apache-2.0 AND CNRI-Python | Company-rule patterns with a per-match timeout (ReDoS-safe) |
| cryptography | Apache-2.0 OR BSD-3-Clause | AES-256-GCM for the placeholder vault and key wrapping (Phase 5) |
| cffi, pycparser | MIT-0 / BSD-3-Clause | cryptography runtime |
| reportlab | BSD | Rebuilds safe PDFs from masked text (Phase 5). Only the **Bitstream Vera** fonts (Vera licence, permissive) are bundled; the GPL *DarkGarden* font and the other sample fonts are left out of the frozen engine, and `scripts/package.py` fails a build that contains them. |
| opencv-python-headless (bundled libraries) | Apache-2.0; FFmpeg plugin LGPL | The wheel carries an FFmpeg video plugin (LGPL) that Airlock never loads. On Windows it is a separate DLL (`opencv_videoio_ffmpeg*.dll`) and is left out of the bundle (the build fails if it is present). Linux wheels link FFmpeg into `cv2` itself, so a Linux test build contains it; Linux is not a shipped platform. |

MPL-2.0 is a file-level licence. Distributing unmodified copies inside a
proprietary product is permitted, provided the licence notice and source
availability are preserved. The installer's `THIRD_PARTY_NOTICES.txt` carries
these notices.

## Desktop (Rust / TypeScript)

| Component | Licence |
| --- | --- |
| Tauri 2, tauri-plugin-dialog, wry, tao | Apache-2.0 / MIT |
| sha2 | Apache-2.0 / MIT (engine integrity check, machine code) |
| ed25519-dalek, curve25519-dalek | BSD-3-Clause (licence signatures) |
| base64 | Apache-2.0 / MIT |
| ureq, rustls, rustls-native-certs, webpki | Apache-2.0 / MIT / ISC (online licence activation only) |
| ring | Apache-2.0 AND ISC |
| webpki-roots | CDLA-Permissive-2.0 / MPL-2.0 (unmodified) |
| winreg | MIT (reads the Windows machine ID for the machine code) |

Windows DPAPI is called through Python's standard `ctypes` (no pywin32).
| serde, serde_json | Apache-2.0 / MIT |
| React, React DOM | MIT |
| @tauri-apps/api, @tauri-apps/plugin-dialog | Apache-2.0 / MIT |

## Development only (not shipped)

python-docx (MIT), openpyxl (MIT) and python-pptx (MIT) build test fixtures
(reportlab is now a runtime dependency); types-regex (Apache-2.0) provides type stubs; pytest (MIT), ruff (MIT), mypy (MIT), Vite (MIT), Vitest (MIT)
and Testing Library (MIT) are used for development and CI.

## Packaging (Phase 8)

| Component | Licence | Note |
| --- | --- | --- |
| PyInstaller (build only) | GPL-2.0-or-later with the bootloader exception | Freezes the engine. The bootloader inside `airlock-engine.exe` is covered by the exception, which allows shipping the result under any licence. PyInstaller itself is a build tool and is not shipped. |
| NSIS (via Tauri) | zlib/libpng | Installer runtime. |
| Microsoft Edge WebView2 Runtime | Microsoft Software License Terms | Installed by Microsoft's bootstrapper or offline installer when missing. |

`scripts/notices.py` writes `THIRD_PARTY_NOTICES.txt` into every installer:
each shipped Python package, Rust crate and npm package with its licence and
the licence texts it carries (about 300 components). It fails the build if a
Rust or npm component offers only a copyleft licence.
