# Airlock architecture

> The privacy layer between your data and AI.

Airlock is an offline-first Windows desktop application that detects and
neutralises sensitive company data **on the user's device** before a document
is shared with an external AI system. This document is the technical source of
truth. Product requirements live in the PRD; security is detailed in
[SECURITY.md](SECURITY.md), the engine protocol in [IPC.md](IPC.md), testing in
[TESTING.md](TESTING.md) and phase status in [ROADMAP.md](ROADMAP.md).

## 1. Non-negotiables

| Rule | How it is enforced |
| --- | --- |
| No external LLM, OCR or NER in the privacy pipeline | No such dependency exists; the engine installs a CPython audit hook that blocks all non-loopback DNS and socket connections at start-up (`engine/.../security/network_guard.py`). Tested in a network namespace with no network. |
| Works with the internet disabled | Same as above; all models ship inside the installer. |
| The original file is never modified | Adapters receive the source read-only and always write to a new destination; tests compare bytes and mtime before/after. |
| Sensitive values never reach logs | `SensitiveValue` wrapper (redacted `repr`/`str`/`format`, not JSON- or pickle-serialisable); allowlist-only structured logger in the engine; independent allowlist re-check in the host before anything is persisted. |
| Export only after verification | The verifier re-extracts the *exported artifact* and rescans it; export is refused if any protected entity remains (Phase 7). |

## 2. System overview

```
┌──────────────────────── Airlock.exe (Tauri host, Rust) ────────────────────────┐
│                                                                                │
│  WebView2 UI (React + TS)          Rust host                                   │
│  ┌─────────────────────┐  invoke   ┌──────────────────────────────────────┐    │
│  │ Drop zone, report,  │ ───────▶  │ commands.rs  (method allowlist)      │    │
│  │ review, export      │ ◀───────  │ engine.rs    (supervisor + JSON-RPC) │    │
│  └─────────────────────┘  events   │ logsink.rs   (content-free log file) │    │
│      no fs / no http               │ licensing    (Phase 10, Ed25519)     │    │
│                                    └──────────────┬───────────────────────┘    │
└───────────────────────────────────────────────────┼────────────────────────────┘
                                   stdin/stdout pipes│ JSON-RPC 2.0, one object per line
                                                     ▼
┌──────────────────── airlock-engine.exe (Python, frozen) ───────────────────────┐
│  network_guard ─ installed before anything else                               │
│                                                                               │
│  documents/*  ──▶ extraction ──▶ detectors/{regex,secrets,ner,custom}          │
│   (adapters)        │                    │                                    │
│                     │                    ▼                                    │
│                     │              policy ──▶ risk                            │
│                     │                    │                                    │
│                     │                    ▼                                    │
│                     └──────────────▶ masking ──▶ adapter.sanitize ──▶ verify  │
│                                                                               │
│  storage (SQLite: settings, rules, profiles, license cache, encrypted vault)  │
└───────────────────────────────────────────────────────────────────────────────┘
```

Two processes, no servers, no microservices:

* **Host (Rust/Tauri 2).** Owns the window, starts and supervises the engine,
  exposes a small allowlist of engine methods to the UI, persists a
  content-free log, and (later) handles licensing, the Windows shell
  integration and the single-instance file hand-off.
* **Engine (Python 3.11, frozen with PyInstaller).** Everything that touches
  document content: extraction, detection, policy, masking, verification,
  storage. It has no network access and no listening sockets.
* **UI (React + TypeScript in WebView2).** Presentation only. It never reads
  files and never sees raw sensitive values: the engine sends masked previews
  (`r••••@company.com`) and finding ids.

### Why Python for the engine

The document stack (PDF, OOXML), OCR and NER ecosystems are strongest in
Python, and the PRD calls for it. Python stays behind a narrow process
boundary, so a crash or hostile document in a native parser cannot take the UI
down, and the engine can be swapped component by component.

### Why stdio JSON-RPC instead of a local HTTP server

A localhost HTTP server would be reachable by every local process and, via DNS
rebinding, by web pages. It would need a token, and it may trigger firewall or
antivirus prompts. With stdio there is nothing to connect to: only the parent
holds the pipes. The same transport is what Chrome/Edge native messaging uses,
which suits the V2 browser extension. See [IPC.md](IPC.md).

## 3. Core flow

```
drop/open file ─▶ document.inspect  (path validation + magic-byte sniffing)
               ─▶ scan.start        (extract → detect → policy → risk; progress notifications)
               ─▶ report            (categories, risk, per-finding explanation, masked previews)
               ─▶ review            (user overrides: allow / mask / redact / block; "teach" → rule)
               ─▶ sanitize          (masker → adapter.sanitize → new file in a private temp dir)
               ─▶ verify            (re-extract the produced file, full rescan, residual-value check)
               ─▶ export / AI-safe copy   (only if verification passed and no BLOCK remains)
```

`scan.*`, `sanitize.*`, `verify.*` and `export.*` arrive in Phases 3–7.

## 4. Directory structure

```
Airlock/
├── apps/
│   ├── desktop/                     Tauri app
│   │   ├── src/                     React UI
│   │   │   ├── engine/              Platform abstraction (Tauri / preview), IPC types
│   │   │   ├── components/          DropZone, TrustBar, ErrorNotice, icons
│   │   │   └── styles/              Design tokens + app styles
│   │   └── src-tauri/               Rust host
│   │       ├── src/engine.rs        Engine supervisor + JSON-RPC client
│   │       ├── src/commands.rs      UI-facing commands (method allowlist)
│   │       ├── src/logsink.rs       Content-free persistent log
│   │       ├── src/locate.rs        Finds the bundled or dev engine
│   │       └── capabilities/        Minimal Tauri permissions
│   └── browser-extension/           V2 placeholder (architecture notes only)
├── engine/                          Python engine (uv project)
│   ├── src/airlock_engine/
│   │   ├── cli.py                   Entry point: guard → logging → stdio takeover → serve
│   │   ├── ipc/                     JSON-RPC protocol + threaded stdio server
│   │   ├── api/                     RPC method handlers (single registry)
│   │   ├── core/                    Data model, interfaces, SensitiveValue, user errors
│   │   ├── security/                Network guard, input-file validation
│   │   ├── documents/               Format registry/sniffing + one adapter per family
│   │   ├── extraction/              Adapter routing, worker isolation
│   │   ├── detectors/{regex,secrets,ner,custom}
│   │   ├── scan/                    In-memory scan sessions, content-free report
│   │   ├── masking/                 Replacements, value sweep, plan, vault, work folder
│   │   ├── storage/                 SQLite: settings, categories, rules, allow-list
│   │   ├── policy/  masking/  verification/  risk/
│   │   ├── clipboard/               V2 module boundary (empty)
│   │   └── safelog.py               Allowlist-only structured logging
│   └── tests/
├── licensing/                       Offline license issuer tooling (never shipped)
├── tests/                           Cross-component fixtures and end-to-end suites
├── docs/
└── .github/workflows/               CI
```

The PRD lists `documents/`, `storage/` and `licensing/` at the top level. In
this repository `documents/` and `storage/` live **inside** the engine package
because they are Python modules that must be frozen into one executable.
License *verification* lives in the Rust host (isolated from the privacy
engine, per PRD §29); the top-level `licensing/` holds the issuer tooling,
which is never shipped.

## 5. Technology decisions

| Area | Decision | Notes |
| --- | --- | --- |
| Desktop shell | **Tauri 2** + WebView2 | Small binary, Rust host, capability-scoped IPC. |
| UI | **React 19 + TypeScript**, Vite | Hand-built design tokens; system fonts (Segoe UI Variable), no CDN assets. |
| Engine | **Python 3.11**, stdlib-only core | Frozen with **PyInstaller `--onedir`** (no per-launch extraction, fewer AV false positives); bundled as Tauri resources. |
| IPC | **JSON-RPC 2.0 over stdio** | See IPC.md. |
| Storage | **SQLite** (stdlib `sqlite3`) | WAL mode, schema migrations, in `%LOCALAPPDATA%\com.airlock.desktop`. |
| Pseudonym vault | **AES-256-GCM** (`cryptography`), key wrapped with **Windows DPAPI** (`CryptProtectData`, current-user scope) | Keys never leave the machine; vault never in logs. |
| Licensing policy | **Open source, permissive licences only** (MIT/BSD/Apache/PSF; MPL-2.0 tolerated for unmodified use) | Enforced by `engine/tests/test_licenses.py`. No copyleft (GPL/AGPL/LGPL/SSPL) in the shipped app; see [THIRD_PARTY.md](THIRD_PARTY.md). |
| PDF | **pypdfium2** (PDFium; Apache-2.0/BSD-3) | Text, metadata, bookmarks, annotations, form values, links, attachments, rendering for OCR. Sanitized PDFs will be **rebuilt**, not edited in place (risk R1). |
| DOCX / XLSX / PPTX | **Direct OOXML part reading** with `defusedxml` (PSF) | Every ZIP part is visited, not just what a document library exposes: comments, tracked changes, notes, hidden sheets/rows/columns, orphaned shared strings, pivot caches, data connections, properties, custom XML, embedded files. python-docx/openpyxl/python-pptx are used only to build test fixtures. |
| OCR | **RapidOCR 3 (ONNX Runtime, PP-OCRv6 models)** behind `OcrProvider` | Apache-2.0; models ship inside the wheel; runs with the network guard on (verified: zero network attempts). Tesseract remains a possible alternative provider. |
| Document isolation | **One disposable worker process per document** (`multiprocessing` spawn) | Timeout, cancellation, memory cap (Windows Job Object / Linux `RLIMIT_AS`), network guard in the worker, JSON-only result channel (no pickle). |
| NER | **spaCy `en_core_web_sm`** behind `NerProvider` | OntoNotes labels map directly onto PERSON/ORG/LOCATION/MONEY/DATE/PRODUCT/EVENT. Upgrade path: `en_core_web_md`, or a GLiNER/BERT ONNX model, without touching the pipeline. |
| Licensing | **Ed25519** signed JSON licences, verified in Rust (`ed25519-dalek`) | Public key compiled in; private key offline. |
| Installer | Tauri **NSIS**, per-user install | WebView2 bootstrapper embedded; an offline-installer variant for air-gapped sites. |
| Python tooling | **uv** (lockfile), ruff, mypy `--strict`, pytest | |

### Dependencies by phase

| Phase | Engine (Python) | Host / UI |
| --- | --- | --- |
| 1 ✅ | stdlib only (dev: pytest, ruff, mypy) | tauri 2, tauri-plugin-dialog, serde_json; react, @tauri-apps/api, plugin-dialog (dev: vite, vitest, testing-library) |
| 2 ✅ | defusedxml, pypdfium2, pillow, rapidocr, onnxruntime, opencv-python-headless, numpy (dev: python-docx, openpyxl, python-pptx, reportlab for fixtures) | — |
| 3 ✅ | spacy + `en_core_web_sm` (bundled), phonenumbers, regex | — |
| 5 ✅ | cryptography (AES-GCM), reportlab (rebuilt PDFs); DPAPI through `ctypes` (no pywin32) | — |
| 7 | — | — |
| 8 | pyinstaller | NSIS via tauri-bundler, code-signing tooling |
| 9 | — | tauri-plugin-single-instance |
| 10 | — | ed25519-dalek, base64 |

Every dependency must work offline and be bundleable. Licences are checked for
commercial compatibility before adoption (AGPL/GPL is excluded from the
shipped binary).

## 5a. Document extraction (Phase 2)

```
document.extract(path)
  └─ validate (path, size, magic bytes)            engine process
  └─ spawn worker ──────────────────────────────── worker process (fresh interpreter)
        network guard → memory cap → read bytes → re-sniff (TOCTOU)
        adapter.extract(bytes, ctx)  ── emits TextSegments ──┐
          ├─ PDF:   pages, info/XMP, bookmarks, annotations, │  ctx enforces limits:
          │         form values, links, attachments (↻),     │  chars, segments, pages,
          │         OCR of scanned pages and pictures        │  OCR image count, depth
          ├─ OOXML: structured main parts + every other part │
          │         (generic walker), external links, media  │
          │         (OCR), embeddings (↻), macros (reported) │
          ├─ Text/CSV/config/code: encoding detection,       │
          │         per-cell segments with header context    │
          └─ Images: OCR per frame + EXIF/GPS/PNG text/XMP   │
        progress → JSON frames → engine → `$/progress`       │
  └─ ExtractedDocument (JSON, validated) ◀────────────────────┘
  └─ summarize → content-free summary to the UI
```

* **Segments** carry `kind` (body, comment, tracked_change, hidden,
  metadata, link, ...), a content-free `label` ("Sheet 2 · C14"), a locator
  for write-back, optional `context` (column header) and OCR `boxes`.
* **Nothing is silently skipped.** Parts that cannot be read are recorded as
  `unextracted` (macros, OLE objects, unreadable images, earlier PDF
  revisions, scripts) and shown to the user. Phase 5 removes them from safe
  copies.
* **Embedded files** (attachments, OLE packages, chart workbooks) are
  extracted recursively up to depth 2, with `!/`-prefixed locators.
* The extracted text never crosses IPC to the UI; `document.extract` returns
  only counts and labels. Phase 3 keeps the document in an engine-side scan
  session for detection.

## 5b. Detection (Phase 3)

```
scan.start(path)
  └─ extract_path (same isolated worker as document.extract)
  └─ DetectionEngine.run(document)                    engine process
        per segment:  regex detectors ── checksum / context validation
                      secret detector ── provider tokens, PEM, JWT, assigned secrets
                      company rules   ── exact / case-insensitive / normalized / alias / regex
        batched:      NER (spaCy, shared model, lock-guarded)
        allow-list filter (keyed HMAC of the value)
        resolve: merge duplicates; checksum beats context guess; any
                 deterministic match beats overlapping NER
  └─ ScanSession (engine memory, TTL 30 min, max 4) ── scan_id
  └─ report: findings with masked previews + content-free summary → UI
```

* **Entity catalogue** (`detectors/entities.py`): every built-in entity type
  has a label, report category, default severity and *quality class*
  (secret, checksummed id, contact, contextual id, company rule, NER). The
  quality class selects the precision/recall gate and the overlap strength.
* **Validation over pattern-matching.** Aadhaar uses Verhoeff, GSTIN its
  mod-36 check character, cards Luhn plus brand ranges, IBAN mod-97, phones
  libphonenumber metadata. Ids without a checksum (bank account, date of
  birth, contiguous Aadhaar) require a context keyword nearby or in the
  column header; reference-number context ("Order", "Invoice", "Ref") vetoes
  bare phone-like numbers.
* **Detection is separate from decision.** Detectors only say *what* a span
  is and how sure they are. Overlap resolution in this phase is limited to
  detection quality; choosing actions for overlapping findings of different
  types is Phase 4.
* **Company rules** compile into one alternation per kind (so thousands of
  terms stay fast) and match on a normalized copy of the text with an
  offset map back to the original. Regex rules use the `regex` module with
  a 250 ms per-segment timeout; a rule that times out three times is
  skipped for the rest of the document and the report says so.
* **NER** is optional at run time: if the model cannot load, scanning
  continues without it and the report says names were not checked. Text
  beyond 3 M characters per document is not sent to NER (reported as
  partial).
* **What leaves the engine**: finding id, entity type and label, category,
  severity, confidence, detector id, a masked preview (credentials show at
  most a public prefix such as `ghp_`; card, Aadhaar, account and IBAN show
  the last four characters), the structural location label, and whether
  the location is hidden. Raw values stay in the scan session.

## 5c. Policy (Phase 4)

```
Detected (Phase 3) ──▶ PolicyEngine.decide(items, profile, overrides)
                         per finding: override │ rule action │ profile entity
                                      │ company-rule │ category │ default
                                      + confidence threshold, GENERALIZE fallback
                         overlaps → regions (union span, strongest action)
                     ──▶ PolicyDecision {findings[Finding], regions[Region], blocked}
```

* **Profiles** (`policy/profiles.py`): Company Default, Strict and Secrets
  & IDs only are built in and immutable; custom profiles (`storage/profiles.py`)
  name their built-in base and store only their differences in
  `policy_rules`. The user's default profile is a setting.
* **Credentials default to BLOCK** in every built-in profile. BLOCK means the
  document cannot be shared as is until the user chooses another action;
  Phase 7 enforces it at export.
* **Explainable**: each `Finding` carries `policy_reason`, a short sentence
  naming the profile or rule that decided it, and never the value.
* **Regions** are the masker's input (Phase 5): non-overlapping spans per
  segment with one action and the primary finding's type and mask style.
* **Overrides** live in the scan session only. They target a finding or a
  value group, so one decision covers every occurrence of the same value.

## 5d. Masking and protected copies (Phase 5)

```
sanitize.run(scan_id)
  └─ build_plan(document, decision)                        engine
        edits  (segment, start, end, replacement)  — every region
        sweep  (value → replacement)                — regions and covered findings
        paint  (image part, frame, boxes | whole)   — OCR text cannot be edited
        vault  (replacement → original, type)       — reversible replacements only
  └─ worker: read original, check SHA-256 against the scan
        format sanitizer ─ text | OOXML token rewriter | image painter | PDF rebuild
        second sweep pass (no word edges) for values never found
        write <data dir>/work/<artifact>.<ext>  (exclusive create, 0600)
  └─ vault record (AES-256-GCM, key wrapped by DPAPI)       engine
  └─ result: counts, removed hidden content, vault status (no content)
```

* **Plan vs. execution.** The engine decides every replacement; the worker
  only applies them. The plan holds original values, so it travels only over
  the worker's private pipe.
* **Write-back mirrors extraction.** The OOXML rewriter walks the same text the
  extractor read (paragraph runs, rich-text strings, leaf text, human-text
  attributes, external relationship targets), so anything detected can be
  replaced. It edits only the bytes that change, so namespace prefixes and
  `mc:Ignorable` lists survive, and every rewritten part must parse again.
* **What cannot be checked is removed.** Macros, thumbnails, unreadable
  pictures and embedded objects do not reach the copy (removed, blanked or
  emptied), which closes risk R2 for content Airlock cannot read.
* **PDFs are rebuilt** (risk R1): masked page text only.
* **Copies are not yet trusted.** Phase 7 re-extracts and rescans each copy
  before it can be saved; until then copies stay in the private work folder.
* **Reversibility** is recorded per copy in the vault; restoring AI responses
  in the UI, session-scoped mappings and `PERSON_001`-style placeholders are
  Phase 12 ([REVERSIBLE_MASKING.md](REVERSIBLE_MASKING.md)).

## 6. Data model

### 6.1 In-memory (engine)

Defined in `engine/src/airlock_engine/core/models.py`:

* `ExtractedDocument(format, segments[TextSegment], unextracted_parts, ocr_used)`
* `TextSegment(segment_id, text, locator: Locator(part, path))`. The locator
  lets an adapter write a replacement back to the exact place it came from
  (a PDF block, an XLSX cell, a PPTX notes paragraph).
* `DetectionResult(entity_type, matched_value: SensitiveValue, segment_id,
  start, end, confidence, detector, rule_id, severity)`
* `Finding(finding_id, detection, category, action, policy_reason,
  corroborating_detectors)`. Detection plus decision; the two stay separate types.
* `Replacement(segment_id, start, end, replacement_text)`

Scan sessions live **only in engine memory**, keyed by `scan_id` with a TTL,
and are wiped on `scan.discard`, on export, or on engine exit. The UI receives
`finding_id` + masked preview, never the raw value.

### 6.2 Persistent (SQLite, Phase 3+)

```sql
CREATE TABLE schema_version (version INTEGER NOT NULL);

CREATE TABLE settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL                -- JSON
);

CREATE TABLE privacy_profiles (
  id          TEXT PRIMARY KEY,      -- 'company-default', ...
  name        TEXT NOT NULL,
  is_builtin  INTEGER NOT NULL DEFAULT 0,
  created_at  TEXT NOT NULL,
  updated_at  TEXT NOT NULL
);

CREATE TABLE policy_rules (          -- entity type → action, per profile
  profile_id  TEXT NOT NULL REFERENCES privacy_profiles(id) ON DELETE CASCADE,
  entity_type TEXT NOT NULL,         -- 'EMAIL', 'API_KEY', 'INTERNAL_PROJECT', custom...
  action      TEXT NOT NULL CHECK (action IN ('ALLOW','MASK','REDACT','GENERALIZE','BLOCK')),
  mask_style  TEXT NOT NULL DEFAULT 'typed_placeholder',
  PRIMARY KEY (profile_id, entity_type)
);

CREATE TABLE categories (            -- built-in + custom categories
  id         TEXT PRIMARY KEY,       -- 'INTERNAL_PROJECT'
  label      TEXT NOT NULL,
  group_name TEXT NOT NULL,          -- PERSONAL / FINANCIAL / BUSINESS / ...
  severity   INTEGER NOT NULL,       -- 1..4
  is_builtin INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE custom_rules (          -- "teach Airlock": company-specific terms
  id          TEXT PRIMARY KEY,
  kind        TEXT NOT NULL CHECK (kind IN ('exact','case_insensitive','normalized','regex')),
  pattern     TEXT NOT NULL,         -- sensitive by nature: see note below
  category_id TEXT NOT NULL REFERENCES categories(id),
  action      TEXT,                  -- NULL = use the profile's policy for the category
  enabled     INTEGER NOT NULL DEFAULT 1,
  created_at  TEXT NOT NULL
);

CREATE TABLE custom_rule_aliases (
  rule_id TEXT NOT NULL REFERENCES custom_rules(id) ON DELETE CASCADE,
  alias   TEXT NOT NULL,
  PRIMARY KEY (rule_id, alias)
);

CREATE TABLE allow_list (            -- "not sensitive" decisions
  id         TEXT PRIMARY KEY,
  value_hmac TEXT NOT NULL UNIQUE,   -- keyed hash, not the value itself
  entity_type TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE license (               -- cache of the verified licence (host-owned)
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  license_json TEXT NOT NULL,
  signature    TEXT NOT NULL,
  verified_at  TEXT NOT NULL
);
```

Implemented in `engine/src/airlock_engine/storage/db.py` (migration v1;
v2 adds `base_id`, `min_confidence` and `mask_style` to `privacy_profiles`).
Two deviations from the sketch above: `custom_rules` also has `updated_at`,
and `allow_list` is unique on `(value_hmac, entity_type)` rather than on the
hash alone, so a value can be allowed as one type but not another. The engine
opens the database lazily in the folder passed by the host (`--data-dir`, the
Tauri app-local-data folder); `--memory-only` keeps rules in memory.

Custom rule patterns are themselves confidential (for example "Project
Phoenix"). The database file lives in the per-user profile with a user-only
ACL. The pseudonym vault is a **separate** encrypted file
(`vault.bin`, AES-256-GCM, DPAPI-wrapped key) and is never stored in SQLite
in plaintext. Original documents are never stored.

The future ML path (PRD §13) adds a `labelled_examples` table fed by explicit
user decisions. No training happens in V1.

## 7. Interfaces

Defined in `engine/src/airlock_engine/core/interfaces.py`:

```python
class DocumentAdapter(ABC):
    formats: tuple[str, ...]
    def extract(self, source: Path) -> ExtractedDocument: ...
    def sanitize(self, source, document, replacements, destination) -> None: ...

class Detector(ABC):
    name: str                                    # "regex.email"
    def detect(self, segment: TextSegment) -> Iterable[DetectionResult]: ...

class NerProvider(ABC):                          # replaceable model
    def load(self, model_dir: Path) -> None: ... # local weights only
    def entities(self, text: str) -> Sequence[NerEntity]: ...

class OcrProvider(ABC):
    def recognize(self, image_png: bytes, locator: Locator) -> Sequence[TextSegment]: ...
```

Planned for later phases (shape fixed now, code later):

```python
class PolicyEngine:   def decide(self, items, profile, overrides) -> PolicyDecision   # ✅ Phase 4
class Masker:         build_plan(document, decision) -> MaskPlan     # ✅ Phase 5 (masking/masker.py)
class RiskScorer:     def score(self, findings) -> RiskReport          # deterministic, explainable
class Verifier:       def verify(self, original_findings, produced_file) -> VerificationReport
```

`can_handle` from the PRD sketch is replaced by the format registry: the
validator sniffs the bytes, resolves exactly one `FormatSpec`, and the
registry maps it to one adapter. Format logic therefore never leaks into the
pipeline.

## 8. Major risks

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | **PyMuPDF is AGPL-3.0.** | **Resolved (open-source-only decision):** pypdfium2 for extraction and rendering; sanitized PDFs will be rebuilt (Phase 5/7) rather than redacted in place. |
| R2 | **Hidden-content leakage**: metadata, comments, tracked changes, speaker notes, hidden sheets, embedded objects, cached pivot data and alt text survive sanitisation. | Phase 2 extracts every text-bearing part (canary tests cover each location per format) and reports what it cannot read (macros, OLE objects, PDF revisions, scripts). The verifier additionally runs a **raw sweep** over every XML part of the output package, plus a check that no original finding value (normalised) appears anywhere in the output bytes. Unextractable parts are dropped from the output. |
| R3 | **Verification is circular** if it only reuses the same detectors. | Two independent checks: a fresh full detection pass **and** a literal residual-value search for every original finding (case, whitespace and separator normalised). |
| R4 | **NER is probabilistic**, and weak on Indian names in English text. | NER findings are labelled with confidence. Deterministic and company-rule detectors carry the guarantees. Custom dictionaries cover known names and customers. The model can be upgraded behind `NerProvider`. |
| R5 | **Packaging size and start-up** (spaCy + ONNX Runtime + PDF libs ≈ 250–350 MB); onefile extraction is slow and flagged by antivirus. | PyInstaller `--onedir` bundled as Tauri resources; lazy-load NER/OCR on first use; warm-start the engine at launch. |
| R6 | **SmartScreen / AV reputation** for an unsigned `.exe`. | Authenticode signing (OV/EV certificate) of the installer, host and engine executables from Phase 8. |
| R7 | **WebView2 on clean or offline machines.** | Windows 11 ships it. The default installer embeds the bootstrapper; an offline installer variant embeds the full runtime. |
| R8 | **Windows 11 context menu**: classic registry verbs only appear under "Show more options". | V1: per-user registry verb (works everywhere). V1.x: `IExplorerCommand` handler with sparse-package identity for the modern menu. |
| R9 | **Hostile documents**: zip bombs, XML entity expansion, decompression bombs, parser crashes in native code. | Implemented in Phase 2: size/entry/ratio limits, `defusedxml` (DTDs and entities forbidden), Pillow pixel limits, and a disposable worker per document with timeout, cancellation and memory cap. Mutation fuzzing in CI. |
| R10 | **False positives** (bank-account-like numbers, invoice ids) erode trust. | Checksums where they exist (Verhoeff, Luhn, GSTIN mod-36), context keywords for checksum-less ids, per-detector precision/recall gates in CI. |
| R11 | **Placeholder collisions** (`PERSON_001` already present in the text). | Track issued placeholders per session and exclude only those from verification; detect pre-existing collisions and suffix them. |
| R12 | **Legacy formats** (.doc, .xls, .ppt, .rtf, ODF) have weak pure-Python support. | Recognised with precise "convert first" errors in V1; .xls via xlrd and ODF via odfpy as V1.x candidates. |
