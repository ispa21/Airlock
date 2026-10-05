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
│   │   ├── policy/  masking/  verification/  risk/  storage/
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
| PDF | **pypdfium2** (Apache-2.0/BSD) for text + rendering | Sanitized PDFs are **rebuilt**, not edited in place (see risk R1). PyMuPDF only if a commercial licence is purchased. |
| DOCX / XLSX / PPTX | python-docx, openpyxl, python-pptx + direct OOXML part handling via `defusedxml` | Covers comments, notes, headers/footers, hidden sheets, metadata. |
| OCR | **RapidOCR (ONNX Runtime, PP-OCR models)** behind `OcrProvider` | pip-installable, no external binary. Tesseract is the alternative provider. |
| NER | **spaCy `en_core_web_sm`** behind `NerProvider` | OntoNotes labels map directly onto PERSON/ORG/LOCATION/MONEY/DATE/PRODUCT/EVENT. Upgrade path: `en_core_web_md`, or a GLiNER/BERT ONNX model, without touching the pipeline. |
| Licensing | **Ed25519** signed JSON licences, verified in Rust (`ed25519-dalek`) | Public key compiled in; private key offline. |
| Installer | Tauri **NSIS**, per-user install | WebView2 bootstrapper embedded; an offline-installer variant for air-gapped sites. |
| Python tooling | **uv** (lockfile), ruff, mypy `--strict`, pytest | |

### Dependencies by phase

| Phase | Engine (Python) | Host / UI |
| --- | --- | --- |
| 1 (now) | stdlib only (dev: pytest, ruff, mypy) | tauri 2, tauri-plugin-dialog, serde_json; react, @tauri-apps/api, plugin-dialog (dev: vite, vitest, testing-library) |
| 2 | pypdfium2, python-docx, openpyxl, python-pptx, defusedxml, Pillow, rapidocr-onnxruntime | — |
| 3 | spacy + `en_core_web_sm` (bundled) | — |
| 5 | cryptography, pywin32 (DPAPI) | — |
| 7 | reportlab (rebuild safe PDFs) | — |
| 8 | pyinstaller | NSIS via tauri-bundler, code-signing tooling |
| 9 | — | tauri-plugin-single-instance |
| 10 | — | ed25519-dalek, base64 |

Every dependency must work offline and be bundleable. Licences are checked for
commercial compatibility before adoption (AGPL/GPL is excluded from the
shipped binary).

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
class PolicyEngine:   def decide(self, detections, profile) -> list[Finding]
class Masker:         def replacements(self, findings, style, vault) -> list[Replacement]
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
| R1 | **PyMuPDF is AGPL-3.0.** Shipping it in a closed-source product requires a commercial licence from Artifex. | Default to pypdfium2 (permissive) for extraction and rendering, and **rebuild** sanitized PDFs rather than redacting in place. Revisit if a PyMuPDF licence is bought (true in-place redaction with layout). The adapter boundary makes the swap local. |
| R2 | **Hidden-content leakage**: metadata, comments, tracked changes, speaker notes, hidden sheets, embedded objects, cached pivot data and alt text survive sanitisation. | Adapters must extract every text-bearing part. The verifier additionally runs a **raw sweep** over every XML part of the output package, plus a check that no original finding value (normalised) appears anywhere in the output bytes. Unextractable parts are dropped from the output. |
| R3 | **Verification is circular** if it only reuses the same detectors. | Two independent checks: a fresh full detection pass **and** a literal residual-value search for every original finding (case, whitespace and separator normalised). |
| R4 | **NER is probabilistic**, and weak on Indian names in English text. | NER findings are labelled with confidence. Deterministic and company-rule detectors carry the guarantees. Custom dictionaries cover known names and customers. The model can be upgraded behind `NerProvider`. |
| R5 | **Packaging size and start-up** (spaCy + ONNX Runtime + PDF libs ≈ 250–350 MB); onefile extraction is slow and flagged by antivirus. | PyInstaller `--onedir` bundled as Tauri resources; lazy-load NER/OCR on first use; warm-start the engine at launch. |
| R6 | **SmartScreen / AV reputation** for an unsigned `.exe`. | Authenticode signing (OV/EV certificate) of the installer, host and engine executables from Phase 8. |
| R7 | **WebView2 on clean or offline machines.** | Windows 11 ships it. The default installer embeds the bootstrapper; an offline installer variant embeds the full runtime. |
| R8 | **Windows 11 context menu**: classic registry verbs only appear under "Show more options". | V1: per-user registry verb (works everywhere). V1.x: `IExplorerCommand` handler with sparse-package identity for the modern menu. |
| R9 | **Hostile documents**: zip bombs, XML entity expansion, decompression bombs, parser crashes in native code. | Size limits, entry-count limits, `defusedxml`, Pillow pixel limits, and extraction in a disposable worker process with timeout and memory limit (Job Object). A host-level crash only restarts the engine. |
| R10 | **False positives** (bank-account-like numbers, invoice ids) erode trust. | Checksums where they exist (Verhoeff, Luhn, GSTIN mod-36), context keywords for checksum-less ids, per-detector precision/recall gates in CI. |
| R11 | **Placeholder collisions** (`PERSON_001` already present in the text). | Track issued placeholders per session and exclude only those from verification; detect pre-existing collisions and suffix them. |
| R12 | **Legacy formats** (.doc, .xls, .ppt, .rtf, ODF) have weak pure-Python support. | Recognised with precise "convert first" errors in V1; .xls via xlrd and ODF via odfpy as V1.x candidates. |
