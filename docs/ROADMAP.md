# Roadmap and phase status

Each phase follows **implement → test → run → fix → document**. A phase is
done when its exit criteria pass on a real run, not when it compiles.

| Phase | Scope | Exit criteria | Status |
| --- | --- | --- | --- |
| 0 | Architecture and repository setup | Docs (architecture, IPC, security, testing, roadmap); monorepo layout; tooling (uv, ruff, mypy, cargo, vite, vitest); CI | ✅ Done |
| 1 | Desktop shell + Python engine + IPC | Tauri app spawns the engine, handshake with version check, allowlisted calls, structured errors, crash restart, graceful shutdown, no orphans, network guard, content-free logs, main screen UI, file drop/browse with validation | ✅ Done |
| 2 | Document extraction | Adapters for PDF, DOCX, XLSX, CSV, TXT, PPTX, then images (OCR), config files and code. Hidden parts extracted. Worker-process isolation. Malformed-file and fuzz suites | ✅ Done |
| 3 | Detection | Regex detectors with checksums (Email, Phone, PAN, Aadhaar, GSTIN, bank account, IFSC, card, IP, URL); secret detectors; spaCy NER provider; company rules (exact, case-insensitive, normalized, alias, regex); SQLite storage; quality gates | ✅ Done |
| 4 | Policy | Profiles, entity → action mapping, defaults (credentials → BLOCK), overlap resolution, user overrides | ✅ Done |
| 5 | Masking | Redaction, placeholder, typed placeholder, synthetic replacement, generalisation, reversible encrypted vault (DPAPI + AES-GCM), adapter `sanitize` for each format | ✅ Done |
| 6 | Privacy report | Category summary, deterministic explainable risk, per-finding detector/confidence/action, partial masking, "teach Airlock" flow | ✅ Done |
| 7 | Verification and export | Re-extract the produced artifact, rescan, residual-value check, raw OOXML sweep, block on failure, safe export, AI-safe copy | ✅ Done |
| 8 | Windows packaging (in progress) | PyInstaller onedir engine, NSIS installer, WebView2 strategy, code signing, firewall rule option, tauri-driver E2E on Windows, clean-VM DoD run | |
| 9 | ~~Right-click integration~~ | Skipped by decision (2026-10-05): files are opened by drag-and-drop or Browse in every surface | ⏭ Skipped |
| 10 | Lifetime licensing | Ed25519 signed licences, offline import, online activation (isolated from the engine), local verification | |
| 11 | Browser extension foundation | MV3 extension for Chrome and Edge. Uses the local app's engine through native messaging when it is installed, otherwise the in-browser engine from Phase 14 | |
| 12 | Reversible masking & response restoration (queued) | Session/conversation-scoped mapping vault, stable `PERSON_001`-style pseudonyms, local restoration of AI responses (review before restore), outbound privacy check, prompt and clipboard protection, provider-neutral AI adapter layer. Requirements: [REVERSIBLE_MASKING.md](REVERSIBLE_MASKING.md) | |
| 13 | Local web app | The installed engine serves the same UI to the user's own browser on a loopback address: 127.0.0.1 only, random port, per-launch secret, Host and Origin checks, the same method allowlist as the desktop host. No document leaves the computer | |
| 14 | Web app (in the browser) | A static website where the engine runs inside the user's browser (WebAssembly in a Web Worker). Files are never uploaded; the site works offline after the first visit. Measure and document what is lighter than the desktop app (language model, OCR, very large files) | |

## Delivery surfaces

Airlock ships as four surfaces. In all of them documents are processed on the
user's own device and are never uploaded; there is no cloud processing.

| Surface | Where the engine runs | How the UI reaches it | Phase |
| --- | --- | --- | --- |
| Local app (desktop) | Bundled Python engine, child process of the app | Tauri host, stdio JSON-RPC (no socket) | 1-8 (1-7 done) |
| Local web app | Same installed engine | User's browser → loopback HTTP with a per-launch secret | 13 |
| Web app | Inside the user's browser (WebAssembly, Web Worker) | In-page messages; the website only serves static files | 14 |
| Browser extension | Local app's engine (native messaging) or the in-browser engine | Extension pages | 11 |

The React UI is shared: each surface supplies its own `Platform`
implementation (`apps/desktop/src/engine/platform.ts`), as the desktop app
and the browser preview already do. Order after Phase 7 can be changed.

## Phase 1 verification log

Run in this repository's development container (Linux, Xvfb):

* Engine: 67 tests pass (1 IPv6 case skipped where no IPv6 stack exists);
  ruff and mypy `--strict` clean. The **same suite passes inside a network
  namespace with no network** (`unshare -n`, loopback only).
* Host: 10 Rust tests pass against the real engine and fake engines (crash,
  restart budget, incompatible handshake, timeout, missing binary); clippy
  `-D warnings` clean.
* UI: 7 component tests pass; production build contains no preview mock and
  no external URLs.
* Real app (`tauri build --debug --no-bundle`, run under Xvfb + openbox):
  * launches, spawns the engine, handshake succeeds, shows "Processing locally";
  * valid DOCX chosen through the native dialog → verified (format, size);
  * `.pdf` that is really an executable → rejected with an explanation and
    "Your original file was not changed";
  * engine killed mid-session → next action transparently restarts it;
  * window closed → `system.shutdown`, engine exits, no processes left;
  * host hard-killed → engine exits on stdin EOF (no orphan);
  * persisted log contains only allowlisted events: no file names, paths or
    content.

Not yet verified on Windows (no Windows runner in this environment). The CI
workflow builds and tests the host on `windows-latest`. Packaging and
clean-VM runs are Phase 8.

## Phase 2 verification log

* Formats: PDF, DOCX/DOCM, XLSX/XLSM, PPTX/PPTM, CSV, TSV, TXT/MD/LOG,
  JSON, YAML, XML, TOML, INI, ENV, 20 source-code types, PNG, JPEG, WebP,
  multi-page TIFF; scanned PDFs and embedded pictures via local OCR.
* Canary tests: a unique marker planted in every hidden location is found,
  with the right kind. That covers 15 DOCX locations (tracked deletions,
  text boxes, docVars, custom XML, embedded workbook, ...), 15 XLSX
  (hidden rows/cols/sheets, orphaned shared strings, pivot cache, connection
  password, ...), 9 PPTX (notes, hidden slide, chart data, comments, ...),
  8 PDF (form values, annotations, bookmarks, attachment, ...) and image
  EXIF/GPS/PNG-text.
* Hostile input: zip bomb, >20k entries, billion-laughs XML, decompression
  bomb, truncated and corrupted files, and 450 mutated files per run. Every one
  yields a result or an actionable error, and none escapes as a raw exception.
* Isolation: crash, segfault, hang (timeout), memory blow-up, network
  attempt and cancellation inside the worker are all contained.
* Engine 176 tests (+1 IPv6 case skipped here), host 12 tests, UI 11 tests; ruff, mypy `--strict`,
  clippy `-D warnings` clean. Licence policy test: all runtime dependencies
  permissive.
* Real app (Linux, Xvfb): scanned a DOCX with every hidden part (report
  shows 19 easy-to-miss items and the macro project as unreadable), a
  scanned PDF (OCR), cancelled a scan mid-way, and was shown a clear error
  for a password-protected PDF. Originals byte-identical afterwards; the log
  held only structured events (0 matches for content, names or paths); no
  processes left after closing.

Known limits carried forward: legacy binary Office (.doc/.xls/.ppt), RTF,
ODF and e-mail formats are recognised but not read; OLE-embedded objects
other than OOXML/PDF are reported as unreadable; OCR is tuned for printed
Latin script (Devanagari OCR is a V1.x candidate).

## Phase 3 verification log

* Detectors: e-mail, phone (libphonenumber metadata, Indian and
  international), IPv4/IPv6, URL, date of birth (context-gated), PAN
  (structure), Aadhaar (Verhoeff), GSTIN (mod-36), IFSC, bank account
  (context-gated), payment card (Luhn + brand ranges), IBAN (mod-97); secrets:
  PEM private keys, AWS, GitHub, GitLab, Slack, Stripe, Google, OpenAI,
  Anthropic, SendGrid, Twilio, npm, Azure keys and SAS, JWTs, bearer tokens,
  credentials in URLs and connection strings, and secrets assigned to
  secret-named keys (placeholders such as `${VAR}` or `changeme` ignored).
* NER: spaCy `en_core_web_sm` behind `NerProvider`, loaded from the bundled
  package with the network guard on (verified: zero blocked attempts). Maps
  to PERSON, ORGANIZATION, LOCATION, MONEY, PRODUCT, EVENT with confidence
  below the deterministic detectors; deterministic matches suppress
  overlapping NER spans.
* Company rules: exact, case-insensitive, normalized (case, accents,
  full-width forms and separators), aliases and regex (per-segment timeout;
  a rule that times out 3 times is skipped for the rest of the document).
* Storage: SQLite (WAL, migrations, user-only file) with the schema from
  ARCHITECTURE §6.2; rules CRUD over `rules.*`; allow-list stored as keyed
  HMACs only.
* Quality gates: all gated entity types at recall 1.00 / precision 1.00 on
  the 1,452-sample tuning corpus (984 labelled values, 468 negatives) **and**
  on a separately written held-out set of 90 realistic documents (345
  labelled values). Company-rule gate 1.00/1.00. The corpus values are
  synthetic, so these numbers measure the detectors' logic, not real-world
  recall; NER is tracked without a gate.
* Engine 273 tests (+1 IPv6 case skipped here), host 13 tests, UI 14 tests;
  ruff, mypy `--strict`, clippy `-D warnings` clean; licence policy test
  passes with spaCy, phonenumbers and regex.
* Real app (Linux, Xvfb): scanned a DOCX with PII in the body, a comment and
  the document properties plus a company term: 12 findings, 5 flagged as
  hidden, masked previews only; scanned a `.env` (password and AWS key
  critical). The run found and fixed one bug the corpus had missed (ids
  followed by a comma, "account no 5707536455, IFSC…", were skipped); a
  regression test and corpus templates were added. Originals byte-identical;
  log held only allowlisted events (no values, names, labels or paths);
  database held no document values; no processes left after closing.

Known limits carried forward: NER is English-only and weaker on Indian names
(company rules are the guarantee); PAN has no public checksum, so it is
validated structurally; bank account numbers and dates of birth need a
context keyword or column header.

## Phase 4 verification log

* Profiles: three built-ins (Company Default, Strict, Secrets & IDs only)
  defined in code, and custom profiles stored in SQLite as a copy of a
  built-in plus their own entity → action choices (schema v2 migration,
  verified in place on a Phase 3 database in the real app). Credentials are
  BLOCK in every built-in profile; company-rule matches are enforced in every
  profile; a rule's own action beats the profile.
* Resolution order: user override → company rule action → profile entity
  action → profile company-rule action → category action → default. Findings
  below the profile's confidence threshold are kept (credentials and company
  rules never are). GENERALIZE falls back to MASK for types with no coarser
  form. Every decision carries a content-free reason ("Company Default masks
  government ids.").
* Overlaps: overlapping findings merge (transitively) into one region with
  the strongest action (BLOCK > REDACT > MASK > GENERALIZE > ALLOW); the
  other members are marked `covered_by`. Regions are what Phase 5 masks.
* Overrides: per scan, by finding or by value group (every occurrence of the
  same value), never persisted. Keeping a critical or credential finding
  requires `acknowledge_risk`; the UI asks first. Switching profile on a
  finished scan keeps the user's own decisions.
* Engine 298 tests (+1 IPv6 case skipped here), host 13 tests, UI 18 tests;
  ruff, mypy `--strict`, clippy `-D warnings` clean.
* Real app (Linux, Xvfb): profiles loaded from the engine; the DOCX scan
  showed the GitHub token blocked with a "1 item is blocked" banner; changed
  it to Redact (banner cleared, counts updated); choosing Keep on the Aadhaar
  number asked for confirmation and Cancel left it masked; switching to
  Strict re-applied the profile without rescanning and kept the token
  override. Originals byte-identical; log held only allowlisted events;
  database held no document values; no processes left after closing.

Not done in this phase: a screen for creating and editing custom profiles
(the `profiles.*` methods exist; the UI only selects profiles). That screen
belongs with the "teach Airlock" flow in Phase 6.

## Phase 5 verification log

* Masking: typed placeholders (`[EMAIL_1]`, consistent per value, numbering
  skips placeholders already in the file), generic placeholders, synthetic
  values from reserved ranges (`example.invalid`, `192.0.2.x`, `2001:db8::`),
  redaction (`[REDACTED]`) and generalisation (date of birth → year, e-mail →
  domain, phone → country code, IP → subnet, URL → host, amount → rounded).
  Custom category names never appear in placeholders.
* Value sweep: every protected value is replaced wherever it is stored, not
  only where it was detected. Short plain words match on word edges; ids,
  secrets, e-mail addresses and names match anywhere; a value never found is
  swept again without edges.
* Sanitizers (isolated worker, original checked by SHA-256 against the scan):
  text/config/code/CSV (same encoding, BOM and line endings); DOCX/XLSX/PPTX
  through a byte-preserving token rewriter (runs joined, namespace prefixes and
  `mc:Ignorable` intact, numeric cells and pivot items become text, external
  link targets, human-text attributes, every rewritten part re-parsed);
  macros and thumbnails removed with their relationships; unreadable pictures
  blanked (valid EMF/WMF/PNG blanks); unreadable embedded objects emptied;
  embedded Office files sanitised recursively; author fields cleared; images
  painted over OCR line boxes and rebuilt from pixels (no EXIF/GPS/XMP/ICC);
  PDFs rebuilt from masked text with reportlab (hidden PDF content dropped).
* Vault: AES-256-GCM record per copy (placeholder, original, entity type),
  record id as associated data, key wrapped by DPAPI on Windows (ctypes) or a
  user-only key file elsewhere; 30-day retention; `vault.restore` restores
  only known placeholders. The allow-list key moved under the same protector
  (Phase 3 plain keys migrated).
* Work folder: `<data dir>/work`, user-only; swept at start-up, emptied on
  exit, scan discard and copy discard.
* Leak tests: a canary in every hidden location of DOCX, XLSX, PPTX, PDF
  (with a scanned page), PNG, CSV and ENV; after protection no canary in the
  copy's bytes (every ZIP part decompressed, recursively), in a re-extraction
  of the copy with OCR, in the log, in IPC responses or in the database; the
  original is unchanged; the copy is user-only and is deleted on discard.
* Engine 367 tests (+1 IPv6 and 1 Windows-only DPAPI case skipped here), host
  13 tests, UI 20 tests; ruff, ruff format, mypy `--strict`, clippy clean.
* Real app (Linux, Xvfb): the token blocked the copy until set to Redact; the
  protected DOCX had all 8 sensitive values replaced (checked against the
  original's XML), the IFSC code kept as the profile allows, author cleared,
  thumbnail removed; on closing, the work folder was empty and the encrypted
  vault record remained; originals unchanged; log and database clean.
* CI: Phase 3 and 4 commits had failed CI on `ruff format --check`, which
  also hid a Windows-only failure (the isolation test's simulated segfault
  raised `OSError` under ctypes instead of crashing). Both fixed. CI is now
  green on Linux and Windows: the engine suite (367 tests) passes on
  `windows-latest`, including the DPAPI round-trip of the vault key.

Known limits carried forward: the rebuilt PDF loses layout and pictures (by
design) and renders scripts outside the Vera font (e.g. Devanagari) as boxes
until Phase 8 bundles a broader font; Excel may repair pivot caches whose
numeric items became text; the restore UI is part of Phase 12; the copy is
not yet verified or saveable (Phase 7).

## Phase 6 verification log

* Risk: a deterministic 0-100 score as a sum of named, capped factors
  (ARCHITECTURE.md §5e), shown twice: the document as it is, and what the
  protected copy would still share (kept findings plus anything still
  blocked). "Why this score?" lists every factor with its points and a
  content-free detail ("3 distinct values found 3 times").
* Report: findings grouped by category (count, distinct values, highest
  severity, what will happen to them); every finding explains which rule
  matched (checksum, format, context word, company rule, language model) and
  which other detectors agreed, next to the policy reason.
* Partial masking: a fourth mask style that keeps the last 4 letters or
  digits, initials, or an e-mail's first letter and domain. Per finding
  ("Mask partly") or per data type in a custom profile (schema v3
  `profile_styles`). Not reversible; never for credentials.
* Teach Airlock: "It's not sensitive" (allow-list fingerprint) or "Always
  protect it" (company rule) from any finding except credentials and
  company-rule matches; the open scan refreshes on the text already in memory
  and keeps the user's decisions. Settings screen: company rules (add, turn
  on/off, delete), profiles (duplicate a built-in, rename, action and mask
  style per data type, make default, delete), and "Forget all" for the
  allow-list; closing it refreshes the open scan.
* Engine 404 tests (+1 IPv6 and 1 Windows-only DPAPI case skipped here), host
  13 tests, UI 30 tests; ruff, ruff format, mypy `--strict` (also for
  `win32`), clippy clean.
* Real app (Linux, Xvfb), on the Phase 5 data folder: schema migrated v2 → v3
  in place; the DOCX scored 100 (critical) as it is and 73 (high) for the
  protected copy while the token was still blocked, with the breakdown
  matching the findings; six category cards; "Teach Airlock → It's not
  sensitive" on the bank account number removed it (12 → 11 findings) with
  a confirmation in the report; Settings listed the existing company rule,
  showed the built-in profile read-only and duplicated it into an editable
  copy. Originals byte-identical; the log held only allowlisted events
  (`airlock_taught` with `status: not_sensitive`); no document value in the
  log or the database; no processes left after closing. After a restart the
  "not sensitive" decision still held, and company-rule matches offered no
  "Teach Airlock" link.
* CI green on Linux and Windows (engine, host and UI jobs).

Not in this phase: editing a profile's confidence threshold or adding custom
categories from the UI (`profiles.update` and `rules.add_category` exist);
restoring AI responses (Phase 12).

## Phase 7 verification log

* Verification (`verify.run`, automatic after every copy): the copy is read
  back in the isolated worker exactly like an original (OCR when the scan
  used it), its stored bytes are searched (every Office part decompressed,
  embedded Office files too, XML entities decoded, font family names
  ignored), and every detector runs again. A protected value left behind (as
  written, in any letter case for values that are not short words, written
  differently, or only in the stored bytes) or content that cannot be read
  fails the check; findings the original scan did not have need the user's
  confirmation ("review"); Airlock's own replacements and values the user kept
  are expected.
* Export: "Save Protected Copy…" and "Save as Text…" go through the host,
  which shows the native save dialog with the suggested name and the right
  filter; the web view cannot name a path (`export.prepare` / `export.save`
  are host-only). The engine refuses the original file, Airlock's folders,
  links, devices and other extensions, re-checks the copy's SHA-256, and
  writes atomically. "Copy Text for AI" puts the checked copy's readable text
  (tables as tab-separated rows) on the clipboard.
* A real defect found while building it: words such as "Microsoft" recognised
  as organisations also appear in Office theme font names
  (`typeface="Microsoft Himalaya"`); the stored-bytes search now ignores font
  family attributes, so typography does not fail a check while real leaks
  still do.
* Engine 430 tests (+1 IPv6, 1 Windows-only DPAPI and 1 non-root case
  skipped here), host 16 tests, UI 34 tests; ruff, ruff format, mypy
  `--strict` (also for `win32`), clippy clean.
* Real app (Linux, Xvfb): the DOCX with the token set to Redact produced a
  copy that was checked automatically ("none of the 9 protected values are in
  it"); the native save dialog opened with "Vendor Onboarding (Airlock
  protected).docx" and a DOCX filter and saved it; "Copy Text for AI" put the
  placeholder text on the clipboard (pasted back to confirm); cancelling the
  text dialog saved nothing. An independent search of the exported file
  found no protected value; the only original number left was the bank
  account the user had marked "not sensitive" in Phase 6. The log held
  `verify_completed`, `export_completed` and `export_text` with no path or
  value; the work folder was empty after closing; originals unchanged.

## Phase 8 verification log (in progress)

* Frozen engine: PyInstaller onedir (`engine/packaging/airlock-engine.spec`)
  with the spaCy English model, OCR models, PDFium and the Vera fonts; spaCy
  languages other than those its registry imports are left out; ReportLab's
  GPL font and OpenCV's FFmpeg plugin (Windows) are excluded and the build
  fails if they reappear. Built here on Linux (553 MB folder): the stdio
  smoke test passed (language model, OCR on a picture, PDF rebuild, every
  copy verified).
* The smoke test found two real issues that unit tests had not: the frozen
  build needed spaCy's CJK/Thai/Vietnamese tokenizer modules (imported by its
  registry at load), and with the language model on, a two-letter comment
  author ("CC") matched a colour shade in `styles.xml` during the stored-bytes
  search; short plain words are now checked in the extracted text only. A
  logging gap also surfaced: exception class names were silently dropped by
  the safe logger; they are now kept (names only, never messages).
* Installer: NSIS with a per-user / all-users choice, WebView2 bootstrapper by
  default and an offline variant, the frozen engine and
  `THIRD_PARTY_NOTICES.txt` (about 300 components with licence texts) as
  resources; all-users installs add firewall rules that block the engine's
  network traffic, removed on uninstall.
* Integrity: the release host checks the engine's SHA-256 before every
  start. Verified here with a release build: the bundled engine started and
  scanned the test document (same results as development); after changing one
  byte of the engine the app refused it ("engine_tampered", shown with
  "Reinstall Airlock") and no engine process ran. Closing the app left no
  engine process.
* Signing is wired (`AIRLOCK_SIGN_COMMAND`, CI secrets) but needs a
  certificate; builds without one are unsigned and say so.
* Remaining: the Windows `Package` workflow run (build, install, check,
  uninstall on a fresh runner) and the clean-VM check in
  [PACKAGING.md](PACKAGING.md).
