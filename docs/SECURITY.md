# Airlock security model

## Assets

1. **Document content**: the user's confidential files.
2. **Sensitive values**: anything a detector matches.
3. **Pseudonym mappings** (`PERSON_001 → real name`).
4. **Company rules**: custom dictionaries such as internal project names,
   which are themselves confidential.
5. **Licence integrity**: the signing key and the licence verification path.
   The machine ID behind a machine code is never shown or sent.

## Threats and controls

| Threat | Control | Status |
| --- | --- | --- |
| Data leaves the device through the privacy engine | Audit-hook network guard installed before any other engine code: blocks DNS and non-loopback connect/sendto, `urllib`, and every library built on them. Proxy variables are removed by both host and engine. Tests run inside a network namespace with no network. All-users installs add Windows Firewall rules blocking inbound and outbound traffic for `airlock-engine.exe` (removed on uninstall); `packaging/windows/firewall.ps1` adds them for per-user installs. | Phase 1 ✅, Phase 8 ✅ |
| Another local process or a web page talks to the engine | No listening socket exists: stdio only. The UI reaches the engine only through an allowlist of methods in the Rust host. | Phase 1 ✅ |
| Compromised or buggy UI script exfiltrates data | CSP `default-src 'self'`; `connect-src` limited to Tauri IPC; no `withGlobalTauri`; capabilities limited to events, window and file-open dialog (no fs, shell or http plugins); prototype freezing. The UI never receives raw sensitive values. | Phase 1 ✅ (value masking from Phase 3) |
| Sensitive data in logs | `SensitiveValue` redacts on `str/repr/format` and refuses JSON or pickle serialisation. The engine logger accepts only allowlisted keys with numeric or identifier-token values. Third-party loggers are reduced to `{event: third_party_log, logger}`. The host re-validates every record before writing and drops unstructured stderr. Internal errors return a generic message. | Phase 1 ✅ |
| Stray output corrupts the protocol or leaks via stdout | The engine duplicates stdout to a private descriptor, points fd 1 at stderr and fd 0 at the null device. | Phase 1 ✅ |
| Hostile input files | Absolute paths only; device namespace, NUL bytes and reserved names rejected; regular files only; 200 MB limit; magic-byte sniffing must match the extension; encrypted OOXML/PDF detected. ZIP packages: ≤ 20,000 entries, ≤ 512 MB per part, ≤ 2 GB total, inflation ratio ≤ 200:1 for large parts. XML parsed with `defusedxml` (DTDs and entity expansion forbidden). Images capped at 100 MP. Extraction limits: 30 M characters, 500 k text items, 5,000 pages, 200 OCR images, embedding depth 2; exceeding a limit is an error, never a silent truncation. | Phase 2 ✅ |
| Parser exploits / crashes / hangs on a hostile file | Each document is parsed in a **disposable worker process** (fresh interpreter, network guard installed first). 15-minute timeout, user cancellation, memory cap (Windows Job Object with KILL_ON_JOB_CLOSE, so workers never outlive the engine; Linux `RLIMIT_AS`). Results return as validated JSON, never pickle, so a compromised worker cannot execute code in the engine. The worker re-reads and re-sniffs the file and refuses it if it changed after validation. | Phase 2 ✅ |
| Content the engine cannot read | Macros, OLE objects, unreadable images, earlier PDF revisions and embedded scripts are reported as "could not be read", never silently skipped; safe copies remove macros, blank unreadable pictures, empty unreadable embedded objects and rebuild PDFs without revisions or scripts. | Phase 2 ✅, Phase 5 ✅ |
| Sensitive values reach the UI | Findings carry masked previews only; credentials never show more than a public prefix; raw values stay in the in-memory scan session (TTL 30 min, discarded when the user changes or clears the file). | Phase 3 ✅ |
| Company rules leak | Rule text is stored in the user-only database, never logged (custom category ids are logged only as `custom`), never echoed in errors, and `CompanyRule`/`RuleRow` reprs hide it. | Phase 3 ✅ |
| "Not sensitive" decisions reveal values | The allow-list stores an HMAC-SHA256 of the normalized value under a random per-install key, never the value. The key is wrapped by the same protector as the vault key (DPAPI on Windows). | Phase 3 ✅, Phase 5 ✅ |
| "Teach Airlock" stores something it should not | Teaching keeps only an HMAC fingerprint ("not sensitive") or a company rule ("always protect", stored like any other rule). Credentials can never be taught, so a password or key is never written to disk; company-rule matches cannot be allow-listed, so a rule cannot be undone by accident. The log records only the event and its kind (`airlock_taught`, `status`), never the value or rule text. Teaching and refreshing re-detect on the text already in memory: the file is not reopened. | Phase 6 ✅ |
| Risk score hides danger or leaks content | The score is deterministic and explainable (named, capped factors, ARCHITECTURE.md §5e), computed only on the device. Factor details are counts, never values. Blocked items keep counting in the "protected copy" score until resolved. Partial masking keeps at most the last 4 letters or digits, initials or an e-mail domain, and is never offered for credentials. | Phase 6 ✅ |
| Hostile company-rule regex (ReDoS) | Patterns are validated (length, must not match empty text) and run with a per-segment timeout; a rule that keeps timing out is skipped for the document. Built-in detectors are linear (tested on 100k-character adversarial input). | Phase 3 ✅ |
| A credential is shared by accident | Credentials default to BLOCK in every built-in profile; keeping a critical or credential finding needs an explicit acknowledgement (engine-enforced, the UI asks first); overrides are per scan and never persisted, so they cannot silently weaken later scans. Nothing leaves Airlock without passing verification. | Phase 4 ✅, Phase 7 ✅ |
| A protected copy still contains a value | Value sweep across the whole file (not only detected spots); unreadable content removed, blanked or emptied; macros and thumbnails removed; canary leak tests per format. Before anything leaves, `verify.run` reads the copy back (OCR as in the scan), searches every stored part, and rescans it: a protected value left behind or unreadable content blocks every export; new findings need the user's confirmation. | Phase 5 ✅, Phase 7 ✅ |
| A checked copy is swapped before it leaves | Export re-hashes the copy and refuses unless it matches the SHA-256 that verification approved; the worker checks the same hash before reading it back. | Phase 7 ✅ |
| Copy made from a different file than the one reviewed | The worker checks the original's SHA-256 against the scan and refuses on mismatch. | Phase 5 ✅ |
| Third-party licence risk | Open-source, permissively licensed runtime dependencies only; CI test rejects GPL/AGPL/LGPL/SSPL. The packaging build fails if a copyleft file is in the frozen engine (ReportLab's DarkGarden font, OpenCV's FFmpeg plugin) or a copyleft-only Rust/npm component would ship; every installer carries `THIRD_PARTY_NOTICES.txt`. | Phase 2 ✅, Phase 8 ✅ |
| Original file modified | Inputs are opened read-only; adapters write only to new destinations; tests assert bytes and mtime unchanged. | Phase 1 ✅ (tests extend per adapter) |
| Path traversal on export | The host shows the native save dialog and passes the chosen path itself; `export.save` is not callable from the web view. The engine validates the destination (absolute, existing folder, the copy's own extension, not the original, not Airlock's data or work folders, not a link or device) and writes atomically (temp file in the same folder, fsync, replace). Logs record the file type and size only, never the path. | Phase 7 ✅ |
| Temporary sensitive artifacts | Protected copies live in `<data dir>/work` (user-only, files 0600), are created exclusively, deleted on discard, scan discard and engine exit, and swept at start-up. | Phase 5 ✅ |
| Pseudonym mappings exposed | Separate vault folder, one AES-256-GCM record per copy (record id bound as associated data), random 256-bit key wrapped by DPAPI (current user) on Windows; on other platforms by a user-only key file (weaker: readable by anyone who can read the user's files; macOS Keychain is a Phase 12 item). 30-day retention. Never logged, never sent over IPC to the UI except the explicit `vault.restore`. | Phase 5 ✅ |
| Another website or local process drives the local web app (Phase 13) | Loopback only, random port, per-launch secret required on every call, strict Host and Origin checks against DNS rebinding and cross-site requests, no CORS, same method allowlist and masked previews as the desktop app. | Phase 13 |
| The web app sends a document somewhere (Phase 14) | The engine runs in a Web Worker inside the page; the site serves static files only and has no upload endpoint. CSP `connect-src 'self'` and no third-party scripts or analytics, so the page cannot reach other origins. Rules, allow-list keys and the vault use WebCrypto keys marked non-extractable, stored in the browser profile. Releases are versioned and reproducible from the repository. | Phase 14 |
| Licence forgery | Ed25519 signatures (strict verification) checked offline in the Rust host against the public keys compiled into the app; only public keys ship, the private key stays offline. A changed licence, an unknown issuer or another machine's licence is refused and reported. No feature depends on the licence, and scanning never depends on licence-server availability. | Phase 10 ✅ |
| Activation leaks data or becomes a tracking channel | Online activation is optional, user-initiated, done by the host (never the engine), HTTPS-only in release builds, and sends only the licence key, a one-way machine code (hash of the machine ID) and the app version. No periodic check-ins. The reference server stores keys hashed and logs no request bodies. | Phase 10 ✅ |
| Engine crash or hang (e.g. a malicious PDF) | Separate process; request timeouts; automatic restart with a budget; the UI gets an actionable error; the scan is never silently "passed". | Phase 1 ✅ |
| Tampered installation | The release host verifies the engine executable's SHA-256 (recorded at build time) before every start and refuses a changed engine (`engine_tampered`); all-users installs live in Program Files. Authenticode signing of the engine, host and installer is wired into the build and runs when a certificate is configured. | Phase 8 ✅ (signing needs the certificate) |

## Rules for contributors

* Never log, print, raise or return a raw matched value or document text.
  Use `SensitiveValue` and call `.reveal()` only in masking and verification
  code.
* Never add a dependency that performs network I/O at import or run time
  without proving it is blocked or disabled.
* Never put real personal data in tests or fixtures. Use the synthetic
  generators, `example.invalid` domains, and checksum-valid **synthetic** IDs.
* Errors shown to users must state what happened, whether the original was
  affected, and the next step, without including paths or content.
