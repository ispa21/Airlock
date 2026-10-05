# Roadmap and phase status

Each phase follows **implement → test → run → fix → document**. A phase is
done when its exit criteria pass on a real run, not when it compiles.

| Phase | Scope | Exit criteria | Status |
| --- | --- | --- | --- |
| 0 | Architecture and repository setup | Docs (architecture, IPC, security, testing, roadmap); monorepo layout; tooling (uv, ruff, mypy, cargo, vite, vitest); CI | ✅ Done |
| 1 | Desktop shell + Python engine + IPC | Tauri app spawns the engine, handshake with version check, allowlisted calls, structured errors, crash restart, graceful shutdown, no orphans, network guard, content-free logs, main screen UI, file drop/browse with validation | ✅ Done |
| 2 | Document extraction | Adapters for PDF, DOCX, XLSX, CSV, TXT, PPTX, then images (OCR), config files and code. Hidden parts extracted. Worker-process isolation. Malformed-file and fuzz suites | Next |
| 3 | Detection | Regex detectors with checksums (Email, Phone, PAN, Aadhaar, GSTIN, bank account, IFSC, card, IP, URL); secret detectors; spaCy NER provider; company rules (exact, case-insensitive, normalized, alias, regex); SQLite storage; quality gates | |
| 4 | Policy | Profiles, entity → action mapping, defaults (credentials → BLOCK), overlap resolution, user overrides | |
| 5 | Masking | Redaction, placeholder, typed placeholder, synthetic replacement, generalisation, reversible encrypted vault (DPAPI + AES-GCM), adapter `sanitize` for each format | |
| 6 | Privacy report | Category summary, deterministic explainable risk, per-finding detector/confidence/action, partial masking, "teach Airlock" flow | |
| 7 | Verification and export | Re-extract the produced artifact, rescan, residual-value check, raw OOXML sweep, block on failure, safe export, AI-safe copy | |
| 8 | Windows packaging | PyInstaller onedir engine, NSIS installer, WebView2 strategy, code signing, firewall rule option, tauri-driver E2E on Windows, clean-VM DoD run | |
| 9 | Right-click integration | "Protect with Airlock" verb (HKCU), single-instance hand-off of the file path | |
| 10 | Lifetime licensing | Ed25519 signed licences, offline import, online activation (isolated from the engine), local verification | |
| 11 | Browser extension foundation | Native-messaging host, named-pipe agent channel, MV3 extension skeleton for Chrome and Edge | |

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
