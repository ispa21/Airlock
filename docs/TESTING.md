# Testing strategy

The property that matters most: **with the network disabled, Airlock can
scan, mask, verify and export a confidential document, and nothing sensitive
survives in the output or the logs.** Every layer of testing serves that
property.

## Layers

| Layer | Tooling | What it covers |
| --- | --- | --- |
| Engine unit | pytest | Protocol parsing, server behaviour (cancel, oversize, drain on EOF), input validation, sniffing, `SensitiveValue`, safelog. Later: every detector, policy, masking, risk and verification. |
| Extraction (canaries) | pytest + `tests/builders.py` | Real DOCX/XLSX/PPTX/PDF/images built with python-docx, openpyxl, python-pptx, reportlab and Pillow, with a unique canary in every hidden location; each must be extracted with the correct kind, label and locator, and labels/locators must never contain content. |
| Hostile documents | pytest | Zip bomb, entry-count bomb, billion laughs, decompression bomb, encrypted files, truncation, plus seeded mutation fuzzing (450 mutated files per run) that requires a result or an `AirlockError`, never a raw exception or a hang. |
| Worker isolation | pytest (`-m subprocess`) | Crash, segfault, timeout, memory cap, network attempt and cancellation inside the real worker process; `document.extract` end to end with originals hashed before/after and stderr checked for leaks. |
| Licence policy | pytest | Every runtime dependency is permissively licensed (no GPL/AGPL/LGPL/SSPL). |
| Engine subprocess | pytest (`-m subprocess`) | The real engine process over pipes: handshake, calls, clean exit, stdout-pollution immunity, no leaks on stderr. |
| Network isolation | pytest (fresh interpreters) + `unshare -n` in CI | Guard blocks DNS, TCP, UDP, `urllib`, `http.client`, IPv6; loopback still works; proxy variables removed. The full suite also runs in a network namespace with no network. |
| Host | `cargo test` | Supervisor against the real engine and against fake engines (crash, restart budget, incompatible handshake, timeout, missing binary); RPC error mapping; log allowlist; UI method allowlist. |
| UI | vitest + Testing Library | Drop/browse/inspect flow, error explanation, multi-file handling, engine unavailable/retry, never claiming local processing without network isolation. |
| Desktop end to end | Real app under Xvfb on Linux (dev); **tauri-driver/WebDriver on `windows-latest`** (Phase 8) | Launch, engine handshake, real file dialogs, crash recovery, graceful shutdown, no orphan processes, log contents. |
| Release acceptance | Scripted checklist on a clean Windows VM | PRD §36 Definition of Done, Wi-Fi disabled. |

## Synthetic data policy

* Never use real personal data. Fixtures use `example.invalid` e-mail
  domains, reserved phone ranges, and **generated, checksum-valid synthetic**
  PAN, Aadhaar (Verhoeff), GSTIN (mod-36) and card numbers (Luhn).
* Generators live in `tests/synthetic/` (Phase 3) and are seeded, so corpora
  are reproducible. Generated binaries are rebuilt in CI from scripts rather
  than committed, except for a small golden set.
* Corpus coverage: Indian and international formats, Unicode (Devanagari,
  accented Latin, RTL), tables, scanned PDFs, images, spreadsheets with
  hidden sheets and comments, decks with speaker notes, source code, `.env`
  files, malformed and truncated files, zip bombs, very large documents.

## Detector quality gates (Phase 3+)

Each detector has positive, negative and adversarial cases. CI computes
per-entity precision and recall on the labelled synthetic corpus and fails
when they regress below thresholds:

| Class | Recall | Precision |
| --- | --- | --- |
| Credentials / secrets | ≥ 0.99 | ≥ 0.90 |
| Checksummed government and financial IDs | ≥ 0.99 | ≥ 0.98 |
| E-mail, phone, IP, URL | ≥ 0.98 | ≥ 0.95 |
| Company rules (exact / normalized) | 1.00 | 1.00 |
| NER entities | tracked, no hard gate in V1 | tracked |

False-positive suites include invoice numbers, timestamps, version strings,
hashes, UUIDs and arithmetic in spreadsheets.

## Leak tests (Phase 5+)

Canary values are seeded into every part of each test document: body,
headers/footers, comments, tracked changes, speaker notes, hidden sheets,
document properties, alt text and embedded objects. After sanitisation:

1. Canaries must not appear in the **output bytes**, including after
   decompressing every ZIP part.
2. Canaries must not appear in the log file, the temp directory (after
   cleanup), SQLite, or anything sent over IPC to the UI.
3. The source file's bytes and mtime are unchanged.

## Fuzzing

Mutation-based fuzzing of each adapter's `extract` (truncation, bit flips,
zip-entry corruption) asserts that the engine returns an actionable error or
a result and never hangs, crashes or leaves temp files behind.

## Running tests

```bash
# engine
cd engine && uv sync && uv run pytest && uv run ruff check . && uv run mypy

# host
cd apps/desktop/src-tauri && cargo test && cargo clippy --all-targets -- -D warnings

# UI
cd apps/desktop && npm ci && npm run typecheck && npm test

# offline (Linux): the whole engine suite with no network at all
unshare -rn bash -c 'ip link set lo up; cd engine && .venv/bin/python -m pytest'
```
