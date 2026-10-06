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
| Browser extension | `node --test` (apps/extension) + pytest (`test_bridge.py`) | Bridge: JSON-RPC matching, notifications ignored, error mapping, "app not found" vs "connection closed", timeouts, idle disconnect and reconnect; popup text. Engine side: native-messaging framing, origin refusal, method allowlist, size limits, `text.protect` (placeholders, blocked secrets removed, repeats swept, company rules and allow-list applied, nothing logged), and the extension ID derived from the manifest key. Real run: Chromium with the unpacked extension and the registered development engine. |
| Reversible masking (Phase 12) | pytest (`test_restore.py`, `test_conversations.py`) + vitest | Restoration token rules (possessives, punctuation, Markdown escapes, no partial matches, literal insertion, unknown placeholders left as written), stable placeholders across conversation turns, earlier values protected without detection, the outbound check stopping a differently written value, privacy modes, credentials never stored, forgotten conversations, encrypted records, the document workspace; the Text for AI screen (send only after the check, review before restore, keep anonymized, new conversation, Settings → Delete All). |
| Desktop end to end | `scripts/desktop_e2e.py` through tauri-driver: the installed app on `windows-latest` (WebView2, msedgedriver; `Package` workflow) and a development build on Linux (WebKitWebDriver, Xvfb) | Launch and engine handshake, file drop (`tauri://drag-drop`), scan, protected copy and its check, Copy Text for AI with the system clipboard read back, original unchanged, log events present and no values, Text for AI (protect a prompt, outbound check, Copy for AI, review and restore a response), engine killed and restarted, window closed with no process left. |
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
| Context-gated ids (bank account, date of birth) | ≥ 0.95 | ≥ 0.95 |
| Company rules (exact / normalized) | 1.00 | 1.00 |
| NER entities | tracked, no hard gate in V1 | tracked |

False-positive suites include invoice numbers, timestamps, version strings,
hashes, UUIDs and arithmetic in spreadsheets.

Implemented in `engine/tests/test_quality_gates.py` on two corpora:

* `tests/synthetic/corpus.py`: templates per entity type plus the negative
  suite. The detectors were tuned against it.
* `tests/synthetic/heldout.py`: realistic mixed documents (vendor e-mails,
  `.env` files, log lines, JSON, KYC notes) written separately, scored
  against the same thresholds to catch over-fitting.

Both use synthetic values, so they test detector logic rather than
real-world recall. Run `uv run pytest tests/test_quality_gates.py -s` to
print the per-entity table. Company rules are gated at 1.00/1.00 in
`tests/test_company_rules.py`.

## Policy tests (Phase 4)

`test_policy.py` covers every built-in profile's table (credentials → BLOCK
everywhere), resolution order, confidence threshold, GENERALIZE fallback,
reasons, and overlap regions (containment, partial and chained overlaps).
`test_profiles.py` covers custom profiles, validation and the v1 → v2 schema
migration; `test_api_policy.py` drives overrides, risk acknowledgement and
profile switching over RPC and checks no raw value appears in any response.

## Privacy report tests (Phase 6)

`test_risk.py` covers the risk scorer (levels, caps, repeats counted once,
factor order, hidden/volume/unreadable points, the residual set, determinism),
detector explanations (every built-in pattern detector has a reason; reasons
never contain the value) and partial masking (formats per type, never for
credentials, never stored in the vault). `test_api_teach.py` drives the RPC
side: explanations and category summaries in a real scan, a partial-mask
override reaching the protected copy, "not sensitive" then clearing the
allow-list (no value in the log or database), credentials and company-rule
matches refused, a company rule taught from a language-model finding with the
user's earlier choices carried over, per-type mask styles in custom profiles,
and `scan.refresh` applying an edited (or deleted) profile.

## Verification and export tests (Phase 7)

`test_verify.py` covers the verifier (clean copy, exact and any-case leaks,
short words on word edges, a number written differently, matches inside
Airlock's own replacements, leaks only in stored bytes, kept values,
new findings → review, unreadable content → failed), the raw search
(decompressed parts, embedded packages, XML entities, font names ignored,
UTF-16 text, safe part labels), the AI-safe text layout, destination rules
and the atomic write. `test_api_verify.py` drives every format through
scan → copy → verify → export (file and text) over RPC with canaries, then
the gates: nothing leaves before a check, a simulated sanitizer bug fails the
check and blocks every export, new findings need an acknowledgement, and the
original file, wrong extensions, Airlock's folders and a changed copy are
refused.

## Leak tests (Phase 5+) — implemented in `test_api_sanitize.py`

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

# browser extension
cd apps/extension && npm test

# offline (Linux): the whole engine suite with no network at all
unshare -rn bash -c 'ip link set lo up; cd engine && .venv/bin/python -m pytest'

# desktop end to end (Linux): needs webkit2gtk-driver, xclip, Xvfb and
# `cargo install tauri-driver --locked`; a debug build runs engine/.venv
(cd apps/desktop && npm run build && cd src-tauri && cargo build --features tauri/custom-protocol)
xvfb-run -a dbus-run-session -- python3 scripts/desktop_e2e.py \
  --app apps/desktop/src-tauri/target/debug/airlock-desktop \
  --log ~/.local/share/com.airlock.desktop/logs/airlock.log
```

On Windows the same script runs on the installed app from
`packaging/windows/installer-smoke.ps1 -TauriDriver <path>` (see
[PACKAGING.md](PACKAGING.md)). Under Xvfb there is no window manager, so the
Linux run ends the app with SIGTERM instead of closing its window; the
engine must still exit.
