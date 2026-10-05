# Engine IPC protocol (v1.0)

The desktop host and the Python engine talk over the engine's **stdin/stdout**
using **JSON-RPC 2.0**, one JSON object per line (UTF-8; the engine emits pure
ASCII). There are no sockets, ports or tokens: only the parent process holds
the pipes.

```
host ──stdin──▶ engine     requests, $/cancelRequest
host ◀─stdout── engine     responses, $/progress notifications
host ◀─stderr── engine     structured log records (filtered again by the host)
```

## Framing

* A frame is one JSON object followed by `\n`. JSON escaping guarantees that
  frames contain no raw newlines.
* Max frame size: 16 MiB from host to engine, 64 MiB from engine to host. An
  oversized inbound frame is discarded and answered with error `-32002`
  (`id: null`). The engine keeps serving.
* Documents are always passed **by path**. File bytes never cross the pipe.
* Blank lines and `\r\n` line endings are tolerated.

## Lifecycle

1. The host spawns the engine (`CREATE_NO_WINDOW` on Windows, proxy variables
   removed).
2. The engine installs the network guard, configures logging, and moves the
   real stdout to a private descriptor. File descriptor 1 is pointed at
   stderr, so a stray `print()` cannot corrupt a frame.
3. The host sends `system.hello` with its `protocol_version`. The engine
   replies with `compatible`; a major-version mismatch is fatal.
4. Requests run concurrently on a worker pool; responses may arrive out of
   order and are matched by `id`.
5. Shutdown: the host sends `system.shutdown` (or closes stdin). The engine
   finishes every accepted request, then exits. If it has not exited within
   3 s, the host kills it. If the host dies, the engine sees EOF and exits.

The host restarts a crashed engine on the next request, at most 3 restarts per
60 s. Pending requests fail with `engine_crashed`.

## Methods

| Method | Exposed to UI | Params | Result |
| --- | --- | --- | --- |
| `system.hello` | no (host only) | `{protocol_version}` | `{engine, engine_version, protocol_version, compatible, methods[], pid, network_isolation}` |
| `system.health` | yes | `{}` | `{status, uptime_s, network_isolation, blocked_network_attempts, python, platform}` |
| `system.shutdown` | no (host only) | `{}` | `{ok: true}`, then the engine stops reading |
| `document.inspect` | yes | `{path}` | `{file_name, extension, size_bytes, format, format_label, family, support, scannable}` |
| `document.extract` | yes (cancellable) | `{path, ocr?: bool}` | Content-free summary: `{format, format_label, segment_count, char_count, word_count, parts[{kind, segments, chars, words}], counts{pages, slides, sheets, rows, lines, images_ocr, embedded}, ocr_used, unextracted[{kind, label, count}], unextracted_total, duration_ms}`. Emits `$/progress` with stages `pages`, `slides`, `sheets`, `rows`, `parts`, `ocr`. |
| `scan.start` | yes (cancellable) | `{path, profile_id?, ocr?: bool, ner?: bool}` | `{scan_id, extraction, findings[], summary, policy, detection_ms, risk}` with `$/progress` stages from extraction, then `prepare` (model load) and `detect` |
| `scan.set_profile` | yes | `{scan_id, profile_id}` | `{scan_id, findings[], summary, policy, risk}`; the user's overrides are kept |
| `scan.override` | yes | `{scan_id, overrides: [{finding_id \| value_group, action \| null, mask_style?}], acknowledge_risk?}` | `{scan_id, findings[], summary, policy, risk}`; all-or-nothing. `mask_style` needs action `MASK`; `partial` is refused for credentials |
| `scan.refresh` | yes (cancellable) | `{scan_id}` | Same as `scan.override`. Detects again on the text already read (the file is not reopened) with the current company rules, allow-list and profile (a deleted profile falls back to the default); the user's decisions carry over to the same values |
| `scan.teach` | yes (cancellable) | `{scan_id, finding_id, kind: not_sensitive \| company_rule, match?, category_id?, action?}` | Same as `scan.refresh`, after storing the decision: `not_sensitive` adds the value to the allow-list (keyed fingerprint), `company_rule` saves it as a rule (`match`: normalized, exact or case_insensitive; category `CONFIDENTIAL_TERM` by default). Refused with `cannot_teach_credential` for credentials and `cannot_teach_rule_match` for company-rule matches |
| `scan.discard` | yes | `{scan_id}` | `{ok, discarded}` |
| `allowlist.status` | yes | `{}` | `{count}` |
| `allowlist.clear` | yes | `{}` | `{ok, count: 0}`: every "not sensitive" value is flagged again |
| `sanitize.run` | yes (cancellable) | `{scan_id, strip_metadata?: bool}` (uses the scan's current decisions) | `{artifact_id, file_name, format, size_bytes, replaced{MASK,REDACT,GENERALIZE}, removed[{label,count}], vault{entries,stored,protection}, verified: false, duration_ms}`; fails with `blocked_findings` while any BLOCK remains, `file_changed` if the original changed since the scan |
| `sanitize.discard` | yes | `{artifact_id}` | `{ok, discarded}` (the vault record stays) |
| `vault.restore` | yes | `{artifact_id, text}` | `{text, restored}`: the only method that returns original values, on this explicit request; unknown placeholders are left unchanged |
| `vault.forget` | yes | `{artifact_id}` | `{ok, deleted}` |
| `vault.status` | yes | `{}` | `{protection: dpapi \| file \| memory, records}` |
| `verify.run` | yes (cancellable) | `{artifact_id}` | `{artifact_id, status: passed \| review \| failed, passed, checked{protected_values, segments, ocr_used}, remaining_count, new_count, remaining[{reason: protected \| new, entity_type, entity_label, preview, location{kind, label}, hidden}], unreadable[{label, count}], kept_count, replacement_count, duration_ms}`. Reads the copy back in an isolated worker (OCR if the scan used it), searches its stored bytes (every Office part decompressed) and runs every detector again. Stages: extraction stages, then `raw`, `prepare`, `detect` |
| `export.text` | yes | `{artifact_id, acknowledge_review?}` | `{text, chars}`: the checked copy's readable text (body, headers and footers, notes, pictures' text; tables as tab-separated rows) |
| `export.prepare` | no (host only) | `{artifact_id, as_text?, acknowledge_review?}` | `{file_name, extension, filter_label}` for the native save dialog |
| `export.save` | no (host only) | `{artifact_id, destination, as_text?, acknowledge_review?}` | `{ok, file_name, size_bytes}`. Atomic write; refuses the original file, Airlock's own folders, links and other extensions |
| `profiles.list` | yes | `{}` | `{profiles[], default_id, entity_types[], actions[], mask_styles[]}`; each profile lists `{action, source, style}` for every entity type |
| `profiles.create` | yes | `{name, base_id}` | `{profile}` |
| `profiles.update` | yes | `{id, name?, actions?: {entity_type: action \| null}, styles?: {entity_type: mask_style \| null}, min_confidence?, mask_style?}` | `{profile}` (built-ins are refused; `partial` is refused for credentials) |
| `profiles.delete` | yes | `{id}` | `{ok, default_id}` |
| `profiles.set_default` | yes | `{id}` | `{ok, default_id}` |
| `rules.list` | yes | `{}` | `{rules[], categories[], kinds[], actions[]}` |
| `rules.create` | yes | `{kind, pattern, category_id, aliases?, action?, enabled?}` | `{rule}` |
| `rules.update` | yes | `{id, ...any of kind/pattern/category_id/aliases/action/enabled}` | `{rule}` |
| `rules.delete` | yes | `{id}` | `{ok}` |
| `rules.add_category` | yes | `{label, group, severity}` | `{category}` |

A finding in `scan.start` is `{id, entity_type, entity_label, category,
severity, confidence, detector, corroborated_by[], rule_id, preview,
location: {kind, label}, hidden, value_group, action, effective_action, reason,
overridden, covered_by, generalizable, high_risk, mask_style, partial_available,
explanation}`. `explanation` names the rule that matched (a checksum, a
format, a context word, a company rule, the language model), never the value.
`mask_style` is `typed_placeholder`, `placeholder`, `synthetic` or `partial`
(keeps a recognisable part such as the last 4 digits; not reversible, never
for credentials). `action` is the decision
for the finding itself; `effective_action` is what applies after overlapping
findings merge (`covered_by` names the finding that decided the region).
`policy` is `{profile, actions{ALLOW..BLOCK}, regions, blocked, overridden,
ready}`. An override that keeps (`ALLOW`) a `high_risk` finding fails with
`confirmation_required` unless `acknowledge_risk` is true. `preview` is always masked;
`value_group` groups repeats of the same value within one scan without
revealing it. `summary` holds totals by severity, category and entity type,
the hidden count and detector status (`ner`: used, disabled, unavailable or
partial); each `by_category` entry is `{category, count, distinct,
max_severity, actions{...}}`. At most 2,000 findings are listed per response;
the summary always counts all of them.

`risk` is `{before, after}`, each `{score (0-100), level (none, low, medium,
high, critical), factors[{id, label, points, detail}]}`. `before` scores the
document as it is; `after` scores what the protected copy would still share
(findings kept, plus anything still blocked). See ARCHITECTURE.md, "Risk
score".

A copy can leave Airlock (`export.*`) only after `verify.run`: status
`passed`, or `review` with `acknowledge_review: true`; `failed` always
refuses with `verification_failed`. The bytes that leave must still have the
SHA-256 that was checked (`copy_changed` otherwise). The UI saves through the
host command `export_save(artifactId, asText, acknowledgeReview)`, which shows
the native save dialog and calls `export.prepare` / `export.save` itself, so
the web view never supplies a path. It returns `{saved: false}` when the user
cancels.

Rule text is returned only by `rules.*` (it is the user's own input for the
rules screen). It is never logged and never echoed in error messages.

The UI can only call methods in the host's allowlist
(`apps/desktop/src-tauri/src/commands.rs`). Lifecycle methods are never
exposed.

### UI request tags (host ⇄ UI)

`engine_call(method, params, tag?)` accepts an optional opaque tag
(`[A-Za-z0-9_-]{1,64}`). The host records the request id for that tag, adds
`tag` to every `$/progress` notification for the request before emitting
`engine://notification`, and `engine_cancel(tag)` sends `$/cancelRequest`
for it. The cancelled call then rejects with kind `cancelled`.

## Notifications

* Engine to host, `$/progress`: `{request_id, stage, done, total}`. The host
  re-emits it to the UI as the Tauri event `engine://notification`.
* Host to engine, `$/cancelRequest`: `{id}`. The handler stops at its next
  checkpoint and the request fails with `-32001`.

## Errors

| Code | Meaning |
| --- | --- |
| -32700 | Parse error |
| -32600 | Invalid request (bad envelope, bad or duplicate id) |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error (generic message; details are never sent or logged) |
| -32000 | Airlock error. `data` = `{kind, message, next_step, original_affected}` |
| -32001 | Request cancelled |
| -32002 | Message too large |

Every `-32000` error explains what happened, whether the original file was
affected, and what the user can do next. Messages never include file paths,
document content or matched values.

Example:

```json
→ {"jsonrpc":"2.0","id":7,"method":"document.inspect","params":{"path":"C:\\Users\\a\\invoice.pdf"}}
← {"jsonrpc":"2.0","id":7,"error":{"code":-32000,"message":"This file is named .pdf but its contents look like a Windows program. ...",
   "data":{"kind":"format_mismatch","message":"...","next_step":"Save the file again from the application that created it.","original_affected":false}}}
```

## Logging channel

The engine's stderr carries JSON log records with allowlisted keys only (see
`safelog.py`). The host persists a line **only** if it passes its own
independent allowlist check (`logsink.rs`). Anything else, such as tracebacks
or library output, is dropped and only counted.

## V2: browser extension

Chrome and Edge native messaging use stdio with 32-bit length-prefixed frames.
The planned design runs a tiny native-messaging host that forwards to the
running desktop agent over a per-user named pipe with an ACL restricted to the
current user. The detection engine stays in the agent; the extension never
holds it, and nothing goes to a cloud service.
