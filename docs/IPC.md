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
| `scan.start` | Phase 3 | `{path, profile_id}` | `{scan_id, findings[], summary, risk}` with `$/progress` notifications |
| `scan.discard` | Phase 3 | `{scan_id}` | `{ok}` |
| `sanitize.run` | Phase 5 | `{scan_id, decisions[]}` | `{artifact_id}` |
| `verify.run` | Phase 7 | `{artifact_id}` | `{passed, original_count, remaining_count, remaining[]}` |
| `export.save` / `export.text` | Phase 7 | `{artifact_id, destination}` / `{artifact_id}` | `{ok}` / `{text}` (sanitized only) |
| `rules.*` | Phase 3 | CRUD for company rules | |

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
