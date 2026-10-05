# Airlock security model

## Assets

1. **Document content**: the user's confidential files.
2. **Sensitive values**: anything a detector matches.
3. **Pseudonym mappings** (`PERSON_001 → real name`).
4. **Company rules**: custom dictionaries such as internal project names,
   which are themselves confidential.
5. **Licence integrity**: the signing key and the licence verification path.

## Threats and controls

| Threat | Control | Status |
| --- | --- | --- |
| Data leaves the device through the privacy engine | Audit-hook network guard installed before any other engine code: blocks DNS and non-loopback connect/sendto, `urllib`, and every library built on them. Proxy variables are removed by both host and engine. Tests run inside a network namespace with no network. The installer may add a Windows Firewall outbound-block rule for `airlock-engine.exe` (Phase 8). | Phase 1 ✅ |
| Another local process or a web page talks to the engine | No listening socket exists: stdio only. The UI reaches the engine only through an allowlist of methods in the Rust host. | Phase 1 ✅ |
| Compromised or buggy UI script exfiltrates data | CSP `default-src 'self'`; `connect-src` limited to Tauri IPC; no `withGlobalTauri`; capabilities limited to events, window and file-open dialog (no fs, shell or http plugins); prototype freezing. The UI never receives raw sensitive values. | Phase 1 ✅ (value masking from Phase 3) |
| Sensitive data in logs | `SensitiveValue` redacts on `str/repr/format` and refuses JSON or pickle serialisation. The engine logger accepts only allowlisted keys with numeric or identifier-token values. Third-party loggers are reduced to `{event: third_party_log, logger}`. The host re-validates every record before writing and drops unstructured stderr. Internal errors return a generic message. | Phase 1 ✅ |
| Stray output corrupts the protocol or leaks via stdout | The engine duplicates stdout to a private descriptor, points fd 1 at stderr and fd 0 at the null device. | Phase 1 ✅ |
| Hostile input files | Absolute paths only; device namespace, NUL bytes and reserved names rejected; regular files only; 200 MB limit; magic-byte sniffing must match the extension; encrypted OOXML detected; zip entry-count cap. Phase 2 adds `defusedxml`, decompression limits, Pillow pixel caps, and extraction in a disposable worker process with timeout and Job Object memory cap. | Phase 1 ✅ / Phase 2 |
| Original file modified | Inputs are opened read-only; adapters write only to new destinations; tests assert bytes and mtime unchanged. | Phase 1 ✅ (tests extend per adapter) |
| Path traversal on export | Export destinations come only from the native save dialog. The engine resolves and validates the destination, refuses to overwrite the source, and writes atomically (temp file in the same directory, then rename). | Phase 7 |
| Temporary sensitive artifacts | Per-session private temp directory (user-only ACL), deleted after export/discard and swept on start-up. | Phase 5 |
| Pseudonym mappings exposed | Separate vault file, AES-256-GCM with a random 256-bit key wrapped by DPAPI (current user). Never logged, never sent over IPC to the UI except an explicit "restore" action. | Phase 5 |
| Licence forgery | Ed25519 signatures verified in the Rust host. Only the public key ships; the private key stays offline (HSM or air-gapped machine). Scanning never depends on licence-server availability. | Phase 10 |
| Engine crash or hang (e.g. a malicious PDF) | Separate process; request timeouts; automatic restart with a budget; the UI gets an actionable error; the scan is never silently "passed". | Phase 1 ✅ |
| Tampered installation | Authenticode signing of installer, host and engine; the host verifies the engine binary hash before launch (Phase 8). | Phase 8 |

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
