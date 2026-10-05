# Reversible masking and response restoration (queued: Phase 12)

Status: **requirement recorded, not yet implemented.** Requested after Phase 4,
to be built once Phases 5–11 are done. Phase 5 already lays the groundwork
(see "Already in place" below); this document is the source of truth for the
rest.

## Goal

Airlock must not only protect content before it goes to an external AI; it
must also restore the original values in the AI's response, **locally**.

> The AI can understand the information without knowing the identity behind it.
> We don't send your data to AI to decide whether it is safe to send to AI.

```
                         USER'S DEVICE
  original content → detection → policy → reversible masking
                                              │
                                     🔐 mapping vault (original, placeholder,
                                              │        entity type, scope id)
                                              ▼
                                      sanitized content
  ───────────────────────── device boundary ─────────────────────────
                     external AI (ChatGPT / Claude / Gemini ...)
                                              │ AI response
  ───────────────────────── device boundary ─────────────────────────
                         local restoration engine → restored response → user
```

Only sanitized content ever crosses the boundary. Mappings never leave the
device.

## Requirements

1. **Bidirectional flow** as above; the boundary must be explicit in code and
   in the UI.
2. **Placeholders** such as `PERSON_001`, `PROJECT_001`, `FINANCIAL_001`,
   `EMAIL_001` (zero-padded, typed). Example: "Rahul Sharma is managing
   Project Phoenix" → "PERSON_001 is managing PROJECT_001".
3. **Restoration** replaces placeholders in the AI response with the
   originals, locally.
4. **Local-only vault.** Mappings are never uploaded, sent to any AI or API,
   put in prompts, analytics or crash reports, or logged in plaintext.
5. **Mapping vault component**: create, store, retrieve, restore, destroy;
   scoped to a session / document / conversation with a unique id (e.g.
   `AIRLOCK-2026-001928`); encrypted at rest; never in logs.
6. **No blind global replacement.** Restoration is structured and
   session-scoped, preserves entity types, handles overlaps, keeps repeats
   consistent, handles special characters safely, and never corrupts partial
   matches. `PERSON_001`, `PERSON_001's`, `PERSON_001.` → `Rahul Sharma`,
   `Rahul Sharma's`, `Rahul Sharma.`; `PERSON_0011` is not `PERSON_001`.
7. **Stable pseudonyms** within a session: the same value always gets the same
   placeholder.
8. **Cross-document consistency**: opt-in privacy *workspace* where the same
   value keeps its placeholder across documents. Default: session-scoped.
9. **Privacy mode control** before sending: Permanent Redaction, Reversible
   Masking (default), Synthetic Replacement, Block Sensitive Content.
10. **Response handling UI**: "AI response received · N placeholders" with
    *Restore protected data*, *Keep anonymized*, *Review before restoring*
    (preview table placeholder → original, then Restore / Cancel).
11. **Security boundary UI** that a non-technical user understands (your
    device / only sanitized data / external AI / your device).
12. **Outbound privacy check** (second local scan) before anything is sent:
    original entities, masked entities, remaining high-risk entities,
    credentials; "Safe to send" or "Send blocked · Review". No accidental
    transmission.
13. **Restoration safety**: restore only placeholders present in the trusted
    vault for this scope. Unknown placeholders (`PERSON_999`) stay unchanged.
    Never guess, never ask the AI to resolve one.
14. **Conversation continuity**: placeholders stay stable across turns; the AI
    keeps seeing pseudonyms; only the local UI knows the mapping.
15. **Prompt protection**: text typed into Airlock is sanitized the same way
    as documents ("Write an email to Rahul Sharma about Project Phoenix" →
    "… PERSON_001 about PROJECT_001"), and the response restored.
16. **Clipboard workflow** must be architecturally possible (copy → sanitized
    clipboard → paste into AI → restore response); implementation may come
    later (the engine already has a `clipboard/` module boundary).
17. **First-class capability**, not a UI add-on: detection, policy, masking,
    mapping vault, session manager, AI adapter layer, restoration engine,
    privacy verification, audit/event system and local encrypted storage all
    support it. macOS and Windows compatible; no cloud dependency; external AI
    integrations pluggable without changing the core privacy engine.

## Already in place (Phase 5) and what Phase 12 changes

| Requirement | Phase 5 | Phase 12 work |
| --- | --- | --- |
| Stable pseudonyms per file | Same value → same placeholder within a protected copy; placeholder collisions with existing text avoided | Session/conversation scope across several inputs; opt-in workspace scope |
| Encrypted local vault | AES-256-GCM per protected copy, key wrapped with DPAPI on Windows (user-only key file elsewhere); entries hold placeholder, original and entity type | Keychain-backed key on macOS; session ids; destroy/retention controls in the UI |
| Restoration only from known mappings | `vault.restore` replaces only placeholders recorded for that copy; unknown ones are left untouched | Token-aware matching (`PERSON_001's`, no partial matches), review-before-restore UI, conversation scope |
| Placeholder format | `[EMAIL_1]` (brackets, unpadded) | Decide on `PERSON_001` style (and migrate, or support both) |
| Outbound check | Phase 7 verification (re-extract, rescan, residual-value check) | Same check applied to prompts and clipboard text before sending |
| Prompt / clipboard | — | Text input + clipboard integration through the same masking pipeline |
| AI adapter layer | — | Provider-neutral interface; providers only ever receive sanitized text |
