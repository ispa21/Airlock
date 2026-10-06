import { useCallback, useEffect, useMemo, useState } from "react";

import { clipboardAdapter, outboundText } from "../ai/adapter";
import { usePlatform } from "../engine/PlatformContext";
import { toEngineError, type EngineError, type PrivacyMode, type ProtectTextResult } from "../engine/types";
import { plural } from "../lib/format";
import { ErrorNotice } from "./ErrorNotice";
import { AlertIcon, CheckIcon, ChevronIcon } from "./icons";
import { RemainingList } from "./ProtectedCopy";
import { ResponsePanel } from "./ResponsePanel";

const MODES: { id: PrivacyMode; label: string; hint: string }[] = [
  {
    id: "reversible",
    label: "Reversible masking (recommended)",
    hint: "Sensitive values become placeholders such as PERSON_001. The originals stay on this device so the AI's response can be restored.",
  },
  {
    id: "synthetic",
    label: "Synthetic replacement",
    hint: "Realistic stand-ins such as person1@example.invalid where a safe one exists, placeholders otherwise. Also restorable.",
  },
  {
    id: "redact",
    label: "Permanent redaction",
    hint: "Sensitive values become [REDACTED]. Nothing is kept, so nothing can be restored.",
  },
  {
    id: "block",
    label: "Block sensitive content",
    hint: "If anything sensitive is found, Airlock produces nothing to send.",
  },
];

/** Where the text is now, in the order a non-technical person thinks of it. */
const STEPS = [
  { place: "Your device", what: "Airlock finds and masks sensitive data" },
  { place: "Leaves your device", what: "Only the protected text" },
  { place: "Your AI tool", what: "Sees placeholders, never the originals" },
  { place: "Your device", what: "Airlock puts the originals back" },
];

function Boundary({ step }: { step: number }) {
  return (
    <ol className="boundary" aria-label="Where your data goes">
      {STEPS.map((s, i) => (
        <li
          key={i}
          className="boundary__step"
          data-side={i === 0 || i === 3 ? "device" : "outside"}
          data-current={i === step || undefined}
          data-done={i < step || undefined}
        >
          <span className="boundary__place">{s.place}</span>
          <span className="boundary__what">{s.what}</span>
        </li>
      ))}
    </ol>
  );
}

function summaryLine(result: ProtectTextResult): string {
  const parts: string[] = [];
  const found = result.findings.filter((f) => f.action !== "ALLOW").length;
  parts.push(found ? `${plural(found, "item")} protected` : "Nothing sensitive found");
  if (result.placeholders) parts.push(`${plural(result.placeholders, "placeholder")} the AI will see`);
  if (result.blocked) parts.push(`${plural(result.blocked, "password, key or token", "passwords, keys or tokens")} removed`);
  return parts.join(" · ");
}

function OutboundBadge({
  result,
  acknowledged,
  onAcknowledge,
}: {
  result: ProtectTextResult;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  const check = result.check;
  if (check === null) return null;
  if (check.status === "safe") {
    return (
      <p className="copy__verified" role="status">
        <CheckIcon className="copy__verified-icon" />
        <span>Safe to send · checked again on this device: no original values, nothing unprotected.</span>
      </p>
    );
  }
  const review = check.status === "review";
  return (
    <div className={`notice ${review ? "notice--warn" : "notice--error"}`} role="alert">
      <AlertIcon className="notice__icon" />
      <div className="copy__check">
        <p className="notice__title">Send blocked · Review</p>
        <p className="notice__body">
          {review
            ? "The second check found something the first pass did not protect."
            : "An original value is still in the text, written in a way Airlock did not replace. Remove it, then protect the text again."}
        </p>
        <RemainingList items={check.remaining} label="Found in the protected text" />
        {review && (
          <label className="copy__ack">
            <input type="checkbox" checked={acknowledged} onChange={(e) => onAcknowledge(e.target.checked)} />
            <span>I've looked at these items and want to send the text anyway</span>
          </label>
        )}
      </div>
    </div>
  );
}

/**
 * Protect a prompt (or any text) before it goes to an AI tool, then restore
 * the response, all on this device. The conversation keeps placeholders
 * stable across turns.
 */
export function TextProtect({
  conversationId,
  onConversation,
}: {
  conversationId: string | null;
  onConversation: (id: string | null) => void;
}) {
  const platform = usePlatform();
  const adapter = useMemo(() => clipboardAdapter(platform), [platform]);
  const [text, setText] = useState("");
  const [mode, setMode] = useState<PrivacyMode>("reversible");
  const [result, setResult] = useState<ProtectTextResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<EngineError | null>(null);
  const [acknowledged, setAcknowledged] = useState(false);
  const [sent, setSent] = useState(false);
  const [restored, setRestored] = useState(false);
  const [stored, setStored] = useState<number | null>(null);
  const [confirmNew, setConfirmNew] = useState(false);

  const refreshStatus = useCallback(
    async (id: string) => {
      try {
        setStored((await platform.conversationStatus(id)).placeholders);
      } catch (err) {
        if (toEngineError(err).kind === "conversation_not_found") onConversation(null);
      }
    },
    [platform, onConversation],
  );

  useEffect(() => {
    if (conversationId) void refreshStatus(conversationId);
    else setStored(null);
  }, [conversationId, refreshStatus]);

  async function protect() {
    setBusy(true);
    setError(null);
    setResult(null);
    setAcknowledged(false);
    setSent(false);
    setRestored(false);
    try {
      let id = conversationId;
      if (!id) {
        id = await platform.startConversation();
        onConversation(id);
      }
      const protectedText = await platform.protectText(text, { mode, conversationId: id });
      setResult(protectedText);
      void refreshStatus(id);
    } catch (err) {
      setError(toEngineError(err));
    } finally {
      setBusy(false);
    }
  }

  async function send() {
    if (!result) return;
    const outbound = outboundText(result, acknowledged);
    if (outbound === null) return;
    setError(null);
    try {
      await adapter.send(outbound);
      setSent(true);
    } catch {
      setError({
        kind: "clipboard_unavailable",
        message: "Airlock could not put the text on the clipboard.",
        next_step: "Select the protected text and copy it yourself.",
        original_affected: false,
      });
    }
  }

  async function newConversation() {
    setConfirmNew(false);
    setError(null);
    try {
      if (conversationId) await platform.forgetConversation(conversationId);
      onConversation(null);
      setResult(null);
      setSent(false);
      setRestored(false);
    } catch (err) {
      setError(toEngineError(err));
    }
  }

  const outbound = result ? outboundText(result, acknowledged) : null;
  const step = restored ? 3 : sent ? 2 : outbound ? 1 : 0;
  const hint = MODES.find((m) => m.id === mode)!.hint;

  return (
    <>
      <section className="report textai" aria-labelledby="textai-title">
        <header className="report__head">
          <h2 id="textai-title">Protect text for AI</h2>
          <span className="report__meta">Processed on this device</span>
        </header>
        <Boundary step={step} />

        {conversationId && (
          <div className="conversation">
            <p className="conversation__line">
              Conversation <code>{conversationId}</code>
              {stored !== null && <> · {plural(stored, "placeholder")} kept on this device</>}
            </p>
            {confirmNew ? (
              <div className="conversation__confirm" role="group" aria-label="Start a new conversation">
                <span>
                  Delete this conversation's placeholders from this device? Its responses can't be restored afterwards.
                </span>
                <button type="button" className="danger" onClick={() => void newConversation()}>
                  Delete and start new
                </button>
                <button type="button" className="ghost" onClick={() => setConfirmNew(false)}>
                  Cancel
                </button>
              </div>
            ) : (
              <button type="button" className="link" onClick={() => setConfirmNew(true)}>
                New conversation
              </button>
            )}
          </div>
        )}

        <label className="field field--stacked">
          <span className="field__label">Your prompt or text</span>
          <textarea
            className="textbox"
            rows={6}
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Write an email to Rahul Sharma about Project Phoenix…"
          />
        </label>
        <label className="field">
          <span className="field__label">Privacy mode</span>
          <span className="select">
            <select value={mode} onChange={(e) => setMode(e.target.value as PrivacyMode)}>
              {MODES.map((m) => (
                <option key={m.id} value={m.id}>
                  {m.label}
                </option>
              ))}
            </select>
            <ChevronIcon className="select__chevron" />
          </span>
        </label>
        <p className="inline-note">{hint}</p>
        <button type="button" className="primary" disabled={!text.trim() || busy} onClick={() => void protect()}>
          {busy ? "Protecting on this device…" : "Protect"}
        </button>
        {error && <ErrorNotice error={error} aboutFile={false} />}
      </section>

      {result && (
        <section className="report" aria-labelledby="protected-title">
          <header className="report__head">
            <h2 id="protected-title">Protected text</h2>
            <span className="report__meta">{result.profile.name}</span>
          </header>
          {result.withheld ? (
            <div className="notice notice--error" role="alert">
              <AlertIcon className="notice__icon" />
              <div>
                <p className="notice__title">Nothing to send: {plural(result.blocked, "sensitive item")} found</p>
                <p className="notice__body">
                  Block sensitive content is on. Choose another privacy mode to send a protected version.
                </p>
              </div>
            </div>
          ) : (
            <>
              <OutboundBadge result={result} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />
              <textarea className="textbox" rows={6} readOnly value={result.text ?? ""} aria-label="Text to send" />
              <p className="report__structure">{summaryLine(result)}</p>
              <button type="button" className="primary" disabled={outbound === null} onClick={() => void send()}>
                {adapter.label}
              </button>
              {sent && (
                <p className="report__callout" role="status">
                  Copied. Paste it into your AI tool, then paste its response below.
                </p>
              )}
            </>
          )}
        </section>
      )}

      {conversationId && (
        <ResponsePanel key={conversationId} scope={{ conversation_id: conversationId }} onRestored={() => setRestored(true)} />
      )}
    </>
  );
}
