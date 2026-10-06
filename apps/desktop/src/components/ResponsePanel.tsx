import { useState } from "react";

import { usePlatform } from "../engine/PlatformContext";
import {
  toEngineError,
  type EngineError,
  type ResponseAnalysis,
  type ResponseReview,
  type RestoreScope,
} from "../engine/types";
import { plural } from "../lib/format";
import { ErrorNotice } from "./ErrorNotice";
import { CheckIcon } from "./icons";

type Stage =
  | { kind: "empty" }
  | { kind: "received"; analysis: ResponseAnalysis }
  | { kind: "reviewing"; review: ResponseReview }
  | { kind: "restored"; text: string; restored: number; unknown: string[] }
  | { kind: "kept" };

function UnknownNote({ unknown, count }: { unknown: string[]; count: number }) {
  if (count === 0) return null;
  return (
    <p className="inline-note">
      {count === 1 ? "1 placeholder was" : `${count} placeholders were`} not created here, so{" "}
      {count === 1 ? "it stays" : "they stay"} as written: {unknown.join(", ")}
      {count > unknown.length ? "…" : ""}
    </p>
  );
}

/**
 * Paste an AI response; Airlock finds its placeholders and restores the
 * originals on this device: at once, after a review, or not at all.
 */
export function ResponsePanel({
  scope,
  onRestored,
  embedded = false,
}: {
  scope: RestoreScope;
  onRestored?: () => void;
  /** Inside another card (a protected copy) rather than a card of its own. */
  embedded?: boolean;
}) {
  const platform = usePlatform();
  const [text, setText] = useState("");
  const [stage, setStage] = useState<Stage>({ kind: "empty" });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<EngineError | null>(null);
  const [copied, setCopied] = useState(false);

  async function run<T>(work: () => Promise<T>, next: (value: T) => Stage) {
    setBusy(true);
    setError(null);
    try {
      setStage(next(await work()));
    } catch (err) {
      setError(toEngineError(err));
    } finally {
      setBusy(false);
    }
  }

  const check = () => run(() => platform.analyzeResponse(scope, text), (analysis) => ({ kind: "received", analysis }));
  const review = () => run(() => platform.reviewResponse(scope, text), (result) => ({ kind: "reviewing", review: result }));
  const restore = () =>
    run(
      () => platform.restoreResponse(scope, text),
      (result) => {
        onRestored?.();
        return { kind: "restored", text: result.text, restored: result.restored, unknown: result.unknown };
      },
    );

  async function copyRestored(value: string) {
    setError(null);
    try {
      await platform.writeClipboard(value);
      setCopied(true);
    } catch {
      setError({
        kind: "clipboard_unavailable",
        message: "Airlock could not put the text on the clipboard.",
        next_step: "Select the restored text and copy it yourself.",
        original_affected: false,
      });
    }
  }

  return (
    <section className={embedded ? "response response--embedded" : "report response"} aria-labelledby="response-title">
      <header className="report__head">
        <h2 id="response-title">{embedded ? "Restore an AI response" : "AI response"}</h2>
        <span className="report__meta">Restored on this device</span>
      </header>
      <label className="field field--stacked">
        <span className="field__label">Paste the AI's response</span>
        <textarea
          className="textbox"
          rows={5}
          value={text}
          onChange={(e) => {
            setText(e.target.value);
            setStage({ kind: "empty" });
            setCopied(false);
          }}
          placeholder="The response, with placeholders such as PERSON_001"
        />
      </label>

      {error && <ErrorNotice error={error} aboutFile={false} />}

      {(stage.kind === "empty" || stage.kind === "kept") && (
        <button type="button" className="ghost" disabled={!text.trim() || busy} onClick={() => void check()}>
          Check response
        </button>
      )}

      {stage.kind === "received" && (
        <div className="response__received">
          <p className="response__status" role="status">
            AI response received · {plural(stage.analysis.placeholders, "placeholder")}
          </p>
          <UnknownNote unknown={stage.analysis.unknown} count={stage.analysis.unknown_count} />
          {stage.analysis.placeholders > 0 ? (
            <div className="copy__actions">
              <button type="button" className="primary" disabled={busy} onClick={() => void restore()}>
                Restore protected data
              </button>
              <button type="button" className="ghost" disabled={busy} onClick={() => void review()}>
                Review before restoring
              </button>
              <button type="button" className="ghost" disabled={busy} onClick={() => setStage({ kind: "kept" })}>
                Keep anonymized
              </button>
            </div>
          ) : (
            <p className="inline-note">There is nothing to restore in this response.</p>
          )}
        </div>
      )}

      {stage.kind === "reviewing" && (
        <div className="response__review">
          <table className="review-table">
            <caption>What each placeholder becomes</caption>
            <thead>
              <tr>
                <th scope="col">Placeholder</th>
                <th scope="col">Original</th>
                <th scope="col">Type</th>
              </tr>
            </thead>
            <tbody>
              {stage.review.items.map((item) => (
                <tr key={item.placeholder}>
                  <td>
                    <code>{item.placeholder}</code>
                    {item.count > 1 && <span className="review-table__count"> ×{item.count}</span>}
                  </td>
                  <td className="review-table__original">{item.original}</td>
                  <td>{item.entity_label}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <UnknownNote unknown={stage.review.unknown} count={stage.review.unknown_count} />
          <div className="copy__actions">
            <button type="button" className="primary" disabled={busy} onClick={() => void restore()}>
              Restore
            </button>
            <button
              type="button"
              className="ghost"
              disabled={busy}
              onClick={() => setStage({ kind: "received", analysis: stage.review })}
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {stage.kind === "restored" && (
        <div className="response__restored">
          <p className="copy__verified" role="status">
            <CheckIcon className="copy__verified-icon" />
            <span>
              Restored {plural(stage.restored, "placeholder")} on this device. Nothing was sent anywhere.
            </span>
          </p>
          <UnknownNote unknown={stage.unknown} count={stage.unknown.length} />
          <textarea className="textbox" rows={6} readOnly value={stage.text} aria-label="Restored response" />
          <button type="button" className="ghost" onClick={() => void copyRestored(stage.text)}>
            {copied ? "Copied" : "Copy restored text"}
          </button>
        </div>
      )}

      {stage.kind === "kept" && (
        <p className="inline-note" role="status">
          Kept anonymized: the response still shows placeholders. You can restore it later.
        </p>
      )}
    </section>
  );
}
