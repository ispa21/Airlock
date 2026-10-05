import type { PolicySummary, SanitizeResult } from "../engine/types";
import { formatBytes } from "../lib/format";
import { AlertIcon } from "./icons";

const number = new Intl.NumberFormat("en-US");

export type CopyState =
  | { status: "none" }
  | { status: "running" }
  | { status: "ready"; result: SanitizeResult }
  | { status: "stale" };

function replacedLine(result: SanitizeResult): string {
  const parts: string[] = [];
  if (result.replaced.MASK) parts.push(`${number.format(result.replaced.MASK)} replaced by placeholders`);
  if (result.replaced.REDACT) parts.push(`${number.format(result.replaced.REDACT)} removed`);
  if (result.replaced.GENERALIZE) parts.push(`${number.format(result.replaced.GENERALIZE)} generalised`);
  return parts.length ? parts.join(" · ") : "Nothing needed to change";
}

export function ProtectedCopy({
  state,
  policy,
  onCreate,
  onCancel,
}: {
  state: CopyState;
  policy: PolicySummary;
  onCreate: () => void;
  onCancel: () => void;
}) {
  const blocked = policy.blocked > 0;
  return (
    <section className="report copy" aria-labelledby="copy-title">
      <header className="report__head">
        <h2 id="copy-title">Protected copy</h2>
        {state.status === "ready" && <span className="report__meta">{formatBytes(state.result.size_bytes)}</span>}
      </header>

      {state.status === "running" ? (
        <div className="scan" role="status" aria-live="polite">
          <div className="scan__row">
            <span className="scan__label">Writing the protected copy…</span>
            <button type="button" className="ghost" onClick={onCancel}>
              Cancel
            </button>
          </div>
          <div className="bar" data-indeterminate role="progressbar" aria-valuemin={0} aria-valuemax={100}>
            <span className="bar__fill" />
          </div>
        </div>
      ) : state.status === "ready" ? (
        <div className="copy__ready">
          <p className="copy__name">{state.result.file_name}</p>
          <p className="report__structure">{replacedLine(state.result)}</p>
          {state.result.removed.length > 0 && (
            <ul className="report__unread" aria-label="Removed from the copy">
              {state.result.removed.map((item) => (
                <li key={item.label}>
                  {item.label}
                  {item.count > 1 ? ` (${item.count})` : ""}
                </li>
              ))}
            </ul>
          )}
          {state.result.vault.stored && (
            <p className="report__foot">
              {number.format(state.result.vault.entries)} placeholder
              {state.result.vault.entries === 1 ? " is" : "s are"} kept in Airlock's encrypted vault on this device,
              so they can be turned back into the original values later. They are never sent anywhere.
            </p>
          )}
          <p className="report__foot">
            Next, Airlock reads the copy again and re-checks it before it can be saved. That step comes in the next
            update. Your original file was not changed.
          </p>
        </div>
      ) : (
        <>
          {state.status === "stale" && (
            <p className="inline-note">Your choices changed, so the previous copy was discarded.</p>
          )}
          {blocked && (
            <div className="notice notice--warn">
              <AlertIcon className="notice__icon" />
              <p className="notice__title">Resolve the blocked items above before creating a copy.</p>
            </div>
          )}
          <p className="report__foot">
            Airlock writes a new file with your choices applied and removes hidden content it cannot check. Your
            original file is never changed.
          </p>
        </>
      )}

      {state.status !== "running" && (
        <button type="button" className="primary" disabled={blocked} onClick={onCreate}>
          {state.status === "ready" ? "Create Again" : "Create Protected Copy"}
        </button>
      )}
    </section>
  );
}
