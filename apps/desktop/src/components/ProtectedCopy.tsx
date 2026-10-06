import { useState } from "react";

import type { PolicySummary, RemainingItem, SanitizeResult, VerifyResult } from "../engine/types";
import { formatBytes, plural } from "../lib/format";
import { AlertIcon, CheckIcon } from "./icons";
import { ResponsePanel } from "./ResponsePanel";

const number = new Intl.NumberFormat("en-US");

export type CopyState =
  | { status: "none" }
  | { status: "running" }
  | { status: "verifying"; result: SanitizeResult }
  | { status: "ready"; result: SanitizeResult; check: VerifyResult }
  | { status: "stale" };

/** Opt-in privacy workspace: the copy shares a conversation's placeholders. */
export interface Workspace {
  conversationId: string;
  shared: boolean;
  onShare: (shared: boolean) => void;
}

export interface CopyActions {
  onCreate: () => void;
  onCancel: () => void;
  onSave: (asText: boolean, acknowledgeReview: boolean) => void;
  onCopyText: (acknowledgeReview: boolean) => void;
}

function replacedLine(result: SanitizeResult): string {
  const parts: string[] = [];
  if (result.replaced.MASK) parts.push(`${number.format(result.replaced.MASK)} replaced by placeholders`);
  if (result.replaced.REDACT) parts.push(`${number.format(result.replaced.REDACT)} removed`);
  if (result.replaced.GENERALIZE) parts.push(`${number.format(result.replaced.GENERALIZE)} generalised`);
  return parts.length ? parts.join(" · ") : "Nothing needed to change";
}

export function RemainingList({ items, label }: { items: RemainingItem[]; label: string }) {
  return (
    <ul className="remaining" aria-label={label}>
      {items.map((item, i) => (
        <li key={`${item.entity_type}-${i}`} className="remaining__item">
          <span className="finding__type">{item.entity_label}</span>
          <code className="finding__preview">{item.preview}</code>
          <span className="remaining__where">{item.location.label}</span>
        </li>
      ))}
    </ul>
  );
}

function Check({ check, acknowledged, onAcknowledge }: {
  check: VerifyResult;
  acknowledged: boolean;
  onAcknowledge: (value: boolean) => void;
}) {
  if (check.status === "passed") {
    return (
      <p className="copy__verified" role="status">
        <CheckIcon className="copy__verified-icon" />
        <span>
          Checked: Airlock read the copy back and none of the{" "}
          {plural(check.checked.protected_values, "protected value")} {check.checked.protected_values === 1 ? "is" : "are"}{" "}
          in it{check.checked.ocr_used ? ", including text in pictures" : ""}.
        </span>
      </p>
    );
  }
  if (check.status === "review") {
    const items = check.remaining.filter((r) => r.reason === "new");
    return (
      <div className="notice notice--warn" role="status">
        <AlertIcon className="notice__icon" />
        <div className="copy__check">
          <p className="notice__title">
            Airlock found {plural(check.new_count, "item")} in the copy that it had not flagged before
          </p>
          <p className="notice__body">
            They were not protected. Look at them before the copy leaves Airlock.
          </p>
          <RemainingList items={items} label="Found in the copy" />
          <label className="copy__ack">
            <input type="checkbox" checked={acknowledged} onChange={(e) => onAcknowledge(e.target.checked)} />
            <span>I've looked at these items and want to use the copy anyway</span>
          </label>
        </div>
      </div>
    );
  }
  const leaks = check.remaining.filter((r) => r.reason === "protected");
  return (
    <div className="notice notice--error" role="alert">
      <AlertIcon className="notice__icon" />
      <div className="copy__check">
        <p className="notice__title">This copy can't leave Airlock</p>
        <p className="notice__body">
          {check.remaining_count > 0
            ? `Airlock read the copy back and found ${plural(check.remaining_count, "protected value")} still in it.`
            : "Part of the copy could not be read back, so it could not be checked."}{" "}
          Nothing was saved. Choose Redact for the items listed, then create the copy again.
        </p>
        {leaks.length > 0 && <RemainingList items={leaks} label="Still in the copy" />}
        {check.unreadable.length > 0 && (
          <ul className="report__unread" aria-label="Could not be checked">
            {check.unreadable.map((u) => (
              <li key={u.label}>{u.label}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

export function ProtectedCopy({
  state,
  policy,
  note,
  busy,
  actions,
  workspace = null,
}: {
  state: CopyState;
  policy: PolicySummary;
  /** Confirms the last save or copy. */
  note: string | null;
  busy: boolean;
  actions: CopyActions;
  workspace?: Workspace | null;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [restoring, setRestoring] = useState(false);
  const blocked = policy.blocked > 0;
  const working = state.status === "running" || state.status === "verifying";
  const check = state.status === "ready" ? state.check : null;
  const usable = check !== null && (check.status === "passed" || (check.status === "review" && acknowledged));

  return (
    <section className="report copy" aria-labelledby="copy-title">
      <header className="report__head">
        <h2 id="copy-title">Protected copy</h2>
        {state.status === "ready" && <span className="report__meta">{formatBytes(state.result.size_bytes)}</span>}
      </header>

      {working ? (
        <div className="scan" role="status" aria-live="polite">
          <div className="scan__row">
            <span className="scan__label">
              {state.status === "running" ? "Writing the protected copy…" : "Checking the copy: reading it back…"}
            </span>
            <button type="button" className="ghost" onClick={actions.onCancel}>
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
          <Check check={state.check} acknowledged={acknowledged} onAcknowledge={setAcknowledged} />
          {state.check.status !== "failed" && (
            <div className="copy__actions">
              <button
                type="button"
                className="primary"
                disabled={!usable || busy}
                onClick={() => actions.onSave(false, acknowledged)}
              >
                Save Protected Copy…
              </button>
              <button
                type="button"
                className="ghost"
                disabled={!usable || busy}
                onClick={() => actions.onCopyText(acknowledged)}
              >
                Copy Text for AI
              </button>
              <button
                type="button"
                className="ghost"
                disabled={!usable || busy}
                onClick={() => actions.onSave(true, acknowledged)}
              >
                Save as Text…
              </button>
            </div>
          )}
          {note && (
            <p className="report__callout" role="status">
              {note}
            </p>
          )}
          {state.result.vault.stored && (
            <p className="report__foot">
              {number.format(state.result.vault.entries)} placeholder
              {state.result.vault.entries === 1 ? " is" : "s are"} kept in Airlock's encrypted vault on this device,
              so they can be turned back into the original values later. They are never sent anywhere.
            </p>
          )}
          {state.result.vault.stored &&
            (restoring ? (
              <ResponsePanel key={state.result.artifact_id} scope={{ artifact_id: state.result.artifact_id }} embedded />
            ) : (
              <button type="button" className="ghost" onClick={() => setRestoring(true)}>
                Restore an AI response…
              </button>
            ))}
          <p className="report__foot">Your original file was not changed.</p>
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
            Airlock writes a new file with your choices applied and removes hidden content it cannot check, then
            reads the copy back to make sure nothing protected is left. Your original file is never changed.
          </p>
          {workspace && (
            <label className="copy__ack">
              <input
                type="checkbox"
                checked={workspace.shared}
                onChange={(e) => workspace.onShare(e.target.checked)}
              />
              <span>
                Use the same placeholders as conversation {workspace.conversationId}, so the AI can connect this file
                with your prompts
              </span>
            </label>
          )}
        </>
      )}

      {!working && (
        <button
          type="button"
          className={state.status === "ready" ? "ghost" : "primary"}
          disabled={blocked || busy}
          onClick={() => {
            setAcknowledged(false);
            actions.onCreate();
          }}
        >
          {state.status === "ready" ? "Create Again" : "Create Protected Copy"}
        </button>
      )}
    </section>
  );
}
