import { useState } from "react";

import type {
  CategoryGroup,
  CategorySummary,
  Finding,
  MaskStyle,
  PolicyAction,
  ScanResult,
  SeverityLabel,
  TeachKind,
} from "../engine/types";
import { AlertIcon } from "./icons";

export const CATEGORY_LABELS: Record<CategoryGroup, string> = {
  PERSONAL: "Personal",
  GOVERNMENT: "Government IDs",
  FINANCIAL: "Financial",
  BUSINESS: "Business",
  CREDENTIALS: "Credentials & secrets",
  INTELLECTUAL_PROPERTY: "Intellectual property",
  OTHER: "Other",
};

const SEVERITIES: SeverityLabel[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABELS: Record<SeverityLabel, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
};

/** Findings shown before "Show all". */
const INITIAL_ROWS = 25;

const number = new Intl.NumberFormat("en-US");

function plural(n: number, one: string, many = `${one}s`): string {
  return `${number.format(n)} ${n === 1 ? one : many}`;
}

function detectorLabel(finding: Finding): string {
  if (finding.detector.startsWith("custom.")) return "Company rule";
  if (finding.detector.startsWith("ner.")) return "Language model";
  if (finding.detector.startsWith("secret")) return "Secret pattern";
  return "Pattern + validation";
}

/** "E-mail address" → "e-mail address"; acronyms and names ("PAN", "Aadhaar") keep their case. */
export function midSentence(label: string): string {
  const first = label.split(" ")[0] ?? "";
  if (first === first.toUpperCase() || first === "Aadhaar") return label;
  return label.charAt(0).toLowerCase() + label.slice(1);
}

export const ACTION_LABELS: Record<PolicyAction, string> = {
  ALLOW: "Keep",
  GENERALIZE: "Generalise",
  MASK: "Mask",
  REDACT: "Redact",
  BLOCK: "Block",
};
const ACTION_ORDER: PolicyAction[] = ["MASK", "REDACT", "GENERALIZE", "BLOCK", "ALLOW"];

export type ActionHandler = (
  finding: Finding,
  action: PolicyAction | null,
  acknowledgeRisk: boolean,
  maskStyle?: MaskStyle,
) => void;

export type TeachHandler = (finding: Finding, kind: TeachKind) => void;

/** Select value for "Mask, partly hidden". */
const PARTIAL = "MASK:partial";

function selectValue(finding: Finding): string {
  return finding.action === "MASK" && finding.mask_style === "partial" ? PARTIAL : finding.action;
}

function FindingRow({
  finding,
  onAction,
  onTeach,
  busy,
}: {
  finding: Finding;
  onAction?: ActionHandler | undefined;
  onTeach?: TeachHandler | undefined;
  busy: boolean;
}) {
  const [confirming, setConfirming] = useState(false);
  const [teaching, setTeaching] = useState(false);
  const choose = (value: string) => {
    if (!onAction) return;
    if (value === PARTIAL) {
      onAction(finding, "MASK", false, "partial");
      return;
    }
    const action = value === "" ? null : (value as PolicyAction);
    if (action === "ALLOW" && finding.high_risk) {
      setConfirming(true);
      return;
    }
    // Leaving "partly hidden" for a plain mask needs the style named explicitly,
    // in case the profile itself asks for partial masking.
    if (action === "MASK" && finding.mask_style === "partial") {
      onAction(finding, "MASK", false, "typed_placeholder");
      return;
    }
    onAction(finding, action, false);
  };
  const teach = (kind: TeachKind) => {
    setTeaching(false);
    onTeach?.(finding, kind);
  };
  const covered = finding.covered_by !== null && finding.effective_action !== finding.action;
  // Passwords, keys and tokens are never remembered by Airlock, and company-rule
  // matches are managed through the rule itself (Settings).
  const teachable =
    onTeach !== undefined && finding.category !== "CREDENTIALS" && !finding.detector.startsWith("custom.");
  return (
    <li className="finding" data-severity={finding.severity} data-action={finding.effective_action}>
      <span className={`sev sev--${finding.severity}`}>{SEVERITY_LABELS[finding.severity]}</span>
      <span className="finding__main">
        <span className="finding__type">{finding.entity_label}</span>
        <code className="finding__preview">{finding.preview}</code>
      </span>
      <span className="finding__where">
        {finding.location.label}
        {finding.hidden && <span className="tag">Hidden</span>}
        <span className="finding__how" title={`Detector: ${finding.detector}`}>
          {detectorLabel(finding)} · {Math.round(finding.confidence * 100)}%
        </span>
      </span>
      <span className="finding__action">
        <select
          aria-label={`Action for ${finding.entity_label} ${finding.id}`}
          className={`action action--${finding.action.toLowerCase()}`}
          value={selectValue(finding)}
          disabled={!onAction || busy}
          onChange={(e) => choose(e.target.value)}
        >
          {ACTION_ORDER.filter((a) => a !== "GENERALIZE" || finding.generalizable).flatMap((a) => [
            <option key={a} value={a}>
              {ACTION_LABELS[a]}
            </option>,
            ...(a === "MASK" && finding.partial_available
              ? [
                  <option key={PARTIAL} value={PARTIAL}>
                    Mask partly
                  </option>,
                ]
              : []),
          ])}
          {finding.overridden && <option value="">Reset to profile</option>}
        </select>
      </span>
      <p className="finding__why">
        {finding.explanation}
        {teachable && !teaching && (
          <>
            {" "}
            <button
              type="button"
              className="link finding__teach-link"
              disabled={busy}
              aria-label={`Teach Airlock about ${finding.entity_label} ${finding.id}`}
              onClick={() => setTeaching(true)}
            >
              Teach Airlock
            </button>
          </>
        )}
      </p>
      <p className="finding__reason">
        {finding.reason}
        {covered && ` Part of a larger finding that is set to ${ACTION_LABELS[finding.effective_action].toLowerCase()}.`}
      </p>
      {teaching && (
        <div className="finding__teach" role="group" aria-label={`Teach Airlock about ${finding.entity_label}`}>
          <p className="finding__teach-title">Remember this for every document?</p>
          <div className="finding__teach-actions">
            <button type="button" className="ghost" onClick={() => teach("not_sensitive")}>
              It's not sensitive
            </button>
            <button type="button" className="ghost" onClick={() => teach("company_rule")}>
              Always protect it
            </button>
            <button type="button" className="ghost" onClick={() => setTeaching(false)}>
              Cancel
            </button>
          </div>
          <p className="report__foot">
            "Not sensitive" keeps only a one-way fingerprint of the value. "Always protect" saves it as a company rule
            on this device. You can undo either in Settings.
          </p>
        </div>
      )}
      {confirming && (
        <div className="finding__confirm" role="alertdialog" aria-label="Confirm keeping this finding">
          <span>
            Keep this {midSentence(finding.entity_label)}? It would be shared with the AI as it is.
          </span>
          <button
            type="button"
            className="danger"
            onClick={() => {
              setConfirming(false);
              onAction?.(finding, "ALLOW", true);
            }}
          >
            Keep anyway
          </button>
          <button type="button" className="ghost" onClick={() => setConfirming(false)}>
            Cancel
          </button>
        </div>
      )}
    </li>
  );
}

const ACTION_PAST: Record<PolicyAction, string> = {
  ALLOW: "kept",
  MASK: "masked",
  REDACT: "redacted",
  GENERALIZE: "generalised",
  BLOCK: "blocked",
};

function CategoryCard({ row, types }: { row: CategorySummary; types: ScanResult["summary"]["by_entity"] }) {
  const actions = ACTION_ORDER.filter((a) => (row.actions[a] ?? 0) > 0)
    .map((a) => `${number.format(row.actions[a] ?? 0)} ${ACTION_PAST[a]}`)
    .join(" · ");
  return (
    <li className="category" data-category={row.category}>
      <span className="category__head">
        <span className="category__name">{CATEGORY_LABELS[row.category] ?? row.category}</span>
        <span className={`sev sev--${row.max_severity}`}>{SEVERITY_LABELS[row.max_severity]}</span>
      </span>
      <span className="category__count">
        {plural(row.count, "finding")} · {plural(row.distinct, "value")}
      </span>
      <span className="category__types">
        {types
          .filter((t) => t.category === row.category)
          .map((t) => `${t.label} ${number.format(t.count)}`)
          .join(" · ")}
      </span>
      {actions && <span className="category__actions">{actions}</span>}
    </li>
  );
}

export function FindingsReport({
  result,
  onAction,
  onTeach,
  note = null,
  busy = false,
}: {
  result: ScanResult;
  onAction?: ActionHandler | undefined;
  onTeach?: TeachHandler | undefined;
  /** Confirmation of the last "Teach Airlock" step or refresh. */
  note?: string | null;
  busy?: boolean;
}) {
  const [showAll, setShowAll] = useState(false);
  const { summary, findings, policy } = result;
  const rows = showAll ? findings : findings.slice(0, INITIAL_ROWS);

  return (
    <section className="report findings" aria-labelledby="findings-title">
      <header className="report__head">
        <h2 id="findings-title">What Airlock found</h2>
        <span className="report__meta">Checked on this device in {(result.detection_ms / 1000).toFixed(1)} s</span>
      </header>
      {note && (
        <p className="report__callout" role="status">
          {note}
        </p>
      )}

      {summary.total === 0 ? (
        <p className="findings__none">No sensitive data was found by the detectors that ran.</p>
      ) : (
        <>
          <p className="report__structure">
            {plural(summary.total, "finding")} · {plural(summary.distinct_values, "distinct value")}
          </p>
          <ul className="sev-counts" aria-label="Findings by severity">
            {SEVERITIES.filter((s) => summary.by_severity[s] > 0).map((s) => (
              <li key={s} className={`sev sev--${s}`}>
                {SEVERITY_LABELS[s]} <strong>{number.format(summary.by_severity[s])}</strong>
              </li>
            ))}
          </ul>
          {policy.blocked > 0 ? (
            <div className="notice notice--error" role="status">
              <AlertIcon className="notice__icon" />
              <div>
                <p className="notice__title">
                  {plural(policy.blocked, "item")} {policy.blocked === 1 ? "is" : "are"} blocked
                </p>
                <p className="notice__body">
                  Credentials and other blocked data can't be shared as they are. Choose Redact or Mask for them,
                  or remove them from the file.
                </p>
              </div>
            </div>
          ) : (
            <p className="findings__ready" role="status">
              Nothing is blocked. With {policy.profile.name}, Airlock will{" "}
              {(["MASK", "REDACT", "GENERALIZE"] as PolicyAction[])
                .filter((a) => policy.actions[a] > 0)
                .map((a) => `${ACTION_LABELS[a].toLowerCase()} ${number.format(policy.actions[a])}`)
                .join(", ") || "change nothing"}
              {policy.actions.ALLOW > 0 ? ` and keep ${number.format(policy.actions.ALLOW)}` : ""}.
            </p>
          )}
          {summary.hidden > 0 && (
            <p className="report__callout">
              {plural(summary.hidden, "finding")} {summary.hidden === 1 ? "is" : "are"} in hidden parts of the file
              (comments, properties, tracked changes…) that you would not see when opening it.
            </p>
          )}

          <ul className="categories" aria-label="Findings by category">
            {summary.by_category.map((row) => (
              <CategoryCard key={row.category} row={row} types={summary.by_entity} />
            ))}
          </ul>

          <ul className="findings__list" aria-label="Findings">
            {rows.map((f) => (
              <FindingRow key={f.id} finding={f} onAction={onAction} onTeach={onTeach} busy={busy} />
            ))}
          </ul>
          {!showAll && findings.length > INITIAL_ROWS && (
            <button type="button" className="ghost" onClick={() => setShowAll(true)}>
              Show all {number.format(findings.length)} findings
            </button>
          )}
          {summary.listed < summary.total && (
            <p className="report__foot">
              Showing the first {number.format(summary.listed)} findings. All {number.format(summary.total)} are
              counted above.
            </p>
          )}
        </>
      )}

      {summary.detectors.ner === "unavailable" && (
        <div className="notice notice--warn">
          <AlertIcon className="notice__icon" />
          <p className="notice__title">
            The on-device language model could not be loaded, so names of people and organisations were not checked.
          </p>
        </div>
      )}
      {summary.detectors.ner === "partial" && (
        <p className="report__foot">
          This document is very large. Names of people and organisations were checked in the first part only.
        </p>
      )}
      {summary.detectors.rule_timeouts > 0 && (
        <p className="report__foot">
          A company rule pattern was too slow on this document and was skipped for part of it.
        </p>
      )}
      <p className="report__foot">
        Previews are partly hidden on purpose. A change applies to every place the same value appears. "Mask partly"
        keeps a recognisable part, such as the last four digits; it cannot be turned back into the original.
      </p>
    </section>
  );
}
