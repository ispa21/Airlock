import { useState } from "react";

import type { CategoryGroup, Finding, ScanResult, SeverityLabel } from "../engine/types";
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

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <li className="finding" data-severity={finding.severity}>
      <span className={`sev sev--${finding.severity}`}>{SEVERITY_LABELS[finding.severity]}</span>
      <span className="finding__main">
        <span className="finding__type">{finding.entity_label}</span>
        <code className="finding__preview">{finding.preview}</code>
      </span>
      <span className="finding__where">
        {finding.location.label}
        {finding.hidden && <span className="tag">Hidden</span>}
      </span>
      <span className="finding__how" title={`Detector: ${finding.detector}`}>
        {detectorLabel(finding)} · {Math.round(finding.confidence * 100)}%
      </span>
    </li>
  );
}

export function FindingsReport({ result }: { result: ScanResult }) {
  const [showAll, setShowAll] = useState(false);
  const { summary, findings } = result;
  const rows = showAll ? findings : findings.slice(0, INITIAL_ROWS);

  return (
    <section className="report findings" aria-labelledby="findings-title">
      <header className="report__head">
        <h2 id="findings-title">What Airlock found</h2>
        <span className="report__meta">Checked on this device in {(result.detection_ms / 1000).toFixed(1)} s</span>
      </header>

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
          {summary.hidden > 0 && (
            <p className="report__callout">
              {plural(summary.hidden, "finding")} {summary.hidden === 1 ? "is" : "are"} in hidden parts of the file
              (comments, properties, tracked changes…) that you would not see when opening it.
            </p>
          )}

          <ul className="report__parts" aria-label="Findings by type">
            {summary.by_entity.map((row) => (
              <li key={row.entity_type} className="report__part">
                <span className="report__label">
                  {row.label}
                  <span className="report__group">{CATEGORY_LABELS[row.category] ?? row.category}</span>
                </span>
                <span className="report__count">{number.format(row.count)}</span>
              </li>
            ))}
          </ul>

          <ul className="findings__list" aria-label="Findings">
            {rows.map((f) => (
              <FindingRow key={f.id} finding={f} />
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
        Previews are partly hidden on purpose. Choosing what to mask, redact or block comes next.
      </p>
    </section>
  );
}
