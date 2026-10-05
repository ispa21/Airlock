import { useState } from "react";

import type { RiskFactor, RiskLevel, RiskScore, RiskSummary } from "../engine/types";

export const RISK_LEVEL_LABELS: Record<RiskLevel, string> = {
  none: "None",
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

function Score({ id, title, score }: { id: string; title: string; score: RiskScore }) {
  return (
    <div className="risk__score" data-level={score.level} aria-labelledby={`${id}-title`} role="group">
      <span id={`${id}-title`} className="risk__title">
        {title}
      </span>
      <span className="risk__number" aria-label={`${title}: ${score.score} out of 100, ${score.level}`}>
        <strong>{score.score}</strong>
        <span className="risk__of">/100</span>
      </span>
      <span className={`risk__level risk__level--${score.level}`}>{RISK_LEVEL_LABELS[score.level]}</span>
      <span className="risk__bar" aria-hidden>
        <span className="risk__fill" style={{ width: `${score.score}%` }} />
      </span>
    </div>
  );
}

function Factors({ label, factors, empty }: { label: string; factors: RiskFactor[]; empty: string }) {
  return (
    <div className="risk__factors">
      <p className="risk__factors-title">{label}</p>
      {factors.length === 0 ? (
        <p className="report__foot">{empty}</p>
      ) : (
        <ul aria-label={label}>
          {factors.map((f) => (
            <li key={f.id}>
              <span className="risk__factor">
                {f.label}
                <span className="risk__detail">{f.detail}</span>
              </span>
              <span className="risk__points">+{f.points}</span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/**
 * The score is a plain sum of named factors computed on this device, so every
 * point can be shown. "Protected copy" counts only what would still be shared:
 * findings set to Keep, and anything still blocked.
 */
export function RiskCard({ risk }: { risk: RiskSummary }) {
  const [open, setOpen] = useState(false);
  const { before, after } = risk;
  return (
    <section className="report risk" aria-labelledby="risk-heading">
      <header className="report__head">
        <h2 id="risk-heading">Privacy risk</h2>
        <span className="report__meta">Scored on this device</span>
      </header>
      <div className="risk__pair">
        <Score id="risk-before" title="As it is" score={before} />
        <Score id="risk-after" title="Protected copy" score={after} />
      </div>
      <button type="button" className="link risk__toggle" aria-expanded={open} onClick={() => setOpen(!open)}>
        {open ? "Hide the breakdown" : "Why this score?"}
      </button>
      {open && (
        <div className="risk__why">
          <Factors label="As it is" factors={before.factors} empty="Nothing sensitive was found." />
          <Factors
            label="Still shared by the protected copy"
            factors={after.factors}
            empty="Nothing sensitive would be shared."
          />
          <p className="report__foot">
            Each kind of data adds points for its first value and fewer for each further one, up to a limit. The same
            findings always give the same score. Blocked items count until you choose what to do with them.
          </p>
        </div>
      )}
    </section>
  );
}
