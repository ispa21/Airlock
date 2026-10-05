import type { Progress } from "../engine/types";

const STAGES: Record<string, (done: number, total: number) => string> = {
  pages: (d, t) => `Reading page ${Math.min(d + 1, t)} of ${t}`,
  slides: (d, t) => `Reading slide ${Math.min(d + 1, t)} of ${t}`,
  sheets: (d, t) => `Reading sheet ${Math.min(d + 1, t)} of ${t}`,
  rows: () => "Reading rows",
  parts: () => "Reading comments, notes and hidden parts",
  ocr: (d, t) => `Recognising text in image ${Math.min(d + 1, t)} of ${t}`,
  prepare: () => "Loading the on-device language model…",
  detect: () => "Checking for sensitive data",
};

export function progressLabel(progress: Progress | null): string {
  if (!progress) return "Starting the secure reader…";
  if (progress.total > 0 && progress.done >= progress.total && progress.stage !== "prepare") return "Finishing up…";
  return (STAGES[progress.stage] ?? (() => "Reading document"))(progress.done, progress.total);
}

export function ScanProgress({ progress, onCancel }: { progress: Progress | null; onCancel: () => void }) {
  const fraction = progress && progress.total > 0 ? Math.min(progress.done / progress.total, 1) : null;
  return (
    <div className="scan" role="status" aria-live="polite">
      <div className="scan__row">
        <span className="scan__label">{progressLabel(progress)}</span>
        <button type="button" className="ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>
      <div
        className="bar"
        data-indeterminate={fraction === null || undefined}
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={fraction === null ? undefined : Math.round(fraction * 100)}
      >
        <span className="bar__fill" style={fraction === null ? undefined : { width: `${fraction * 100}%` }} />
      </div>
      <p className="scan__hint">Processing on this device. Nothing is uploaded.</p>
    </div>
  );
}
