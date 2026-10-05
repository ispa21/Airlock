import type { EngineState } from "../engine/types";
import { CheckIcon } from "./icons";

export function TrustBar({ engine, onRetry }: { engine: EngineState; onRetry: () => void }) {
  let tone: "ok" | "wait" | "bad";
  let label: string;
  if (engine.state === "starting") {
    tone = "wait";
    label = "Starting local engine…";
  } else if (engine.state === "unavailable") {
    tone = "bad";
    label = "Local engine unavailable";
  } else if (!engine.info.network_isolation) {
    tone = "wait";
    label = "Network isolation inactive";
  } else {
    tone = "ok";
    label = "Processing locally";
  }

  return (
    <footer className="trust" aria-label="Privacy status">
      <span className="trust__item" data-tone={tone} role="status" aria-live="polite">
        <span className="pulse" aria-hidden />
        {label}
        {engine.state === "unavailable" && (
          <button type="button" className="link trust__retry" onClick={onRetry}>
            Retry
          </button>
        )}
      </span>
      <span className="trust__item">
        <CheckIcon className="trust__check" /> No document uploads
      </span>
      <span className="trust__item">
        <CheckIcon className="trust__check" /> Internet not required
      </span>
    </footer>
  );
}
