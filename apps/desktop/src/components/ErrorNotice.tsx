import type { EngineError } from "../engine/types";
import { AlertIcon } from "./icons";

export function ErrorNotice({ error }: { error: EngineError }) {
  return (
    <div className="notice notice--error" role="alert">
      <AlertIcon className="notice__icon" />
      <div>
        <p className="notice__title">{error.message}</p>
        {error.next_step && <p className="notice__body">{error.next_step}</p>}
        {error.original_affected === false && (
          <p className="notice__foot">Your original file was not changed.</p>
        )}
      </div>
    </div>
  );
}
