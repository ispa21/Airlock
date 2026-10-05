import type { EngineInfo, InspectResult } from "./types";

export interface DropHandlers {
  onHover: (hovering: boolean) => void;
  onDrop: (paths: string[]) => void;
}

/**
 * Everything the UI needs from the outside world. The desktop build uses the
 * Tauri implementation; tests and the browser preview inject their own.
 */
export interface Platform {
  readonly kind: "desktop" | "preview";
  engineInfo(): Promise<EngineInfo>;
  inspect(path: string): Promise<InspectResult>;
  pickFile(): Promise<string | null>;
  /** Subscribe to OS file drops. Returns an unsubscribe function. */
  onFileDrop(handlers: DropHandlers): Promise<() => void>;
}
