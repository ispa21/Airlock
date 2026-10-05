import type { EngineInfo, ExtractSummary, InspectResult, Progress } from "./types";

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
  /**
   * Read every text-bearing part of the file locally. `tag` identifies the
   * request for progress updates and cancellation.
   */
  extract(path: string, tag: string, onProgress: (progress: Progress) => void): Promise<ExtractSummary>;
  /** Cancel the extraction started with `tag`; it then rejects with kind "cancelled". */
  cancel(tag: string): Promise<void>;
  pickFile(): Promise<string | null>;
  /** Subscribe to OS file drops. Returns an unsubscribe function. */
  onFileDrop(handlers: DropHandlers): Promise<() => void>;
}
