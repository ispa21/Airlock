import type {
  EngineInfo,
  InspectResult,
  Override,
  PolicyUpdate,
  ProfileList,
  Progress,
  SanitizeResult,
  ScanResult,
} from "./types";

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
   * Read every text-bearing part of the file and detect sensitive data, all
   * locally. `tag` identifies the request for progress and cancellation.
   */
  scan(path: string, profileId: string, tag: string, onProgress: (progress: Progress) => void): Promise<ScanResult>;
  /** Privacy profiles and the user's default. */
  listProfiles(): Promise<ProfileList>;
  /** Re-apply a different profile to a finished scan (keeps the user's own decisions). */
  setProfile(scanId: string, profileId: string): Promise<PolicyUpdate>;
  /** Change actions for findings; `acknowledgeRisk` is needed to keep a critical one. */
  override(scanId: string, overrides: Override[], acknowledgeRisk?: boolean): Promise<PolicyUpdate>;
  /** Write the protected copy (in Airlock's private work folder). Cancellable by `tag`. */
  sanitize(scanId: string, tag: string, onProgress: (progress: Progress) => void): Promise<SanitizeResult>;
  /** Delete a protected copy that is no longer wanted. */
  discardCopy(artifactId: string): Promise<void>;
  /** Ask the engine to forget a scan's text and findings. */
  discard(scanId: string): Promise<void>;
  /** Cancel the scan started with `tag`; it then rejects with kind "cancelled". */
  cancel(tag: string): Promise<void>;
  pickFile(): Promise<string | null>;
  /** Subscribe to OS file drops. Returns an unsubscribe function. */
  onFileDrop(handlers: DropHandlers): Promise<() => void>;
}
