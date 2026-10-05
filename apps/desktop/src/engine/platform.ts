import type {
  EngineInfo,
  InspectResult,
  NewRule,
  Override,
  PolicyUpdate,
  Profile,
  ProfileChanges,
  ProfileList,
  Progress,
  Rule,
  RuleList,
  SanitizeResult,
  ScanResult,
  TeachKind,
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
  /** Detect again with the current rules, allow-list and profile (no re-reading of the file). */
  refresh(scanId: string): Promise<PolicyUpdate>;
  /** Remember a decision about one finding's value for every document, then refresh. */
  teach(scanId: string, findingId: string, kind: TeachKind): Promise<PolicyUpdate>;
  /** How many values are marked "not sensitive". */
  allowListCount(): Promise<number>;
  /** Forget every "not sensitive" decision. */
  clearAllowList(): Promise<void>;
  listRules(): Promise<RuleList>;
  createRule(rule: NewRule): Promise<Rule>;
  updateRule(id: string, changes: Partial<NewRule> & { enabled?: boolean }): Promise<Rule>;
  deleteRule(id: string): Promise<void>;
  /** Duplicate a profile (built-in ones can't be edited). */
  createProfile(name: string, baseId: string): Promise<Profile>;
  updateProfile(id: string, changes: ProfileChanges): Promise<Profile>;
  deleteProfile(id: string): Promise<void>;
  setDefaultProfile(id: string): Promise<void>;
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
