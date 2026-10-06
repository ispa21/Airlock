import type {
  ConversationStatus,
  EngineInfo,
  ExportResult,
  InspectResult,
  LicenseStatus,
  NewRule,
  Override,
  PolicyUpdate,
  PrivacyMode,
  Profile,
  ProfileChanges,
  ProfileList,
  Progress,
  ProtectTextResult,
  ResponseAnalysis,
  ResponseRestore,
  ResponseReview,
  RestoreScope,
  Rule,
  RuleList,
  SanitizeResult,
  ScanResult,
  TeachKind,
  VerifyResult,
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
  /**
   * Write the protected copy (in Airlock's private work folder). Cancellable by `tag`.
   * With `conversationId` the copy shares that conversation's placeholders (privacy workspace).
   */
  sanitize(
    scanId: string,
    tag: string,
    onProgress: (progress: Progress) => void,
    conversationId?: string | null,
  ): Promise<SanitizeResult>;
  licenseStatus(): Promise<LicenseStatus>;
  /** The host shows the open dialog and checks the file. */
  importLicenseFile(): Promise<LicenseStatus>;
  /** Licence text pasted from an e-mail. */
  importLicenseText(text: string): Promise<LicenseStatus>;
  /** Online activation with a licence key (the app's only network request). */
  activateLicense(key: string): Promise<LicenseStatus>;
  removeLicense(): Promise<LicenseStatus>;
  /** Read the copy back, search it and scan it again. Cancellable by `tag`. */
  verify(artifactId: string, tag: string, onProgress: (progress: Progress) => void): Promise<VerifyResult>;
  /**
   * Save a checked copy (or its text). The host shows the save dialog; the UI
   * never names a path. Resolves `{saved: false}` if the user cancels.
   */
  saveCopy(artifactId: string, options: { asText: boolean; acknowledgeReview: boolean }): Promise<ExportResult>;
  /** The checked copy's readable text, for pasting into an AI tool. */
  copyText(artifactId: string, acknowledgeReview: boolean): Promise<string>;
  writeClipboard(text: string): Promise<void>;
  /** Delete a protected copy that is no longer wanted. */
  discardCopy(artifactId: string): Promise<void>;
  /** Ask the engine to forget a scan's text and findings. */
  discard(scanId: string): Promise<void>;
  /** Cancel the scan started with `tag`; it then rejects with kind "cancelled". */
  cancel(tag: string): Promise<void>;
  pickFile(): Promise<string | null>;
  /**
   * Protect a prompt or other text for an AI tool, locally. In a conversation the
   * same value keeps its placeholder in every turn. The result carries the outbound check.
   */
  protectText(text: string, options: { mode: PrivacyMode; conversationId: string | null }): Promise<ProtectTextResult>;
  /** A new conversation scope; returns its id (AIRLOCK-2026-001928). */
  startConversation(): Promise<string>;
  conversationStatus(conversationId: string): Promise<ConversationStatus>;
  /** Conversations with stored placeholders (ids, times and counts only). */
  listConversations(): Promise<ConversationStatus[]>;
  /** Delete a conversation's stored placeholders for good. */
  forgetConversation(conversationId: string): Promise<void>;
  /** Count the placeholders in an AI response (no values). */
  analyzeResponse(scope: RestoreScope, text: string): Promise<ResponseAnalysis>;
  /** Each placeholder in the response and its original, for review before restoring. */
  reviewResponse(scope: RestoreScope, text: string): Promise<ResponseReview>;
  /** Put the originals back into the response, on this device. */
  restoreResponse(scope: RestoreScope, text: string): Promise<ResponseRestore>;
  /** Subscribe to OS file drops. Returns an unsubscribe function. */
  onFileDrop(handlers: DropHandlers): Promise<() => void>;
}
