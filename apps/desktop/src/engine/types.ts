/** Shapes shared with the Rust host and the Python engine (see docs/IPC.md). */

export interface EngineInfo {
  engine_version: string;
  protocol_version: string;
  network_isolation: boolean;
  methods: string[];
}

export type EngineState =
  | { state: "starting" }
  | { state: "ready"; info: EngineInfo }
  | { state: "unavailable"; error: EngineError };

export interface EngineError {
  kind: string;
  message: string;
  next_step?: string | null;
  original_affected?: boolean;
}

export type FormatFamily =
  | "document"
  | "spreadsheet"
  | "presentation"
  | "image"
  | "text"
  | "config"
  | "code";

export interface InspectResult {
  file_name: string;
  extension: string;
  size_bytes: number;
  format: string;
  format_label: string;
  family: FormatFamily;
  support: "available" | "planned" | "unsupported";
  scannable: boolean;
}

export function isEngineError(value: unknown): value is EngineError {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as EngineError).kind === "string" &&
    typeof (value as EngineError).message === "string"
  );
}

export function toEngineError(value: unknown): EngineError {
  if (isEngineError(value)) return value;
  return {
    kind: "unexpected",
    message: "Airlock hit an unexpected problem.",
    next_step: "Try again. If it keeps happening, restart Airlock.",
    original_affected: false,
  };
}

/** Where text was found; mirrors the engine's SegmentKind. */
export type SegmentKind =
  | "body"
  | "header_footer"
  | "note"
  | "comment"
  | "tracked_change"
  | "hidden"
  | "metadata"
  | "link"
  | "field"
  | "alt_text"
  | "name"
  | "template"
  | "chart"
  | "ocr";

export interface ExtractedPart {
  kind: SegmentKind;
  segments: number;
  chars: number;
  words: number;
}

export interface UnreadItem {
  kind: string;
  label: string;
  count: number;
}

/** Content-free summary returned by `document.extract`. */
export interface ExtractSummary {
  format: string;
  format_label: string;
  segment_count: number;
  char_count: number;
  word_count: number;
  parts: ExtractedPart[];
  counts: Partial<Record<"pages" | "slides" | "sheets" | "rows" | "lines" | "paragraphs" | "images_ocr" | "embedded", number>>;
  ocr_used: boolean;
  unextracted: UnreadItem[];
  unextracted_total: number;
  duration_ms: number;
}

export interface Progress {
  stage: string;
  done: number;
  total: number;
}

export type SeverityLabel = "critical" | "high" | "medium" | "low";

export type CategoryGroup =
  | "PERSONAL"
  | "GOVERNMENT"
  | "FINANCIAL"
  | "BUSINESS"
  | "CREDENTIALS"
  | "INTELLECTUAL_PROPERTY"
  | "OTHER";

/** One detection. The engine sends a masked preview, never the raw value. */
export interface Finding {
  id: string;
  entity_type: string;
  entity_label: string;
  category: CategoryGroup;
  severity: SeverityLabel;
  confidence: number;
  detector: string;
  corroborated_by: string[];
  rule_id: string | null;
  preview: string;
  location: { kind: SegmentKind; label: string };
  hidden: boolean;
  value_group: number;
  /** What the profile (or the user) decided for this finding. */
  action: PolicyAction;
  /** What actually applies once overlapping findings are merged. */
  effective_action: PolicyAction;
  reason: string;
  overridden: boolean;
  covered_by: string | null;
  generalizable: boolean;
  /** Keeping it (ALLOW) needs an explicit confirmation. */
  high_risk: boolean;
  /** How MASK replaces it (placeholder, fake value, partly hidden). */
  mask_style: MaskStyle;
  /** Partial masking is offered (never for credentials). */
  partial_available: boolean;
  /** Why the detector flagged it: the rule that matched, never the value. */
  explanation: string;
}

export type MaskStyle = "typed_placeholder" | "placeholder" | "synthetic" | "partial";

export type RiskLevel = "none" | "low" | "medium" | "high" | "critical";

export interface RiskFactor {
  id: string;
  label: string;
  points: number;
  detail: string;
}

export interface RiskScore {
  score: number;
  level: RiskLevel;
  factors: RiskFactor[];
}

/** Deterministic 0-100 score: the document as it is, and what the protected copy keeps. */
export interface RiskSummary {
  before: RiskScore;
  after: RiskScore;
}

export type PolicyAction = "ALLOW" | "MASK" | "REDACT" | "GENERALIZE" | "BLOCK";

export interface PolicySummary {
  profile: { id: string; name: string; builtin: boolean };
  actions: Record<PolicyAction, number>;
  regions: number;
  blocked: number;
  overridden: number;
  ready: boolean;
}

export interface Profile {
  id: string;
  name: string;
  description: string;
  builtin: boolean;
  base_id: string | null;
  default: boolean;
  min_confidence: number;
  mask_style: MaskStyle;
  actions: Record<string, { action: PolicyAction; source: string; style: MaskStyle }>;
}

export interface EntityTypeInfo {
  id: string;
  label: string;
  category: CategoryGroup;
  company_rule: boolean;
  generalizable: boolean;
}

export interface ProfileList {
  profiles: Profile[];
  default_id: string;
  entity_types?: EntityTypeInfo[];
}

export interface ProfileChanges {
  name?: string;
  actions?: Record<string, PolicyAction | null>;
  styles?: Record<string, MaskStyle | null>;
}

export type RuleKind = "exact" | "case_insensitive" | "normalized" | "regex";

/** A company rule. Its text is the user's own, shown only on the rules screen. */
export interface Rule {
  id: string;
  kind: RuleKind;
  pattern: string;
  aliases: string[];
  category_id: string;
  action: PolicyAction | null;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface RuleCategory {
  id: string;
  label: string;
  group: CategoryGroup;
  severity: number;
  builtin: boolean;
}

export interface RuleList {
  rules: Rule[];
  categories: RuleCategory[];
  kinds: RuleKind[];
  actions: PolicyAction[];
}

export interface NewRule {
  kind: RuleKind;
  pattern: string;
  category_id: string;
  action: PolicyAction | null;
}

/** "Teach Airlock" from a finding. */
export type TeachKind = "not_sensitive" | "company_rule";

/** Result of `scan.set_profile`, `scan.override`, `scan.refresh` and `scan.teach`. */
export interface PolicyUpdate {
  scan_id: string;
  findings: Finding[];
  summary: ScanSummary;
  policy: PolicySummary;
  risk: RiskSummary;
}

export interface Override {
  finding_id?: string;
  value_group?: number;
  action: PolicyAction | null;
  mask_style?: MaskStyle;
}

export interface CategorySummary {
  category: CategoryGroup;
  count: number;
  distinct: number;
  max_severity: SeverityLabel;
  /** Effective actions, e.g. { MASK: 3, BLOCK: 1 }. */
  actions: Partial<Record<PolicyAction, number>>;
}

export interface ScanSummary {
  total: number;
  listed: number;
  distinct_values: number;
  hidden: number;
  max_severity: SeverityLabel | null;
  by_severity: Record<SeverityLabel, number>;
  by_category: CategorySummary[];
  by_entity: { entity_type: string; label: string; category: CategoryGroup; count: number }[];
  detectors: { ner: "used" | "unavailable" | "disabled" | "partial"; company_rules: number; rule_timeouts: number };
  allowed: number;
}

/** Result of `scan.start`: extraction summary plus detections. */
export interface ScanResult {
  scan_id: string;
  extraction: ExtractSummary;
  findings: Finding[];
  summary: ScanSummary;
  policy: PolicySummary;
  detection_ms: number;
  risk: RiskSummary;
}

export type VerifyStatus = "passed" | "review" | "failed";

/** Something found in a protected copy: a protected value left behind, or a new finding. */
export interface RemainingItem {
  reason: "protected" | "new";
  entity_type: string;
  entity_label: string;
  preview: string;
  location: { kind: string; label: string };
  hidden: boolean;
}

/** Result of `verify.run`: the copy read back, searched and scanned again. */
export interface VerifyResult {
  artifact_id: string;
  status: VerifyStatus;
  passed: boolean;
  checked: { protected_values: number; segments: number; ocr_used: boolean };
  remaining_count: number;
  new_count: number;
  remaining: RemainingItem[];
  unreadable: { label: string; count: number }[];
  kept_count: number;
  replacement_count: number;
  duration_ms: number;
}

export interface ExportResult {
  saved: boolean;
  file_name?: string;
  size_bytes?: number;
}

/** Licence state, checked offline by the host. Nothing is limited by it. */
export interface LicenseStatus {
  state: "unlicensed" | "licensed" | "invalid";
  license: {
    license_id: string;
    plan: string;
    customer: string;
    email: string | null;
    seats: number;
    issued_at: string;
    updates_until: string | null;
    /** Activated for (bound to) this computer. */
    bound: boolean;
  } | null;
  problem: EngineError | null;
  /** One-way hash of this computer's ID, for machine-bound licences. */
  machine_code: string;
  activation_available: boolean;
}

/** Result of `sanitize.run`: a protected copy waiting for verification. */
export interface SanitizeResult {
  artifact_id: string;
  file_name: string;
  format: string;
  size_bytes: number;
  replaced: { MASK: number; REDACT: number; GENERALIZE: number };
  removed: { label: string; count: number }[];
  vault: { entries: number; stored: boolean; protection: string | null };
  verified: boolean;
  duration_ms: number;
}

/** How text is protected before it is sent to an AI tool (Phase 12). */
export type PrivacyMode = "reversible" | "synthetic" | "redact" | "block";

/** The second local scan of protected text before it can be sent. */
export interface OutboundCheck {
  /** "safe": nothing sensitive left; "review": something new was found; "blocked": an original value is still in it. */
  status: "safe" | "review" | "blocked";
  remaining_count: number;
  new_count: number;
  remaining: RemainingItem[];
  kept_count: number;
}

export interface TextFinding {
  entity_type: string;
  entity_label: string;
  category: string;
  preview: string;
  action: PolicyAction;
}

/** Result of `text.protect`. */
export interface ProtectTextResult {
  /** The protected text; null when "Block sensitive content" withheld it. */
  text: string | null;
  withheld: boolean;
  mode: PrivacyMode;
  conversation_id: string | null;
  /** Spans replaced. */
  changed: number;
  /** Passwords, keys and tokens removed (never restorable). */
  blocked: number;
  /** Distinct placeholders the AI will see. */
  placeholders?: number;
  actions: Partial<Record<PolicyAction, number>>;
  findings: TextFinding[];
  profile: { id: string; name: string };
  ner: string;
  check: OutboundCheck | null;
}

/** A conversation's mapping, described without any value. */
export interface ConversationStatus {
  conversation_id: string;
  started: number | null;
  updated: number | null;
  placeholders: number;
  types: Record<string, number>;
}

/** Where a response's placeholders come from. */
export type RestoreScope = { conversation_id: string } | { artifact_id: string };

/** Result of `response.analyze`: what a restore would do, without values. */
export interface ResponseAnalysis {
  placeholders: number;
  occurrences: number;
  types: Record<string, number>;
  unknown: string[];
  unknown_count: number;
}

export interface ReviewItem {
  placeholder: string;
  original: string;
  entity_type: string;
  entity_label: string;
  count: number;
}

export interface ResponseReview extends ResponseAnalysis {
  items: ReviewItem[];
}

export interface ResponseRestore extends ResponseAnalysis {
  text: string;
  restored: number;
}
