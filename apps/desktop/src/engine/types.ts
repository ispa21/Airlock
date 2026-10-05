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
  mask_style: string;
  actions: Record<string, { action: PolicyAction; source: string }>;
}

export interface ProfileList {
  profiles: Profile[];
  default_id: string;
}

/** Result of `scan.set_profile` and `scan.override`. */
export interface PolicyUpdate {
  scan_id: string;
  findings: Finding[];
  summary: ScanSummary;
  policy: PolicySummary;
}

export interface Override {
  finding_id?: string;
  value_group?: number;
  action: PolicyAction | null;
}

export interface ScanSummary {
  total: number;
  listed: number;
  distinct_values: number;
  hidden: number;
  max_severity: SeverityLabel | null;
  by_severity: Record<SeverityLabel, number>;
  by_category: { category: CategoryGroup; count: number }[];
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
  risk: null;
}
