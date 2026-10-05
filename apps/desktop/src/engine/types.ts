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
