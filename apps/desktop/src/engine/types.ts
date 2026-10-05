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
