/**
 * Browser preview used only by `npm run dev` outside Tauri, for UI work.
 * It never touches real files and is excluded from production builds.
 */
import type { DropHandlers, Platform } from "./platform";
import type { EngineError, ExtractSummary, FormatFamily, InspectResult, Progress } from "./types";

const FAMILIES: Record<string, [string, string, FormatFamily]> = {
  pdf: ["pdf", "PDF document", "document"],
  docx: ["docx", "Word document", "document"],
  xlsx: ["xlsx", "Excel workbook", "spreadsheet"],
  pptx: ["pptx", "PowerPoint presentation", "presentation"],
  csv: ["csv", "CSV spreadsheet", "spreadsheet"],
  txt: ["txt", "Text file", "text"],
  png: ["png", "PNG image", "image"],
  jpg: ["jpeg", "JPEG image", "image"],
};

const cancelled = new Set<string>();

const PREVIEW_SUMMARY: ExtractSummary = {
  format: "pdf",
  format_label: "PDF document",
  segment_count: 64,
  char_count: 23_140,
  word_count: 3_904,
  parts: [
    { kind: "body", segments: 12, chars: 21_000, words: 3_610 },
    { kind: "comment", segments: 3, chars: 240, words: 41 },
    { kind: "metadata", segments: 4, chars: 80, words: 9 },
    { kind: "link", segments: 2, chars: 90, words: 2 },
    { kind: "ocr", segments: 2, chars: 1_700, words: 242 },
  ],
  counts: { pages: 12, images_ocr: 2, embedded: 1 },
  ocr_used: true,
  unextracted: [{ kind: "revisions", label: "Earlier versions of this PDF kept inside the file", count: 1 }],
  unextracted_total: 1,
  duration_ms: 1_840,
};

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

export const previewPlatform: Platform = {
  kind: "preview",

  async engineInfo() {
    await delay(400);
    return {
      engine_version: "preview",
      protocol_version: "1.0",
      network_isolation: true,
      methods: ["document.inspect", "system.health"],
    };
  },

  async inspect(path: string): Promise<InspectResult> {
    await delay(250);
    const name = path.split(/[\\/]/).pop() ?? path;
    const ext = name.includes(".") ? (name.split(".").pop() ?? "").toLowerCase() : "";
    const known = FAMILIES[ext];
    if (!known) {
      const error: EngineError = {
        kind: "unsupported_format",
        message: `Airlock does not support .${ext || "?"} files yet.`,
        next_step: "Convert the file to PDF, DOCX, XLSX, PPTX, CSV or TXT and try again.",
        original_affected: false,
      };
      throw error;
    }
    return {
      file_name: name,
      extension: ext,
      size_bytes: 248_312,
      format: known[0],
      format_label: known[1],
      family: known[2],
      support: "available",
      scannable: true,
    };
  },

  async extract(_path: string, tag: string, onProgress: (progress: Progress) => void): Promise<ExtractSummary> {
    cancelled.delete(tag);
    for (let page = 0; page <= 12; page += 1) {
      if (cancelled.has(tag)) {
        const error: EngineError = { kind: "cancelled", message: "The operation was cancelled.", original_affected: false };
        throw error;
      }
      onProgress({ stage: "pages", done: page, total: 12 });
      await delay(120);
    }
    return PREVIEW_SUMMARY;
  },

  async cancel(tag: string) {
    cancelled.add(tag);
  },

  async pickFile() {
    return "C:\\Users\\preview\\Documents\\Q3 Board Report.pdf";
  },

  async onFileDrop({ onHover, onDrop }: DropHandlers) {
    const over = (e: DragEvent) => {
      e.preventDefault();
      onHover(true);
    };
    const leave = (e: DragEvent) => {
      if (e.relatedTarget === null) onHover(false);
    };
    const drop = (e: DragEvent) => {
      e.preventDefault();
      onHover(false);
      const names = Array.from(e.dataTransfer?.files ?? []).map((f) => `C:\\preview\\${f.name}`);
      if (names.length) onDrop(names);
    };
    window.addEventListener("dragover", over);
    window.addEventListener("dragleave", leave);
    window.addEventListener("drop", drop);
    return () => {
      window.removeEventListener("dragover", over);
      window.removeEventListener("dragleave", leave);
      window.removeEventListener("drop", drop);
    };
  },
};
