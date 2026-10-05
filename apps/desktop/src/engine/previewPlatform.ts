/**
 * Browser preview used only by `npm run dev` outside Tauri, for UI work.
 * It never touches real files and is excluded from production builds.
 */
import type { DropHandlers, Platform } from "./platform";
import type { EngineError, FormatFamily, InspectResult } from "./types";

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
      support: "planned",
      scannable: false,
    };
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
