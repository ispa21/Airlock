import { invoke } from "@tauri-apps/api/core";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";

import type { DropHandlers, Platform } from "./platform";
import { toEngineError, type EngineInfo, type InspectResult } from "./types";

async function call<T>(method: string, params: Record<string, unknown> = {}): Promise<T> {
  try {
    return await invoke<T>("engine_call", { method, params });
  } catch (error) {
    throw toEngineError(error);
  }
}

export const SUPPORTED_EXTENSIONS = [
  "pdf", "docx", "xlsx", "pptx", "csv", "tsv", "txt", "md", "log",
  "png", "jpg", "jpeg", "webp", "tif", "tiff",
  "json", "yaml", "yml", "xml", "toml", "ini", "cfg", "conf", "env",
  "py", "js", "ts", "jsx", "tsx", "java", "c", "h", "cpp", "hpp", "cs", "go",
  "rs", "php", "rb", "swift", "kt", "sql", "sh", "ps1",
];

export const tauriPlatform: Platform = {
  kind: "desktop",

  async engineInfo(): Promise<EngineInfo> {
    try {
      return await invoke<EngineInfo>("engine_status");
    } catch (error) {
      throw toEngineError(error);
    }
  },

  inspect(path: string): Promise<InspectResult> {
    return call<InspectResult>("document.inspect", { path });
  },

  async pickFile(): Promise<string | null> {
    const selected = await open({
      multiple: false,
      directory: false,
      title: "Choose a file to protect",
      filters: [{ name: "Supported files", extensions: SUPPORTED_EXTENSIONS }],
    });
    return typeof selected === "string" ? selected : null;
  },

  async onFileDrop({ onHover, onDrop }: DropHandlers): Promise<() => void> {
    return getCurrentWebview().onDragDropEvent((event) => {
      const payload = event.payload;
      if (payload.type === "enter" || payload.type === "over") onHover(true);
      else if (payload.type === "leave") onHover(false);
      else if (payload.type === "drop") {
        onHover(false);
        onDrop(payload.paths);
      }
    });
  },
};
