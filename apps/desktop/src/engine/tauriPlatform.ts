import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";

import type { DropHandlers, Platform } from "./platform";
import {
  toEngineError,
  type EngineInfo,
  type InspectResult,
  type Override,
  type PolicyUpdate,
  type ProfileList,
  type Progress,
  type ScanResult,
} from "./types";

async function call<T>(method: string, params: Record<string, unknown> = {}, tag?: string): Promise<T> {
  try {
    return await invoke<T>("engine_call", { method, params, tag: tag ?? null });
  } catch (error) {
    throw toEngineError(error);
  }
}

interface ProgressNotification {
  method?: string;
  params?: { tag?: string; stage?: string; done?: number; total?: number };
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

  async scan(path: string, profileId: string, tag: string, onProgress: (progress: Progress) => void) {
    const unlisten = await listen<ProgressNotification>("engine://notification", (event) => {
      const params = event.payload.params;
      if (event.payload.method === "$/progress" && params?.tag === tag) {
        onProgress({ stage: params.stage ?? "", done: params.done ?? 0, total: params.total ?? 0 });
      }
    });
    try {
      return await call<ScanResult>("scan.start", { path, profile_id: profileId }, tag);
    } finally {
      unlisten();
    }
  },

  listProfiles() {
    return call<ProfileList>("profiles.list");
  },

  setProfile(scanId: string, profileId: string) {
    return call<PolicyUpdate>("scan.set_profile", { scan_id: scanId, profile_id: profileId });
  },

  override(scanId: string, overrides: Override[], acknowledgeRisk = false) {
    return call<PolicyUpdate>("scan.override", {
      scan_id: scanId,
      overrides,
      acknowledge_risk: acknowledgeRisk,
    });
  },

  async discard(scanId: string) {
    await call<{ ok: boolean }>("scan.discard", { scan_id: scanId });
  },

  async cancel(tag: string) {
    try {
      await invoke<boolean>("engine_cancel", { tag });
    } catch (error) {
      throw toEngineError(error);
    }
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
