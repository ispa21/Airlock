import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { getCurrentWebview } from "@tauri-apps/api/webview";
import { open } from "@tauri-apps/plugin-dialog";

import type { DropHandlers, Platform } from "./platform";
import {
  toEngineError,
  type EngineInfo,
  type InspectResult,
  type NewRule,
  type Override,
  type PolicyUpdate,
  type Profile,
  type ProfileChanges,
  type ProfileList,
  type Progress,
  type Rule,
  type RuleList,
  type SanitizeResult,
  type ScanResult,
  type TeachKind,
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

async function withProgress<T>(
  tag: string,
  onProgress: (progress: Progress) => void,
  run: () => Promise<T>,
): Promise<T> {
  const unlisten = await listen<ProgressNotification>("engine://notification", (event) => {
    const params = event.payload.params;
    if (event.payload.method === "$/progress" && params?.tag === tag) {
      onProgress({ stage: params.stage ?? "", done: params.done ?? 0, total: params.total ?? 0 });
    }
  });
  try {
    return await run();
  } finally {
    unlisten();
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

  scan(path: string, profileId: string, tag: string, onProgress: (progress: Progress) => void) {
    return withProgress(tag, onProgress, () => call<ScanResult>("scan.start", { path, profile_id: profileId }, tag));
  },

  sanitize(scanId: string, tag: string, onProgress: (progress: Progress) => void) {
    return withProgress(tag, onProgress, () => call<SanitizeResult>("sanitize.run", { scan_id: scanId }, tag));
  },

  async discardCopy(artifactId: string) {
    await call<{ ok: boolean }>("sanitize.discard", { artifact_id: artifactId });
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

  refresh(scanId: string) {
    return call<PolicyUpdate>("scan.refresh", { scan_id: scanId });
  },

  teach(scanId: string, findingId: string, kind: TeachKind) {
    return call<PolicyUpdate>("scan.teach", { scan_id: scanId, finding_id: findingId, kind });
  },

  async allowListCount() {
    return (await call<{ count: number }>("allowlist.status")).count;
  },

  async clearAllowList() {
    await call<{ ok: boolean }>("allowlist.clear");
  },

  listRules() {
    return call<RuleList>("rules.list");
  },

  async createRule(rule: NewRule) {
    return (await call<{ rule: Rule }>("rules.create", { ...rule })).rule;
  },

  async updateRule(id: string, changes: Partial<NewRule> & { enabled?: boolean }) {
    return (await call<{ rule: Rule }>("rules.update", { id, ...changes })).rule;
  },

  async deleteRule(id: string) {
    await call<{ ok: boolean }>("rules.delete", { id });
  },

  async createProfile(name: string, baseId: string) {
    return (await call<{ profile: Profile }>("profiles.create", { name, base_id: baseId })).profile;
  },

  async updateProfile(id: string, changes: ProfileChanges) {
    return (await call<{ profile: Profile }>("profiles.update", { id, ...changes })).profile;
  },

  async deleteProfile(id: string) {
    await call<{ ok: boolean }>("profiles.delete", { id });
  },

  async setDefaultProfile(id: string) {
    await call<{ ok: boolean }>("profiles.set_default", { id });
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
