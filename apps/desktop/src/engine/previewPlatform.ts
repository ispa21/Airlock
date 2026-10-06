/**
 * Browser preview used only by `npm run dev` outside Tauri, for UI work.
 * It never touches real files and is excluded from production builds.
 */
import type { DropHandlers, Platform } from "./platform";
import type {
  EngineError,
  ExtractSummary,
  Finding,
  FormatFamily,
  InspectResult,
  MaskStyle,
  NewRule,
  Override,
  PolicyAction,
  PolicySummary,
  PolicyUpdate,
  Profile,
  Progress,
  RiskSummary,
  Rule,
  SanitizeResult,
  ScanResult,
} from "./types";

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

type RawFinding = Omit<
  Finding,
  | "action"
  | "effective_action"
  | "reason"
  | "overridden"
  | "covered_by"
  | "generalizable"
  | "high_risk"
  | "mask_style"
  | "partial_available"
  | "explanation"
>;

const EXPLANATIONS: Record<string, string> = {
  API_KEY: "Matches the format of a GitHub access token.",
  AADHAAR: "A 12-digit number that passes the Aadhaar checksum (Verhoeff).",
  INTERNAL_PROJECT: "Matches one of your company rules, ignoring case, accents and separators.",
  EMAIL: "Has the form of an e-mail address (name@domain).",
  PERSON: "The on-device language model recognised this as a person name.",
};

const PROFILE_ACTIONS: Record<string, Record<string, PolicyAction>> = {
  "company-default": { API_KEY: "BLOCK", AADHAAR: "MASK", INTERNAL_PROJECT: "MASK", EMAIL: "MASK", PERSON: "MASK" },
  strict: { API_KEY: "BLOCK", AADHAAR: "REDACT", INTERNAL_PROJECT: "REDACT", EMAIL: "MASK", PERSON: "MASK" },
  "secrets-and-ids": { API_KEY: "BLOCK", AADHAAR: "MASK", INTERNAL_PROJECT: "MASK", EMAIL: "ALLOW", PERSON: "ALLOW" },
};
const PROFILE_NAMES: Record<string, string> = {
  "company-default": "Company Default",
  strict: "Strict",
  "secrets-and-ids": "Secrets & IDs only",
};
let previewProfile = "company-default";
const previewOverrides = new Map<number, { action: PolicyAction; style?: MaskStyle | undefined }>();
const previewAllowed = new Set<number>();
let previewRules: Rule[] = [];

/** Points per kind of data, as the engine's scorer would give for one value each. */
const PREVIEW_POINTS: Record<string, [string, string, number]> = {
  API_KEY: ["credentials", "Passwords, keys and tokens", 40],
  AADHAAR: ["government_ids", "Government ids (PAN, Aadhaar, GSTIN)", 25],
  INTERNAL_PROJECT: ["company_terms", "Company-confidential terms (your rules)", 15],
  EMAIL: ["personal", "Personal contact details", 8],
  PERSON: ["names", "Names, places and amounts (language model)", 3],
};

function score(findings: Finding[]) {
  const factors = findings
    .filter((f) => PREVIEW_POINTS[f.entity_type])
    .map((f) => {
      const [id, label, points] = PREVIEW_POINTS[f.entity_type]!;
      return { id, label, points, detail: "1 distinct value found 1 time" };
    });
  const total = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
  const level = total >= 75 ? "critical" : total >= 50 ? "high" : total >= 25 ? "medium" : total ? "low" : "none";
  return { score: total, level, factors } as RiskSummary["before"];
}

function decide(raw: RawFinding[]): { findings: Finding[]; policy: PolicySummary; risk: RiskSummary } {
  const findings = raw
    .filter((f) => !previewAllowed.has(f.value_group))
    .map((f): Finding => {
      const override = previewOverrides.get(f.value_group);
      const action = override?.action ?? PROFILE_ACTIONS[previewProfile]?.[f.entity_type] ?? "MASK";
      return {
        ...f,
        action,
        effective_action: action,
        reason: override ? "Changed by you." : `${PROFILE_NAMES[previewProfile]} preview decision.`,
        overridden: override !== undefined,
        covered_by: null,
        generalizable: f.entity_type === "EMAIL",
        high_risk: f.severity === "critical",
        mask_style: override?.style ?? "typed_placeholder",
        partial_available: f.category !== "CREDENTIALS",
        explanation: EXPLANATIONS[f.entity_type] ?? "Matches a known format.",
      };
    });
  const actions: Record<PolicyAction, number> = { ALLOW: 0, MASK: 0, REDACT: 0, GENERALIZE: 0, BLOCK: 0 };
  for (const f of findings) actions[f.effective_action] += 1;
  return {
    findings,
    policy: {
      profile: { id: previewProfile, name: PROFILE_NAMES[previewProfile] ?? previewProfile, builtin: true },
      actions,
      regions: findings.length - actions.ALLOW,
      blocked: actions.BLOCK,
      overridden: previewOverrides.size,
      ready: actions.BLOCK === 0,
    },
    risk: {
      before: score(findings),
      after: score(findings.filter((f) => f.effective_action === "ALLOW" || f.effective_action === "BLOCK")),
    },
  };
}

function update(scanId: string): PolicyUpdate {
  return { scan_id: scanId, summary: PREVIEW_RAW.summary, ...decide(PREVIEW_RAW.findings) };
}

function previewProfiles(): Profile[] {
  return Object.entries(PROFILE_NAMES).map(([id, name]) => ({
    id,
    name,
    description: "",
    builtin: true,
    base_id: null,
    default: id === "company-default",
    min_confidence: 0.6,
    mask_style: "typed_placeholder",
    actions: Object.fromEntries(
      Object.entries(PROFILE_ACTIONS[id] ?? {}).map(([type, action]) => [
        type,
        { action, source: "entity", style: "typed_placeholder" as MaskStyle },
      ]),
    ),
  }));
}

function readOnly(): EngineError {
  return {
    kind: "invalid_profile",
    message: "The browser preview can't save profiles.",
    next_step: "Run the desktop app to change profiles.",
    original_affected: false,
  };
}

const PREVIEW_RAW: { findings: RawFinding[] } & Omit<ScanResult, "findings" | "policy" | "risk"> = {
  scan_id: "scan_preview",
  extraction: PREVIEW_SUMMARY,
  detection_ms: 420,
  findings: [
    {
      id: "f1", entity_type: "API_KEY", entity_label: "API key or token", category: "CREDENTIALS",
      severity: "critical", confidence: 0.97, detector: "secret.github_token", corroborated_by: [], rule_id: null,
      preview: "ghp_••••••••", location: { kind: "comment", label: "Comments · paragraph 2" }, hidden: true,
      value_group: 1,
    },
    {
      id: "f2", entity_type: "AADHAAR", entity_label: "Aadhaar number", category: "GOVERNMENT",
      severity: "critical", confidence: 0.99, detector: "regex.aadhaar", corroborated_by: [], rule_id: null,
      preview: "•••• 4821", location: { kind: "body", label: "Page 3" }, hidden: false, value_group: 2,
    },
    {
      id: "f3", entity_type: "INTERNAL_PROJECT", entity_label: "Internal project", category: "INTELLECTUAL_PROPERTY",
      severity: "high", confidence: 1, detector: "custom.normalized", corroborated_by: [], rule_id: "rule_preview",
      preview: "Pr•••••••••••ix", location: { kind: "body", label: "Page 1" }, hidden: false, value_group: 3,
    },
    {
      id: "f4", entity_type: "EMAIL", entity_label: "E-mail address", category: "PERSONAL",
      severity: "medium", confidence: 0.98, detector: "regex.email", corroborated_by: [], rule_id: null,
      preview: "r••••@example.invalid", location: { kind: "metadata", label: "Document properties" }, hidden: true,
      value_group: 4,
    },
    {
      id: "f5", entity_type: "PERSON", entity_label: "Person name", category: "PERSONAL",
      severity: "medium", confidence: 0.75, detector: "ner.spacy", corroborated_by: [], rule_id: null,
      preview: "Ra••••••ma", location: { kind: "body", label: "Page 1" }, hidden: false, value_group: 5,
    },
  ],
  summary: {
    total: 5, listed: 5, distinct_values: 5, hidden: 2, max_severity: "critical",
    by_severity: { critical: 2, high: 1, medium: 2, low: 0 },
    by_category: [
      { category: "PERSONAL", count: 2, distinct: 2, max_severity: "medium", actions: { MASK: 2 } },
      { category: "CREDENTIALS", count: 1, distinct: 1, max_severity: "critical", actions: { BLOCK: 1 } },
      { category: "GOVERNMENT", count: 1, distinct: 1, max_severity: "critical", actions: { MASK: 1 } },
      { category: "INTELLECTUAL_PROPERTY", count: 1, distinct: 1, max_severity: "high", actions: { MASK: 1 } },
    ],
    by_entity: [
      { entity_type: "API_KEY", label: "API key or token", category: "CREDENTIALS", count: 1 },
      { entity_type: "AADHAAR", label: "Aadhaar number", category: "GOVERNMENT", count: 1 },
      { entity_type: "INTERNAL_PROJECT", label: "Internal project", category: "INTELLECTUAL_PROPERTY", count: 1 },
      { entity_type: "EMAIL", label: "E-mail address", category: "PERSONAL", count: 1 },
      { entity_type: "PERSON", label: "Person name", category: "PERSONAL", count: 1 },
    ],
    detectors: { ner: "used", company_rules: 1, rule_timeouts: 0 },
    allowed: 0,
  },
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

  async scan(_path: string, profileId: string, tag: string, onProgress: (progress: Progress) => void): Promise<ScanResult> {
    previewProfile = profileId;
    previewOverrides.clear();
    previewAllowed.clear();
    cancelled.delete(tag);
    for (let page = 0; page <= 12; page += 1) {
      if (cancelled.has(tag)) {
        const error: EngineError = { kind: "cancelled", message: "The operation was cancelled.", original_affected: false };
        throw error;
      }
      onProgress({ stage: "pages", done: page, total: 12 });
      await delay(120);
    }
    onProgress({ stage: "detect", done: 1, total: 2 });
    await delay(300);
    return { ...PREVIEW_RAW, ...decide(PREVIEW_RAW.findings) };
  },

  async listProfiles() {
    return {
      default_id: "company-default",
      profiles: previewProfiles(),
      entity_types: PREVIEW_RAW.findings.map((f) => ({
        id: f.entity_type,
        label: f.entity_label,
        category: f.category,
        company_rule: f.detector.startsWith("custom."),
        generalizable: f.entity_type === "EMAIL",
      })),
    };
  },

  async setProfile(scanId: string, profileId: string) {
    previewProfile = profileId;
    await delay(150);
    return update(scanId);
  },

  async override(scanId: string, overrides: Override[]) {
    for (const o of overrides) {
      if (o.value_group === undefined) continue;
      if (o.action === null) previewOverrides.delete(o.value_group);
      else previewOverrides.set(o.value_group, { action: o.action, style: o.mask_style });
    }
    await delay(150);
    return update(scanId);
  },

  async refresh(scanId: string) {
    await delay(300);
    return update(scanId);
  },

  async teach(scanId: string, findingId: string, kind) {
    const finding = PREVIEW_RAW.findings.find((f) => f.id === findingId);
    if (finding && kind === "not_sensitive") previewAllowed.add(finding.value_group);
    await delay(300);
    return update(scanId);
  },

  async allowListCount() {
    return previewAllowed.size;
  },

  async clearAllowList() {
    previewAllowed.clear();
  },

  async listRules() {
    return {
      rules: previewRules,
      categories: [
        { id: "CONFIDENTIAL_TERM", label: "Confidential term", group: "INTELLECTUAL_PROPERTY", severity: 3, builtin: true },
        { id: "INTERNAL_PROJECT", label: "Internal project", group: "INTELLECTUAL_PROPERTY", severity: 3, builtin: true },
      ],
      kinds: ["normalized", "case_insensitive", "exact", "regex"],
      actions: ["ALLOW", "MASK", "REDACT", "GENERALIZE", "BLOCK"],
    };
  },

  async createRule(rule: NewRule) {
    const now = new Date().toISOString();
    const created: Rule = {
      ...rule,
      id: `rule_${previewRules.length + 1}`,
      aliases: [],
      enabled: true,
      created_at: now,
      updated_at: now,
    };
    previewRules = [...previewRules, created];
    return created;
  },

  async updateRule(id: string, changes) {
    previewRules = previewRules.map((r) => (r.id === id ? { ...r, ...changes } : r));
    return previewRules.find((r) => r.id === id)!;
  },

  async deleteRule(id: string) {
    previewRules = previewRules.filter((r) => r.id !== id);
  },

  async createProfile() {
    throw readOnly();
  },

  async updateProfile() {
    throw readOnly();
  },

  async deleteProfile() {
    throw readOnly();
  },

  async setDefaultProfile() {
    throw readOnly();
  },

  async discard() {},

  async sanitize(scanId: string): Promise<SanitizeResult> {
    await delay(700);
    const { findings, policy } = decide(PREVIEW_RAW.findings);
    return {
      artifact_id: `art_${scanId}`,
      file_name: "Q3 Board Report (Airlock protected).pdf",
      format: "pdf",
      size_bytes: 61_440,
      replaced: { MASK: policy.actions.MASK, REDACT: policy.actions.REDACT, GENERALIZE: policy.actions.GENERALIZE },
      removed: [{ label: "Comments, form values, attachments, bookmarks and properties", count: 1 }],
      vault: { entries: findings.filter((f) => f.effective_action === "MASK").length, stored: true, protection: "dpapi" },
      verified: false,
      duration_ms: 700,
    };
  },

  async licenseStatus() {
    return {
      state: "unlicensed" as const,
      license: null,
      problem: null,
      machine_code: "PREV-IEWM-ACHI-NECO-DE00",
      activation_available: false,
    };
  },

  async importLicenseFile() {
    throw readOnly();
  },

  async importLicenseText() {
    throw readOnly();
  },

  async activateLicense() {
    throw readOnly();
  },

  async removeLicense() {
    return previewPlatform.licenseStatus();
  },

  async verify(artifactId: string) {
    await delay(600);
    return {
      artifact_id: artifactId,
      status: "passed" as const,
      passed: true,
      checked: { protected_values: 4, segments: 64, ocr_used: true },
      remaining_count: 0,
      new_count: 0,
      remaining: [],
      unreadable: [],
      kept_count: 0,
      replacement_count: 4,
      duration_ms: 600,
    };
  },

  async saveCopy() {
    const error: EngineError = {
      kind: "export_destination_invalid",
      message: "The browser preview can't save files.",
      next_step: "Run the desktop app to save protected copies.",
      original_affected: false,
    };
    throw error;
  },

  async copyText() {
    return "Q3 board report for [INTERNAL_PROJECT_1]. Contact [PERSON_1] at [EMAIL_1].\n";
  },

  async writeClipboard(text: string) {
    await navigator.clipboard.writeText(text);
  },

  async discardCopy() {},

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
