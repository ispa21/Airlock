import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { DropHandlers, Platform } from "./engine/platform";
import { PlatformProvider } from "./engine/PlatformContext";
import type {
  EngineError,
  ExtractSummary,
  InspectResult,
  LicenseStatus,
  PolicyUpdate,
  Profile,
  Progress,
  RiskSummary,
  RuleList,
  ScanResult,
  VerifyResult,
} from "./engine/types";

const INFO = {
  engine_version: "0.1.0",
  protocol_version: "1.0",
  network_isolation: true,
  methods: ["document.inspect"],
};

const DOCX: InspectResult = {
  file_name: "Contract.docx",
  extension: "docx",
  size_bytes: 24_576,
  format: "docx",
  format_label: "Word document",
  family: "document",
  support: "available",
  scannable: true,
};

const SUMMARY: ExtractSummary = {
  format: "docx",
  format_label: "Word document",
  segment_count: 40,
  char_count: 9_000,
  word_count: 1_520,
  parts: [
    { kind: "body", segments: 30, chars: 8_500, words: 1_480 },
    { kind: "comment", segments: 3, chars: 200, words: 30 },
    { kind: "tracked_change", segments: 1, chars: 40, words: 6 },
    { kind: "metadata", segments: 6, chars: 60, words: 4 },
  ],
  counts: { paragraphs: 30, images_ocr: 1, embedded: 1 },
  ocr_used: true,
  unextracted: [{ kind: "macro", label: "Macros (VBA project)", count: 1 }],
  unextracted_total: 1,
  duration_ms: 1_234,
};

const RISK: RiskSummary = {
  before: {
    score: 43,
    level: "medium",
    factors: [
      { id: "government_ids", label: "Government ids (PAN, Aadhaar, GSTIN)", points: 25, detail: "1 distinct value found 1 time" },
      { id: "personal", label: "Personal contact details", points: 8, detail: "1 distinct value found 1 time" },
      { id: "hidden", label: "Sensitive data in hidden parts", points: 10, detail: "1 finding in comments" },
    ],
  },
  after: { score: 0, level: "none", factors: [] },
};

const RESULT: ScanResult = {
  scan_id: "scan_test",
  extraction: SUMMARY,
  detection_ms: 310,
  risk: RISK,
  findings: [
    {
      id: "f1", entity_type: "PAN", entity_label: "PAN (income-tax id)", category: "GOVERNMENT",
      severity: "high", confidence: 0.97, detector: "regex.pan", corroborated_by: [], rule_id: null,
      preview: "AB••••••4F", location: { kind: "comment", label: "Comments · paragraph 1" }, hidden: true,
      value_group: 1, action: "MASK", effective_action: "MASK", reason: "Company Default masks government ids.",
      overridden: false, covered_by: null, generalizable: false, high_risk: false, mask_style: "typed_placeholder",
      partial_available: true,
      explanation: "Has the structure of an Indian PAN: 5 letters, 4 digits, 1 letter, with a valid holder-type letter.",
    },
    {
      id: "f2", entity_type: "EMAIL", entity_label: "E-mail address", category: "PERSONAL",
      severity: "medium", confidence: 0.98, detector: "regex.email", corroborated_by: [], rule_id: null,
      preview: "r••••@example.invalid", location: { kind: "body", label: "Body · paragraph 2" }, hidden: false,
      value_group: 2, action: "MASK", effective_action: "MASK", reason: "Company Default masks personal data.",
      overridden: false, covered_by: null, generalizable: true, high_risk: false, mask_style: "typed_placeholder",
      partial_available: true, explanation: "Has the form of an e-mail address (name@domain).",
    },
  ],
  summary: {
    total: 2, listed: 2, distinct_values: 2, hidden: 1, max_severity: "high",
    by_severity: { critical: 0, high: 1, medium: 1, low: 0 },
    by_category: [
      { category: "GOVERNMENT", count: 1, distinct: 1, max_severity: "high", actions: { MASK: 1 } },
      { category: "PERSONAL", count: 1, distinct: 1, max_severity: "medium", actions: { MASK: 1 } },
    ],
    by_entity: [
      { entity_type: "PAN", label: "PAN (income-tax id)", category: "GOVERNMENT", count: 1 },
      { entity_type: "EMAIL", label: "E-mail address", category: "PERSONAL", count: 1 },
    ],
    detectors: { ner: "used", company_rules: 0, rule_timeouts: 0 },
    allowed: 0,
  },
  policy: {
    profile: { id: "company-default", name: "Company Default", builtin: true },
    actions: { ALLOW: 0, MASK: 2, REDACT: 0, GENERALIZE: 0, BLOCK: 0 },
    regions: 2,
    blocked: 0,
    overridden: 0,
    ready: true,
  },
};

const COPY = {
  artifact_id: "art_0123456789abcdef",
  file_name: "Contract (Airlock protected).docx",
  format: "docx",
  size_bytes: 20_480,
  replaced: { MASK: 2, REDACT: 0, GENERALIZE: 0 },
  removed: [{ label: "Macros (VBA project)", count: 1 }],
  vault: { entries: 2, stored: true, protection: "dpapi" },
  verified: false,
  duration_ms: 420,
};

const RULES: RuleList = {
  rules: [],
  categories: [
    { id: "CONFIDENTIAL_TERM", label: "Confidential term", group: "INTELLECTUAL_PROPERTY", severity: 3, builtin: true },
    { id: "CLIENT_NAME", label: "Client name", group: "BUSINESS", severity: 3, builtin: true },
  ],
  kinds: ["exact", "case_insensitive", "normalized", "regex"],
  actions: ["ALLOW", "MASK", "REDACT", "GENERALIZE", "BLOCK"],
};

function profileFixture(id: string, name: string, builtin: boolean): Profile {
  return {
    id,
    name,
    description: "",
    builtin,
    base_id: builtin ? null : "company-default",
    default: id === "company-default",
    min_confidence: 0.6,
    mask_style: "typed_placeholder",
    actions: {
      EMAIL: { action: "MASK", source: "entity", style: "typed_placeholder" },
      API_KEY: { action: "BLOCK", source: "category", style: "typed_placeholder" },
    },
  };
}

const ENTITY_TYPES = [
  { id: "EMAIL", label: "E-mail address", category: "PERSONAL" as const, company_rule: false, generalizable: true },
  { id: "API_KEY", label: "API key or token", category: "CREDENTIALS" as const, company_rule: false, generalizable: false },
];

function updateWith(findings: ScanResult["findings"], extra: Partial<PolicyUpdate> = {}): PolicyUpdate {
  return { scan_id: "scan_test", findings, summary: RESULT.summary, policy: RESULT.policy, risk: RISK, ...extra };
}

async function scanned(platform: Platform) {
  renderApp(platform);
  await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
  await screen.findByText("Verified");
  await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
  await screen.findByRole("heading", { name: "What Airlock found" });
}

const UNLICENSED: LicenseStatus = {
  state: "unlicensed",
  license: null,
  problem: null,
  machine_code: "ABCD-EFGH-IJKL-MNOP-QRST",
  activation_available: true,
};

const LICENSED: LicenseStatus = {
  ...UNLICENSED,
  state: "licensed",
  license: {
    license_id: "lic_X", plan: "lifetime", customer: "Acme Pvt Ltd", email: null, seats: 10,
    issued_at: "2026-10-06T00:00:00Z", updates_until: null, bound: true,
  },
};

const CHECKED: VerifyResult = {
  artifact_id: "art_0123456789abcdef",
  status: "passed",
  passed: true,
  checked: { protected_values: 2, segments: 40, ocr_used: true },
  remaining_count: 0,
  new_count: 0,
  remaining: [],
  unreadable: [],
  kept_count: 0,
  replacement_count: 2,
  duration_ms: 300,
};

function fakePlatform(overrides: Partial<Platform> = {}) {
  let drop: DropHandlers | undefined;
  const platform: Platform = {
    kind: "desktop",
    engineInfo: vi.fn().mockResolvedValue(INFO),
    inspect: vi.fn().mockResolvedValue(DOCX),
    pickFile: vi.fn().mockResolvedValue("C:\\Docs\\Contract.docx"),
    scan: vi.fn(async (_path: string, _profile: string, _tag: string, onProgress: (p: Progress) => void) => {
      onProgress({ stage: "parts", done: 1, total: 4 });
      return RESULT;
    }),
    discard: vi.fn().mockResolvedValue(undefined),
    listProfiles: vi.fn().mockResolvedValue({
      default_id: "company-default",
      profiles: [
        { id: "company-default", name: "Company Default" },
        { id: "strict", name: "Strict" },
      ],
    }),
    setProfile: vi.fn(),
    override: vi.fn(),
    refresh: vi.fn(),
    teach: vi.fn(),
    allowListCount: vi.fn().mockResolvedValue(0),
    clearAllowList: vi.fn().mockResolvedValue(undefined),
    listRules: vi.fn().mockResolvedValue(RULES),
    createRule: vi.fn(),
    updateRule: vi.fn(),
    deleteRule: vi.fn().mockResolvedValue(undefined),
    createProfile: vi.fn(),
    updateProfile: vi.fn(),
    deleteProfile: vi.fn().mockResolvedValue(undefined),
    setDefaultProfile: vi.fn().mockResolvedValue(undefined),
    sanitize: vi.fn().mockResolvedValue(COPY),
    verify: vi.fn().mockResolvedValue(CHECKED),
    saveCopy: vi.fn().mockResolvedValue({ saved: true, file_name: "Contract (Airlock protected).docx" }),
    copyText: vi.fn().mockResolvedValue("Contact [PERSON_1] at [EMAIL_1].\n"),
    writeClipboard: vi.fn().mockResolvedValue(undefined),
    licenseStatus: vi.fn().mockResolvedValue(UNLICENSED),
    importLicenseFile: vi.fn().mockResolvedValue(LICENSED),
    importLicenseText: vi.fn().mockResolvedValue(LICENSED),
    activateLicense: vi.fn().mockResolvedValue(LICENSED),
    removeLicense: vi.fn().mockResolvedValue(UNLICENSED),
    discardCopy: vi.fn().mockResolvedValue(undefined),
    cancel: vi.fn().mockResolvedValue(undefined),
    onFileDrop: vi.fn(async (handlers: DropHandlers) => {
      drop = handlers;
      return () => {};
    }),
    ...overrides,
  };
  return { platform, dropHandlers: () => drop! };
}

function renderApp(platform: Platform) {
  return render(
    <PlatformProvider platform={platform}>
      <App />
    </PlatformProvider>,
  );
}

describe("App", () => {
  it("shows the product promise and the local-processing status", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    expect(screen.getByText("AIRLOCK")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveTextContent(
      "The privacy layer between your data and AI.",
    );
    expect(screen.getByText("Drop files here")).toBeInTheDocument();
    expect(screen.getByText("No document uploads")).toBeInTheDocument();
    expect(screen.getByText("Internet not required")).toBeInTheDocument();
    expect(await screen.findByText("Processing locally")).toBeInTheDocument();
  });

  it("loads a dropped file through the engine and verifies it", async () => {
    const { platform, dropHandlers } = fakePlatform();
    renderApp(platform);
    await waitFor(() => expect(platform.onFileDrop).toHaveBeenCalled());

    act(() => dropHandlers().onHover(true));
    expect(screen.getByText("Release to load file")).toBeInTheDocument();
    act(() => dropHandlers().onDrop(["C:\\Docs\\Contract.docx"]));

    expect(await screen.findByText("Verified")).toBeInTheDocument();
    expect(platform.inspect).toHaveBeenCalledWith("C:\\Docs\\Contract.docx");
    expect(screen.getByText("Contract.docx")).toBeInTheDocument();
    expect(screen.getByText("Word document")).toBeInTheDocument();
    expect(screen.getByText("24 KB")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan Document" })).toBeEnabled();
  });

  it("disables scanning for recognised but unsupported files", async () => {
    const { platform } = fakePlatform({ inspect: vi.fn().mockResolvedValue({ ...DOCX, scannable: false }) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    expect(screen.getByRole("button", { name: "Scan Document" })).toBeDisabled();
    expect(screen.getByTestId("scan-hint")).toBeInTheDocument();
  });

  it("scans locally and shows what was read, including easy-to-miss content", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));

    expect(await screen.findByRole("heading", { name: "What Airlock read" })).toBeInTheDocument();
    expect(platform.scan).toHaveBeenCalledWith(
      "C:\\Docs\\Contract.docx",
      "company-default",
      expect.stringMatching(/^scan-/),
      expect.any(Function),
    );
    expect(screen.getByText("1,520 words · 1 image read with OCR · 1 embedded file")).toBeInTheDocument();
    expect(screen.getByText("Main text")).toBeInTheDocument();
    expect(screen.getByText("1,480 words")).toBeInTheDocument();
    expect(screen.getByText("Deleted text kept by tracked changes")).toBeInTheDocument();
    expect(screen.getByText("Includes 10 items that are easy to miss when you open the file.")).toBeInTheDocument();
    expect(screen.getByText("1 item could not be read")).toBeInTheDocument();
    expect(screen.getByText("Macros (VBA project)")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Scan Again" })).toBeEnabled();
  });

  it("shows findings with masked previews and where they were hidden", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));

    expect(await screen.findByRole("heading", { name: "What Airlock found" })).toBeInTheDocument();
    expect(screen.getByText("2 findings · 2 distinct values")).toBeInTheDocument();
    const findings = screen.getByRole("list", { name: "Findings" });
    expect(findings).toHaveTextContent("PAN (income-tax id)");
    expect(findings).toHaveTextContent("AB••••••4F");
    expect(findings).toHaveTextContent("Comments · paragraph 1");
    expect(findings).toHaveTextContent("Hidden");
    expect(findings).toHaveTextContent("Pattern + validation · 97%");
    expect(screen.getByText(/1 finding is in hidden parts of the file/)).toBeInTheDocument();
  });

  it("asks the engine to forget the previous scan when the file is removed", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    await screen.findByRole("heading", { name: "What Airlock found" });
    await userEvent.click(screen.getByRole("button", { name: "Scan Again" }));
    await waitFor(() => expect(platform.discard).toHaveBeenCalledWith("scan_test"));
  });

  it("reports when nothing sensitive was found and when the language model is missing", async () => {
    const empty: ScanResult = {
      ...RESULT,
      findings: [],
      summary: {
        ...RESULT.summary, total: 0, listed: 0, distinct_values: 0, hidden: 0, max_severity: null,
        by_severity: { critical: 0, high: 0, medium: 0, low: 0 }, by_category: [], by_entity: [],
        detectors: { ner: "unavailable", company_rules: 0, rule_timeouts: 0 },
      },
    };
    const { platform } = fakePlatform({ scan: vi.fn().mockResolvedValue(empty) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    expect(await screen.findByText("No sensitive data was found by the detectors that ran.")).toBeInTheDocument();
    expect(screen.getByText(/language model could not be loaded/)).toBeInTheDocument();
  });

  it("loads profiles from the engine and scans with the chosen one", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await waitFor(() => expect(screen.getByRole("option", { name: "Strict" })).toBeInTheDocument());
    await userEvent.selectOptions(screen.getByLabelText("Privacy Profile"), "strict");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    await screen.findByRole("heading", { name: "What Airlock found" });
    expect(platform.scan).toHaveBeenCalledWith(expect.any(String), "strict", expect.any(String), expect.any(Function));
  });

  it("changes an action for every occurrence of a value and re-applies a profile", async () => {
    const changed: ScanResult["findings"] = RESULT.findings.map((f) =>
      f.id === "f2" ? { ...f, action: "REDACT", effective_action: "REDACT", overridden: true, reason: "Changed by you." } : f,
    );
    const update = updateWith(changed);
    const { platform } = fakePlatform({
      override: vi.fn().mockResolvedValue(update),
      setProfile: vi.fn().mockResolvedValue(update),
    });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    await screen.findByRole("heading", { name: "What Airlock found" });

    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address f2"), "REDACT");
    expect(platform.override).toHaveBeenCalledWith("scan_test", [{ value_group: 2, action: "REDACT" }], false);
    expect(await screen.findByText("Changed by you.")).toBeInTheDocument();
    expect(screen.getByLabelText("Action for E-mail address f2")).toHaveValue("REDACT");

    await userEvent.selectOptions(screen.getByLabelText("Privacy Profile"), "strict");
    expect(platform.setProfile).toHaveBeenCalledWith("scan_test", "strict");
  });

  it("asks before keeping a critical finding and shows blocked items", async () => {
    const token = {
      ...RESULT.findings[0]!, id: "f1", entity_type: "API_KEY", entity_label: "API key or token",
      category: "CREDENTIALS" as const, severity: "critical" as const, action: "BLOCK" as const,
      effective_action: "BLOCK" as const, high_risk: true, value_group: 7,
    };
    const blocked: ScanResult = {
      ...RESULT,
      findings: [token],
      policy: { ...RESULT.policy, blocked: 1, ready: false, actions: { ...RESULT.policy.actions, BLOCK: 1 } },
    };
    const { platform } = fakePlatform({
      scan: vi.fn().mockResolvedValue(blocked),
      override: vi.fn().mockResolvedValue({ ...blocked, scan_id: "scan_test" }),
    });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    expect(await screen.findByText("1 item is blocked")).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Action for API key or token f1"), "ALLOW");
    expect(platform.override).not.toHaveBeenCalled();
    const confirm = screen.getByRole("alertdialog", { name: "Confirm keeping this finding" });
    expect(confirm).toHaveTextContent("Keep this API key or token? It would be shared with the AI as it is.");
    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(platform.override).not.toHaveBeenCalled();

    await userEvent.selectOptions(screen.getByLabelText("Action for API key or token f1"), "ALLOW");
    await userEvent.click(screen.getByRole("button", { name: "Keep anyway" }));
    expect(platform.override).toHaveBeenCalledWith("scan_test", [{ value_group: 7, action: "ALLOW" }], true);
  });

  it("shows policy errors without losing the results", async () => {
    const failure: EngineError = { kind: "scan_not_found", message: "The results of this scan are no longer available." };
    const { platform } = fakePlatform({ override: vi.fn().mockRejectedValue(failure) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    await screen.findByRole("heading", { name: "What Airlock found" });
    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address f2"), "REDACT");
    expect(await screen.findByText("The results of this scan are no longer available.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "What Airlock found" })).toBeInTheDocument();
  });

  it("creates a protected copy and discards it when choices change", async () => {
    const update = updateWith(RESULT.findings);
    const { platform } = fakePlatform({ override: vi.fn().mockResolvedValue(update) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    await screen.findByRole("heading", { name: "What Airlock found" });

    await userEvent.click(screen.getByRole("button", { name: "Create Protected Copy" }));
    expect(platform.sanitize).toHaveBeenCalledWith("scan_test", expect.stringMatching(/^scan-/), expect.any(Function));
    expect(await screen.findByText("Contract (Airlock protected).docx")).toBeInTheDocument();
    expect(screen.getByText("2 replaced by placeholders")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Removed from the copy" })).toHaveTextContent("Macros (VBA project)");
    expect(screen.getByText(/2 placeholders are kept in Airlock's encrypted vault/)).toBeInTheDocument();

    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address f2"), "REDACT");
    await waitFor(() => expect(platform.discardCopy).toHaveBeenCalledWith("art_0123456789abcdef"));
    expect(screen.getByText("Your choices changed, so the previous copy was discarded.")).toBeInTheDocument();
  });

  it("checks every copy, then saves it or copies its text for AI", async () => {
    const { platform } = fakePlatform();
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Create Protected Copy" }));
    expect(platform.verify).toHaveBeenCalledWith("art_0123456789abcdef", expect.stringMatching(/^scan-/), expect.any(Function));
    expect(
      await screen.findByText(/Checked: Airlock read the copy back and none of the 2 protected values are in it/),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Save Protected Copy…" }));
    expect(platform.saveCopy).toHaveBeenCalledWith("art_0123456789abcdef", { asText: false, acknowledgeReview: false });
    expect(await screen.findByText(/Saved as “Contract \(Airlock protected\).docx”/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Copy Text for AI" }));
    expect(platform.copyText).toHaveBeenCalledWith("art_0123456789abcdef", false);
    expect(platform.writeClipboard).toHaveBeenCalledWith("Contact [PERSON_1] at [EMAIL_1].\n");
    expect(await screen.findByText(/Copied the protected text \(33 characters\)/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Save as Text…" }));
    expect(platform.saveCopy).toHaveBeenLastCalledWith("art_0123456789abcdef", { asText: true, acknowledgeReview: false });
  });

  it("asks the user to look at new findings before the copy can be used", async () => {
    const review: VerifyResult = {
      ...CHECKED,
      status: "review",
      passed: false,
      new_count: 1,
      remaining: [
        {
          reason: "new", entity_type: "PERSON", entity_label: "Person name", preview: "Ra••••ma",
          location: { kind: "body", label: "Body · paragraph 4" }, hidden: false,
        },
      ],
    };
    const { platform } = fakePlatform({ verify: vi.fn().mockResolvedValue(review) });
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Create Protected Copy" }));
    expect(await screen.findByText("Airlock found 1 item in the copy that it had not flagged before")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Found in the copy" })).toHaveTextContent("Ra••••ma");
    const save = screen.getByRole("button", { name: "Save Protected Copy…" });
    expect(save).toBeDisabled();
    await userEvent.click(screen.getByRole("checkbox", { name: /I've looked at these items/ }));
    expect(save).toBeEnabled();
    await userEvent.click(save);
    expect(platform.saveCopy).toHaveBeenCalledWith("art_0123456789abcdef", { asText: false, acknowledgeReview: true });
  });

  it("never offers to save a copy that failed its check", async () => {
    const failed: VerifyResult = {
      ...CHECKED,
      status: "failed",
      passed: false,
      remaining_count: 1,
      remaining: [
        {
          reason: "protected", entity_type: "EMAIL", entity_label: "E-mail address", preview: "r••••@example.invalid",
          location: { kind: "file_data", label: "Stored inside the file (word/settings.xml)" }, hidden: true,
        },
      ],
    };
    const { platform } = fakePlatform({ verify: vi.fn().mockResolvedValue(failed) });
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Create Protected Copy" }));
    expect(await screen.findByText("This copy can't leave Airlock")).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Still in the copy" })).toHaveTextContent(
      "Stored inside the file (word/settings.xml)",
    );
    expect(screen.queryByRole("button", { name: "Save Protected Copy…" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Copy Text for AI" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create Again" })).toBeEnabled();
  });

  it("discards the copy when it cannot be checked", async () => {
    const failure: EngineError = {
      kind: "verification_unreadable",
      message: "Airlock could not read the protected copy back to check it, so it can't be saved or copied.",
    };
    const { platform } = fakePlatform({ verify: vi.fn().mockRejectedValue(failure) });
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Create Protected Copy" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(failure.message);
    expect(platform.discardCopy).toHaveBeenCalledWith("art_0123456789abcdef");
    expect(screen.getByRole("button", { name: "Create Protected Copy" })).toBeEnabled();
  });

  it("cannot create a copy while items are blocked", async () => {
    const blocked: ScanResult = { ...RESULT, policy: { ...RESULT.policy, blocked: 1, ready: false } };
    const { platform } = fakePlatform({ scan: vi.fn().mockResolvedValue(blocked) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    expect(await screen.findByRole("button", { name: "Create Protected Copy" })).toBeDisabled();
    expect(screen.getByText("Resolve the blocked items above before creating a copy.")).toBeInTheDocument();
  });

  it("shows progress and can cancel a running scan", async () => {
    let reject: (reason: unknown) => void = () => undefined;
    let report: (p: Progress) => void = () => undefined;
    const { platform } = fakePlatform({
      scan: vi.fn(
        (_path: string, _profile: string, _tag: string, onProgress: (p: Progress) => void) =>
          new Promise<ScanResult>((_resolve, rej) => {
            reject = rej;
            report = onProgress;
          }),
      ),
      cancel: vi.fn(async () => reject({ kind: "cancelled", message: "The operation was cancelled." })),
    });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    expect(await screen.findByText("Starting the secure reader…")).toBeInTheDocument();
    act(() => report({ stage: "pages", done: 2, total: 12 }));
    expect(screen.getByText("Reading page 3 of 12")).toBeInTheDocument();
    expect(screen.getByRole("progressbar")).toHaveAttribute("aria-valuenow", "17");

    await userEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(platform.cancel).toHaveBeenCalledWith(expect.stringMatching(/^scan-/));
    expect(await screen.findByText("Scan cancelled. Your file was not changed.")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("explains a failed scan", async () => {
    const failure: EngineError = {
      kind: "encrypted_document",
      message: "This document is password-protected, so Airlock cannot read its contents.",
      next_step: "Remove the password in the original application, then scan the copy.",
      original_affected: false,
    };
    const { platform } = fakePlatform({ scan: vi.fn().mockRejectedValue(failure) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Scan Document" }));
    expect(await screen.findByRole("alert")).toHaveTextContent(failure.message);
    expect(screen.getByRole("alert")).toHaveTextContent("Your original file was not changed.");
  });

  it("explains rejected files and reassures that the original is untouched", async () => {
    const rejection: EngineError = {
      kind: "format_mismatch",
      message: "This file is named .pdf but its contents look like a Windows program.",
      next_step: "Save the file again from the application that created it.",
      original_affected: false,
    };
    const { platform } = fakePlatform({ inspect: vi.fn().mockRejectedValue(rejection) });
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));

    expect(await screen.findByRole("alert")).toHaveTextContent(rejection.message);
    expect(screen.getByRole("alert")).toHaveTextContent("Your original file was not changed.");
    expect(screen.getByText("Not loaded")).toBeInTheDocument();
  });

  it("only uses the first of several dropped files", async () => {
    const { platform, dropHandlers } = fakePlatform();
    renderApp(platform);
    await waitFor(() => expect(platform.onFileDrop).toHaveBeenCalled());
    act(() => dropHandlers().onDrop(["C:\\a.docx", "C:\\b.docx"]));
    expect(await screen.findByText(/one file at a time/)).toBeInTheDocument();
    expect(platform.inspect).toHaveBeenCalledTimes(1);
  });

  it("can remove a loaded file", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await userEvent.click(screen.getByRole("button", { name: /drop files here/i }));
    await screen.findByText("Verified");
    await userEvent.click(screen.getByRole("button", { name: "Remove file" }));
    expect(screen.getByText("Drop files here")).toBeInTheDocument();
  });

  it("shows the risk before and after protection, with the reasons", async () => {
    const { platform } = fakePlatform();
    await scanned(platform);
    const risk = screen.getByRole("region", { name: "Privacy risk" });
    expect(risk).toHaveTextContent("As it is");
    expect(screen.getByLabelText("As it is: 43 out of 100, medium")).toBeInTheDocument();
    expect(screen.getByLabelText("Protected copy: 0 out of 100, none")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Why this score?" }));
    const factors = screen.getByRole("list", { name: "As it is" });
    expect(factors).toHaveTextContent("Government ids (PAN, Aadhaar, GSTIN)");
    expect(factors).toHaveTextContent("+25");
    expect(screen.getByText("Nothing sensitive would be shared.")).toBeInTheDocument();
  });

  it("explains each finding and groups findings by category", async () => {
    const { platform } = fakePlatform();
    await scanned(platform);
    expect(screen.getByText("Has the form of an e-mail address (name@domain).")).toBeInTheDocument();
    const categories = screen.getByRole("list", { name: "Findings by category" });
    expect(categories).toHaveTextContent("Government IDs");
    expect(categories).toHaveTextContent("PAN (income-tax id) 1");
    expect(categories).toHaveTextContent("1 masked");
  });

  it("can mask a value partly", async () => {
    const partly = RESULT.findings.map((f) =>
      f.id === "f2" ? { ...f, mask_style: "partial" as const, overridden: true } : f,
    );
    const { platform } = fakePlatform({ override: vi.fn().mockResolvedValue(updateWith(partly)) });
    await scanned(platform);
    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address f2"), "MASK:partial");
    expect(platform.override).toHaveBeenCalledWith(
      "scan_test",
      [{ value_group: 2, action: "MASK", mask_style: "partial" }],
      false,
    );
    expect(await screen.findByLabelText("Action for E-mail address f2")).toHaveValue("MASK:partial");
    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address f2"), "MASK");
    expect(platform.override).toHaveBeenLastCalledWith(
      "scan_test",
      [{ value_group: 2, action: "MASK", mask_style: "typed_placeholder" }],
      false,
    );
  });

  it("teaches Airlock that a value is not sensitive", async () => {
    const remaining = RESULT.findings.filter((f) => f.id !== "f2");
    const { platform } = fakePlatform({ teach: vi.fn().mockResolvedValue(updateWith(remaining)) });
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Teach Airlock about E-mail address f2" }));
    const panel = screen.getByRole("group", { name: "Teach Airlock about E-mail address" });
    expect(panel).toHaveTextContent("keeps only a one-way fingerprint");
    await userEvent.click(screen.getByRole("button", { name: "It's not sensitive" }));
    expect(platform.teach).toHaveBeenCalledWith("scan_test", "f2", "not_sensitive");
    expect(await screen.findByText(/won't flag this value again/)).toBeInTheDocument();
    expect(screen.queryByLabelText("Action for E-mail address f2")).not.toBeInTheDocument();
  });

  it("never offers to teach Airlock about credentials", async () => {
    const token = {
      ...RESULT.findings[0]!, id: "f9", entity_type: "API_KEY", entity_label: "API key or token",
      category: "CREDENTIALS" as const, partial_available: false,
    };
    const { platform } = fakePlatform({ scan: vi.fn().mockResolvedValue({ ...RESULT, findings: [token] }) });
    await scanned(platform);
    expect(screen.queryByRole("button", { name: /Teach Airlock about API key/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "Mask partly" })).not.toBeInTheDocument();
  });

  it("leaves company-rule matches to the rule itself", async () => {
    const term = {
      ...RESULT.findings[0]!, id: "f8", entity_type: "INTERNAL_PROJECT", entity_label: "Internal project",
      category: "INTELLECTUAL_PROPERTY" as const, detector: "custom.normalized", rule_id: "rule_1",
    };
    const { platform } = fakePlatform({ scan: vi.fn().mockResolvedValue({ ...RESULT, findings: [term] }) });
    await scanned(platform);
    expect(screen.getByLabelText("Action for Internal project f8")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Teach Airlock/ })).not.toBeInTheDocument();
  });

  it("manages company rules in Settings and refreshes the open scan", async () => {
    const rule = {
      id: "rule_1", kind: "normalized" as const, pattern: "Project Falcon", aliases: [],
      category_id: "CONFIDENTIAL_TERM", action: null, enabled: true, created_at: "", updated_at: "",
    };
    const listRules = vi
      .fn()
      .mockResolvedValueOnce(RULES)
      .mockResolvedValue({ ...RULES, rules: [rule] });
    const { platform } = fakePlatform({
      listRules,
      createRule: vi.fn().mockResolvedValue(rule),
      refresh: vi.fn().mockResolvedValue(updateWith(RESULT.findings)),
    });
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(screen.getByRole("heading", { name: "Company rules" })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Word, phrase or pattern"), "Project Falcon");
    await userEvent.click(screen.getByRole("button", { name: "Add Rule" }));
    expect(platform.createRule).toHaveBeenCalledWith({
      kind: "normalized",
      pattern: "Project Falcon",
      category_id: "CONFIDENTIAL_TERM",
      action: null,
    });
    expect(await screen.findByRole("list", { name: "Saved company rules" })).toHaveTextContent("Project Falcon");

    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(platform.refresh).toHaveBeenCalledWith("scan_test");
    expect(await screen.findByText("Results updated with your new settings.")).toBeInTheDocument();
  });

  it("does not refresh the scan when nothing changed in Settings", async () => {
    const { platform } = fakePlatform();
    await scanned(platform);
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    await userEvent.click(screen.getByRole("button", { name: "Done" }));
    expect(platform.refresh).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { name: "What Airlock found" })).toBeInTheDocument();
  });

  it("duplicates a built-in profile and edits actions and mask styles", async () => {
    const builtin = profileFixture("company-default", "Company Default", true);
    const custom = profileFixture("prof_1", "Company Default (copy)", false);
    const listProfiles = vi
      .fn()
      .mockResolvedValueOnce({ default_id: "company-default", profiles: [builtin], entity_types: ENTITY_TYPES })
      .mockResolvedValueOnce({ default_id: "company-default", profiles: [builtin], entity_types: ENTITY_TYPES })
      .mockResolvedValue({ default_id: "company-default", profiles: [builtin, custom], entity_types: ENTITY_TYPES });
    const redacted = {
      ...custom,
      actions: { ...custom.actions, EMAIL: { action: "REDACT" as const, source: "override", style: "typed_placeholder" as const } },
    };
    const { platform } = fakePlatform({
      listProfiles,
      createProfile: vi.fn().mockResolvedValue(custom),
      updateProfile: vi.fn().mockResolvedValueOnce({
        ...custom,
        actions: { ...custom.actions, EMAIL: { action: "MASK", source: "entity", style: "partial" } },
      }).mockResolvedValueOnce(redacted),
    });
    renderApp(platform);
    await waitFor(() => expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByLabelText("Action for E-mail address")).toBeDisabled();
    await userEvent.click(screen.getByRole("button", { name: "Duplicate" }));
    expect(platform.createProfile).toHaveBeenCalledWith("Company Default (copy)", "company-default");
    await waitFor(() => expect(screen.getByLabelText("Profile to edit")).toHaveValue("prof_1"));

    // Credentials can't be partly masked.
    const tokenStyle = screen.queryByLabelText("Mask style for API key or token");
    expect(tokenStyle).toBeNull();
    const emailStyle = screen.getByLabelText("Mask style for E-mail address");
    expect(emailStyle).toBeEnabled();
    await userEvent.selectOptions(emailStyle, "partial");
    expect(platform.updateProfile).toHaveBeenCalledWith("prof_1", { styles: { EMAIL: "partial" } });
    await userEvent.selectOptions(screen.getByLabelText("Action for E-mail address"), "REDACT");
    expect(platform.updateProfile).toHaveBeenLastCalledWith("prof_1", { actions: { EMAIL: "REDACT" } });
    expect(await screen.findByLabelText("Action for E-mail address")).toHaveValue("REDACT");
  });

  it("forgets every value marked not sensitive", async () => {
    const { platform } = fakePlatform({ allowListCount: vi.fn().mockResolvedValue(3) });
    renderApp(platform);
    await waitFor(() => expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByText("3 values")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Forget All" }));
    expect(platform.clearAllowList).toHaveBeenCalled();
    expect(await screen.findByText("0 values")).toBeInTheDocument();
  });

  it("explains why the engine cannot start", async () => {
    const tampered = {
      kind: "engine_tampered",
      message: "Airlock's privacy engine has changed since it was installed, so Airlock will not run it.",
      next_step: "Reinstall Airlock from the original installer. Your files have not been touched.",
      original_affected: false,
    };
    const { platform } = fakePlatform({ engineInfo: vi.fn().mockRejectedValue(tampered) });
    renderApp(platform);
    expect(await screen.findByRole("alert")).toHaveTextContent(tampered.message);
    expect(screen.getByRole("alert")).toHaveTextContent("Reinstall Airlock from the original installer.");
    expect(screen.getByRole("alert")).not.toHaveTextContent("Your original file was not changed.");
  });

  it("installs a pasted licence, shows who it belongs to and can remove it", async () => {
    const { platform } = fakePlatform();
    renderApp(platform);
    await waitFor(() => expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByText("No licence is installed. Every feature is available.")).toBeInTheDocument();
    expect(screen.getByText("ABCD-EFGH-IJKL-MNOP-QRST")).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Paste Licence…" }));
    await userEvent.type(screen.getByLabelText("Paste the licence from your e-mail"), "AIRLOCK1.k.p.s");
    await userEvent.click(screen.getByRole("button", { name: "Install Licence" }));
    expect(platform.importLicenseText).toHaveBeenCalledWith("AIRLOCK1.k.p.s");
    expect(await screen.findByText("Licensed to Acme Pvt Ltd")).toBeInTheDocument();
    expect(screen.getByText(/10 seats · issued 2026-10-06 · activated on this computer/)).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Remove Licence" }));
    expect(await screen.findByText("No licence is installed. Every feature is available.")).toBeInTheDocument();
  });

  it("activates online and explains a licence that does not belong here", async () => {
    const invalid: LicenseStatus = {
      ...UNLICENSED,
      state: "invalid",
      problem: {
        kind: "license_other_machine",
        message: "This licence belongs to another computer.",
        next_step: "Activate your licence key on this computer, or ask for a licence for this machine code.",
      },
    };
    const { platform } = fakePlatform({ licenseStatus: vi.fn().mockResolvedValue(invalid) });
    renderApp(platform);
    await waitFor(() => expect(screen.getByRole("button", { name: "Settings" })).toBeEnabled());
    await userEvent.click(screen.getByRole("button", { name: "Settings" }));
    expect(await screen.findByText("This licence belongs to another computer.")).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText("Or activate online with your licence key"), "ALK-ABCDE-FGHJK-MNPQR-STUVW");
    await userEvent.click(screen.getByRole("button", { name: "Activate" }));
    expect(platform.activateLicense).toHaveBeenCalledWith("ALK-ABCDE-FGHJK-MNPQR-STUVW");
    expect(await screen.findByText("Licensed to Acme Pvt Ltd")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Copy" }));
    expect(platform.writeClipboard).toHaveBeenCalledWith("ABCD-EFGH-IJKL-MNOP-QRST");
  });

  it("reports an unavailable engine and retries on request", async () => {
    const engineInfo = vi
      .fn()
      .mockRejectedValueOnce({ kind: "engine_missing", message: "missing" })
      .mockResolvedValueOnce(INFO);
    const { platform } = fakePlatform({ engineInfo });
    renderApp(platform);
    expect(await screen.findByText("Local engine unavailable")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("Processing locally")).toBeInTheDocument();
  });

  it("never claims local processing when network isolation is off", async () => {
    const { platform } = fakePlatform({
      engineInfo: vi.fn().mockResolvedValue({ ...INFO, network_isolation: false }),
    });
    renderApp(platform);
    expect(await screen.findByText("Network isolation inactive")).toBeInTheDocument();
    expect(screen.queryByText("Processing locally")).not.toBeInTheDocument();
  });
});
