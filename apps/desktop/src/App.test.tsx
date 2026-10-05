import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { DropHandlers, Platform } from "./engine/platform";
import { PlatformProvider } from "./engine/PlatformContext";
import type { EngineError, ExtractSummary, InspectResult, Progress, ScanResult } from "./engine/types";

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

const RESULT: ScanResult = {
  scan_id: "scan_test",
  extraction: SUMMARY,
  detection_ms: 310,
  risk: null,
  findings: [
    {
      id: "f1", entity_type: "PAN", entity_label: "PAN (income-tax id)", category: "GOVERNMENT",
      severity: "high", confidence: 0.97, detector: "regex.pan", corroborated_by: [], rule_id: null,
      preview: "AB••••••4F", location: { kind: "comment", label: "Comments · paragraph 1" }, hidden: true,
      value_group: 1, action: "MASK", effective_action: "MASK", reason: "Company Default masks government ids.",
      overridden: false, covered_by: null, generalizable: false, high_risk: false,
    },
    {
      id: "f2", entity_type: "EMAIL", entity_label: "E-mail address", category: "PERSONAL",
      severity: "medium", confidence: 0.98, detector: "regex.email", corroborated_by: [], rule_id: null,
      preview: "r••••@example.invalid", location: { kind: "body", label: "Body · paragraph 2" }, hidden: false,
      value_group: 2, action: "MASK", effective_action: "MASK", reason: "Company Default masks personal data.",
      overridden: false, covered_by: null, generalizable: true, high_risk: false,
    },
  ],
  summary: {
    total: 2, listed: 2, distinct_values: 2, hidden: 1, max_severity: "high",
    by_severity: { critical: 0, high: 1, medium: 1, low: 0 },
    by_category: [{ category: "GOVERNMENT", count: 1 }, { category: "PERSONAL", count: 1 }],
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
    sanitize: vi.fn().mockResolvedValue(COPY),
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
    const update = { scan_id: "scan_test", findings: changed, summary: RESULT.summary, policy: RESULT.policy };
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
    const update = { scan_id: "scan_test", findings: RESULT.findings, summary: RESULT.summary, policy: RESULT.policy };
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
