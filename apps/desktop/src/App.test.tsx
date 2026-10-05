import { act, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";
import type { DropHandlers, Platform } from "./engine/platform";
import { PlatformProvider } from "./engine/PlatformContext";
import type { EngineError, InspectResult } from "./engine/types";

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
  support: "planned",
  scannable: false,
};

function fakePlatform(overrides: Partial<Platform> = {}) {
  let drop: DropHandlers | undefined;
  const platform: Platform = {
    kind: "desktop",
    engineInfo: vi.fn().mockResolvedValue(INFO),
    inspect: vi.fn().mockResolvedValue(DOCX),
    pickFile: vi.fn().mockResolvedValue("C:\\Docs\\Contract.docx"),
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
    // Scanning is not available until the detection engine ships.
    expect(screen.getByRole("button", { name: "Scan Document" })).toBeDisabled();
    expect(screen.getByTestId("scan-hint")).toBeInTheDocument();
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
