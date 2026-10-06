import { useCallback, useEffect, useRef, useState } from "react";

import { DropZone, type Selection } from "./components/DropZone";
import { ErrorNotice } from "./components/ErrorNotice";
import { ExtractionReport } from "./components/ExtractionReport";
import { FindingsReport, type ActionHandler, type TeachHandler } from "./components/FindingsReport";
import { ProtectedCopy, type CopyState } from "./components/ProtectedCopy";
import { TextProtect } from "./components/TextProtect";
import { RiskCard } from "./components/RiskCard";
import { Settings } from "./components/Settings";
import { AirlockMark, ChevronIcon } from "./components/icons";
import { ScanProgress } from "./components/ScanProgress";
import { TrustBar } from "./components/TrustBar";
import { usePlatform } from "./engine/PlatformContext";
import {
  toEngineError,
  type EngineError,
  type EngineState,
  type Override,
  type PolicyUpdate,
  type Progress,
  type ScanResult,
} from "./engine/types";

interface ProfileOption {
  id: string;
  label: string;
}

/** Shown until the engine's list arrives (and if it cannot be loaded). */
const FALLBACK_PROFILES: ProfileOption[] = [{ id: "company-default", label: "Company Default" }];

type Scan =
  | { status: "idle" }
  | { status: "running"; tag: string; progress: Progress | null }
  | { status: "done"; result: ScanResult };

let scanCounter = 0;
const newTag = () => `scan-${Date.now().toString(36)}-${(scanCounter += 1)}`;

/** The current conversation's id (not a secret: the mapping stays in the engine's vault). */
const CONVERSATION_KEY = "airlock.conversation";

function savedConversation(): string | null {
  try {
    return localStorage.getItem(CONVERSATION_KEY);
  } catch {
    return null;
  }
}

export function App() {
  const platform = usePlatform();
  const [engine, setEngine] = useState<EngineState>({ state: "starting" });
  const [selection, setSelection] = useState<Selection>({ status: "empty" });
  const [scan, setScan] = useState<Scan>({ status: "idle" });
  const [error, setError] = useState<EngineError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [hovering, setHovering] = useState(false);
  const [profiles, setProfiles] = useState<ProfileOption[]>(FALLBACK_PROFILES);
  const [profile, setProfile] = useState(FALLBACK_PROFILES[0]!.id);
  const [applying, setApplying] = useState(false);
  const [copy, setCopy] = useState<CopyState>({ status: "none" });
  const [copyNote, setCopyNote] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<"file" | "text">("file");
  const [conversationId, setConversationState] = useState<string | null>(savedConversation);
  const [shareConversation, setShareConversation] = useState(false);
  // Confirms a "Teach Airlock" step or a refresh, next to the findings.
  const [findingsNote, setFindingsNote] = useState<string | null>(null);
  const [profilesVersion, setProfilesVersion] = useState(0);
  const copyTag = useRef<string | null>(null);
  // Ignore results from work that a newer file selection replaced.
  const latestRequest = useRef(0);
  const runningTag = useRef<string | null>(null);
  // The engine keeps a finished scan's text in memory until told to forget it.
  const lastScanId = useRef<string | null>(null);

  const setConversation = useCallback((id: string | null) => {
    setConversationState(id);
    if (!id) setShareConversation(false);
    try {
      if (id) localStorage.setItem(CONVERSATION_KEY, id);
      else localStorage.removeItem(CONVERSATION_KEY);
    } catch {
      // The id is only a convenience; without storage the next start begins a new conversation.
    }
  }, []);

  const connect = useCallback(async () => {
    setEngine({ state: "starting" });
    try {
      setEngine({ state: "ready", info: await platform.engineInfo() });
    } catch (err) {
      setEngine({ state: "unavailable", error: toEngineError(err) });
    }
  }, [platform]);

  useEffect(() => {
    void connect();
  }, [connect]);

  useEffect(() => {
    if (engine.state !== "ready") return;
    let cancelled = false;
    platform
      .listProfiles()
      .then((list) => {
        if (cancelled || list.profiles.length === 0) return;
        setProfiles(list.profiles.map((p) => ({ id: p.id, label: p.name })));
        // Keep the user's choice unless it was deleted in Settings.
        setProfile((current) =>
          profilesVersion > 0 && list.profiles.some((p) => p.id === current) ? current : list.default_id,
        );
      })
      .catch(() => undefined); // keep the fallback; scanning still works
    return () => {
      cancelled = true;
    };
  }, [engine.state, platform, profilesVersion]);

  const stopRunningScan = useCallback(() => {
    if (copyTag.current) void platform.cancel(copyTag.current).catch(() => undefined);
    copyTag.current = null;
    setCopy({ status: "none" });
    if (runningTag.current) void platform.cancel(runningTag.current).catch(() => undefined);
    runningTag.current = null;
    if (lastScanId.current) void platform.discard(lastScanId.current).catch(() => undefined);
    lastScanId.current = null;
  }, [platform]);

  const load = useCallback(
    async (paths: string[]) => {
      const path = paths[0];
      if (!path) return;
      stopRunningScan();
      const request = ++latestRequest.current;
      setError(null);
      setScan({ status: "idle" });
      setNotice(paths.length > 1 ? "Airlock protects one file at a time. Loaded the first file." : null);
      setSelection({ status: "inspecting", path });
      try {
        const result = await platform.inspect(path);
        if (request !== latestRequest.current) return;
        setSelection({ status: "verified", path, result });
      } catch (err) {
        if (request !== latestRequest.current) return;
        setSelection({ status: "rejected", path });
        setError(toEngineError(err));
      }
    },
    [platform, stopRunningScan],
  );

  useEffect(() => {
    let unsubscribe: (() => void) | undefined;
    let cancelled = false;
    void platform
      .onFileDrop({
        onHover: setHovering,
        onDrop: (paths) => {
          setView("file");
          void load(paths);
        },
      })
      .then((stop) => {
        if (cancelled) stop();
        else unsubscribe = stop;
      });
    return () => {
      cancelled = true;
      unsubscribe?.();
    };
  }, [platform, load]);

  const browse = useCallback(async () => {
    const path = await platform.pickFile();
    if (path) await load([path]);
  }, [platform, load]);

  const clear = useCallback(() => {
    stopRunningScan();
    latestRequest.current += 1;
    setSelection({ status: "empty" });
    setScan({ status: "idle" });
    setError(null);
    setNotice(null);
  }, [stopRunningScan]);

  const startScan = useCallback(async () => {
    if (selection.status !== "verified") return;
    if (lastScanId.current) void platform.discard(lastScanId.current).catch(() => undefined);
    lastScanId.current = null;
    const request = latestRequest.current;
    const tag = newTag();
    runningTag.current = tag;
    setError(null);
    setNotice(null);
    setCopy({ status: "none" });
    setFindingsNote(null);
    setScan({ status: "running", tag, progress: null });
    try {
      const result = await platform.scan(selection.path, profile, tag, (progress) => {
        if (runningTag.current === tag) setScan({ status: "running", tag, progress });
      });
      if (request !== latestRequest.current || runningTag.current !== tag) {
        void platform.discard(result.scan_id).catch(() => undefined);
        return;
      }
      lastScanId.current = result.scan_id;
      setScan({ status: "done", result });
    } catch (err) {
      if (request !== latestRequest.current) return;
      const failure = toEngineError(err);
      setScan({ status: "idle" });
      if (failure.kind === "cancelled") setNotice("Scan cancelled. Your file was not changed.");
      else setError(failure);
    } finally {
      if (runningTag.current === tag) runningTag.current = null;
    }
  }, [platform, selection, profile]);

  const applyUpdate = useCallback((update: PolicyUpdate) => {
    // Decisions changed: a copy made with the old ones must not be used.
    setCopy((current) => {
      if (current.status === "ready" || current.status === "verifying") {
        void platform.discardCopy(current.result.artifact_id).catch(() => undefined);
        return { status: "stale" };
      }
      return current;
    });
    setScan((current) =>
      current.status === "done" && current.result.scan_id === update.scan_id
        ? {
            status: "done",
            result: {
              ...current.result,
              findings: update.findings,
              summary: update.summary,
              policy: update.policy,
              risk: update.risk,
            },
          }
        : current,
    );
  }, [platform]);

  const policyCall = useCallback(
    async (call: () => Promise<PolicyUpdate>): Promise<boolean> => {
      setApplying(true);
      setError(null);
      try {
        applyUpdate(await call());
        return true;
      } catch (err) {
        setError(toEngineError(err));
        return false;
      } finally {
        setApplying(false);
      }
    },
    [applyUpdate],
  );

  const changeProfile = useCallback(
    (id: string) => {
      setProfile(id);
      if (scan.status === "done") void policyCall(() => platform.setProfile(scan.result.scan_id, id));
    },
    [platform, policyCall, scan],
  );

  const changeAction: ActionHandler = useCallback(
    (finding, action, acknowledgeRisk, maskStyle) => {
      if (scan.status !== "done") return;
      const entry: Override = { value_group: finding.value_group, action };
      if (maskStyle) entry.mask_style = maskStyle;
      void policyCall(() => platform.override(scan.result.scan_id, [entry], acknowledgeRisk));
    },
    [platform, policyCall, scan],
  );

  const teach: TeachHandler = useCallback(
    (finding, kind) => {
      if (scan.status !== "done") return;
      setFindingsNote(null);
      void policyCall(() => platform.teach(scan.result.scan_id, finding.id, kind)).then((ok) => {
        if (!ok) return;
        setFindingsNote(
          kind === "not_sensitive"
            ? "Airlock won't flag this value again, in any document. You can undo this in Settings."
            : "Saved as a company rule. Airlock will protect this value in every document.",
        );
      });
    },
    [platform, policyCall, scan],
  );

  const closeSettings = useCallback(
    (changed: boolean) => {
      setSettingsOpen(false);
      if (!changed) return;
      setProfilesVersion((v) => v + 1);
      // Re-check the open scan with the new rules, allow-list and profile.
      if (scan.status === "done") {
        const scanId = scan.result.scan_id;
        void policyCall(() => platform.refresh(scanId)).then((ok) => {
          if (ok) setFindingsNote("Results updated with your new settings.");
        });
      }
    },
    [platform, policyCall, scan],
  );

  const createCopy = useCallback(async () => {
    if (scan.status !== "done") return;
    const scanId = scan.result.scan_id;
    if (copy.status === "ready") void platform.discardCopy(copy.result.artifact_id).catch(() => undefined);
    const tag = newTag();
    copyTag.current = tag;
    setError(null);
    setCopyNote(null);
    setCopy({ status: "running" });
    let artifactId: string | null = null;
    try {
      const workspace = shareConversation && conversationId ? conversationId : null;
      const result = await platform.sanitize(scanId, tag, () => undefined, workspace);
      artifactId = result.artifact_id;
      if (copyTag.current !== tag) {
        void platform.discardCopy(result.artifact_id).catch(() => undefined);
        return;
      }
      // Every copy is read back and checked before it can leave Airlock.
      setCopy({ status: "verifying", result });
      const check = await platform.verify(result.artifact_id, tag, () => undefined);
      if (copyTag.current !== tag) {
        void platform.discardCopy(result.artifact_id).catch(() => undefined);
        return;
      }
      setCopy({ status: "ready", result, check });
    } catch (err) {
      if (copyTag.current !== tag) return;
      if (artifactId) void platform.discardCopy(artifactId).catch(() => undefined);
      const failure = toEngineError(err);
      setCopy({ status: "none" });
      if (failure.kind === "cancelled") setNotice("Protected copy cancelled. Your file was not changed.");
      else setError(failure);
    } finally {
      if (copyTag.current === tag) copyTag.current = null;
    }
  }, [platform, scan, copy, shareConversation, conversationId]);

  const saveCopy = useCallback(
    async (asText: boolean, acknowledgeReview: boolean) => {
      if (copy.status !== "ready") return;
      setError(null);
      setCopyNote(null);
      setExporting(true);
      try {
        const result = await platform.saveCopy(copy.result.artifact_id, { asText, acknowledgeReview });
        if (result.saved) {
          setCopyNote(`Saved as “${result.file_name ?? copy.result.file_name}”.`);
        }
      } catch (err) {
        setError(toEngineError(err));
      } finally {
        setExporting(false);
      }
    },
    [platform, copy],
  );

  const copyText = useCallback(
    async (acknowledgeReview: boolean) => {
      if (copy.status !== "ready") return;
      setError(null);
      setCopyNote(null);
      setExporting(true);
      try {
        const text = await platform.copyText(copy.result.artifact_id, acknowledgeReview);
        await platform.writeClipboard(text);
        setCopyNote(
          `Copied the protected text (${new Intl.NumberFormat("en-US").format(text.length)} characters). ` +
            "Paste it into your AI tool.",
        );
      } catch (err) {
        const failure = toEngineError(err);
        setError(
          failure.kind === "unexpected"
            ? {
                kind: "clipboard_unavailable",
                message: "Airlock could not put the text on the clipboard.",
                next_step: "Use Save as Text instead.",
                original_affected: false,
              }
            : failure,
        );
      } finally {
        setExporting(false);
      }
    },
    [platform, copy],
  );

  const cancelCopy = useCallback(() => {
    if (copyTag.current) void platform.cancel(copyTag.current).catch(() => undefined);
  }, [platform]);

  const cancelScan = useCallback(() => {
    if (runningTag.current) void platform.cancel(runningTag.current).catch(() => undefined);
  }, [platform]);

  const verified = selection.status === "verified" ? selection.result : null;
  const canScan = engine.state === "ready" && verified !== null && verified.scannable && scan.status !== "running";

  return (
    <div className="app">
      <main className="shell">
        <header className="brand">
          <AirlockMark />
          <span className="wordmark">AIRLOCK</span>
          {!settingsOpen && (
            <button
              type="button"
              className="ghost brand__settings"
              disabled={
                engine.state !== "ready" ||
                scan.status === "running" ||
                copy.status === "running" ||
                copy.status === "verifying"
              }
              onClick={() => setSettingsOpen(true)}
            >
              Settings
            </button>
          )}
        </header>

        {settingsOpen ? (
          <Settings onClose={closeSettings} />
        ) : (
          <>
            <section className="hero">
              <h1>The privacy layer between your data and&nbsp;AI.</h1>
              <p>Protect sensitive data before sending it to AI.</p>
            </section>

            <div className="views" role="tablist" aria-label="What to protect">
              <button
                type="button"
                role="tab"
                aria-selected={view === "file"}
                className="views__tab"
                onClick={() => setView("file")}
              >
                A file
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={view === "text"}
                className="views__tab"
                disabled={engine.state !== "ready"}
                onClick={() => setView("text")}
              >
                Text for AI
              </button>
            </div>
          </>
        )}

        {!settingsOpen && view === "text" && (
          <TextProtect conversationId={conversationId} onConversation={setConversation} />
        )}

        {!settingsOpen && view === "file" && (
          <>
            <DropZone
              selection={selection}
              hovering={hovering}
              disabled={engine.state === "unavailable"}
              onBrowse={() => void browse()}
              onClear={clear}
            />

            {engine.state === "unavailable" && !error && <ErrorNotice error={engine.error} aboutFile={false} />}
            {error && <ErrorNotice error={error} />}
            {notice && !error && <p className="inline-note">{notice}</p>}

            {scan.status === "running" ? (
              <ScanProgress progress={scan.progress} onCancel={cancelScan} />
            ) : (
              <div className="controls">
                <label className="field">
                  <span className="field__label">Privacy Profile</span>
                  <span className="select">
                    <select value={profile} disabled={applying} onChange={(e) => changeProfile(e.target.value)}>
                      {profiles.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.label}
                        </option>
                      ))}
                    </select>
                    <ChevronIcon className="select__chevron" />
                  </span>
                </label>

                <button type="button" className="primary" disabled={!canScan} onClick={() => void startScan()}>
                  {scan.status === "done" ? "Scan Again" : "Scan Document"}
                </button>
                {verified && !verified.scannable && (
                  <p className="inline-note" data-testid="scan-hint">
                    Airlock recognises this file type but cannot scan it yet.
                  </p>
                )}
              </div>
            )}

            {scan.status === "done" && (
              <>
                {scan.result.summary.total > 0 && <RiskCard risk={scan.result.risk} />}
                <FindingsReport
                  result={scan.result}
                  onAction={changeAction}
                  onTeach={teach}
                  note={findingsNote}
                  busy={applying || copy.status === "running" || copy.status === "verifying"}
                />
                {scan.result.summary.total > 0 && (
                  <ProtectedCopy
                    state={copy}
                    policy={scan.result.policy}
                    note={copyNote}
                    busy={exporting}
                    workspace={
                      conversationId
                        ? { conversationId, shared: shareConversation, onShare: setShareConversation }
                        : null
                    }
                    actions={{
                      onCreate: () => void createCopy(),
                      onCancel: cancelCopy,
                      onSave: (asText, ack) => void saveCopy(asText, ack),
                      onCopyText: (ack) => void copyText(ack),
                    }}
                  />
                )}
                <ExtractionReport summary={scan.result.extraction} />
              </>
            )}
          </>
        )}

        <div className="rule" role="presentation" />

        <TrustBar engine={engine} onRetry={() => void connect()} />
      </main>

      {platform.kind === "preview" && (
        <div className="preview-badge">Browser preview · not connected to the local engine</div>
      )}
    </div>
  );
}
