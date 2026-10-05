import { useCallback, useEffect, useRef, useState } from "react";

import { DropZone, type Selection } from "./components/DropZone";
import { ErrorNotice } from "./components/ErrorNotice";
import { ExtractionReport } from "./components/ExtractionReport";
import { FindingsReport, type ActionHandler } from "./components/FindingsReport";
import { ProtectedCopy, type CopyState } from "./components/ProtectedCopy";
import { AirlockMark, ChevronIcon } from "./components/icons";
import { ScanProgress } from "./components/ScanProgress";
import { TrustBar } from "./components/TrustBar";
import { usePlatform } from "./engine/PlatformContext";
import {
  toEngineError,
  type EngineError,
  type EngineState,
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
  const copyTag = useRef<string | null>(null);
  // Ignore results from work that a newer file selection replaced.
  const latestRequest = useRef(0);
  const runningTag = useRef<string | null>(null);
  // The engine keeps a finished scan's text in memory until told to forget it.
  const lastScanId = useRef<string | null>(null);

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
        setProfile(list.default_id);
      })
      .catch(() => undefined); // keep the fallback; scanning still works
    return () => {
      cancelled = true;
    };
  }, [engine.state, platform]);

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
      .onFileDrop({ onHover: setHovering, onDrop: (paths) => void load(paths) })
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
      if (current.status === "ready") {
        void platform.discardCopy(current.result.artifact_id).catch(() => undefined);
        return { status: "stale" };
      }
      return current;
    });
    setScan((current) =>
      current.status === "done" && current.result.scan_id === update.scan_id
        ? {
            status: "done",
            result: { ...current.result, findings: update.findings, summary: update.summary, policy: update.policy },
          }
        : current,
    );
  }, [platform]);

  const policyCall = useCallback(
    async (call: () => Promise<PolicyUpdate>) => {
      setApplying(true);
      setError(null);
      try {
        applyUpdate(await call());
      } catch (err) {
        setError(toEngineError(err));
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
    (finding, action, acknowledgeRisk) => {
      if (scan.status !== "done") return;
      void policyCall(() =>
        platform.override(scan.result.scan_id, [{ value_group: finding.value_group, action }], acknowledgeRisk),
      );
    },
    [platform, policyCall, scan],
  );

  const createCopy = useCallback(async () => {
    if (scan.status !== "done") return;
    const scanId = scan.result.scan_id;
    const tag = newTag();
    copyTag.current = tag;
    setError(null);
    setCopy({ status: "running" });
    try {
      const result = await platform.sanitize(scanId, tag, () => undefined);
      if (copyTag.current !== tag) {
        void platform.discardCopy(result.artifact_id).catch(() => undefined);
        return;
      }
      setCopy({ status: "ready", result });
    } catch (err) {
      if (copyTag.current !== tag) return;
      const failure = toEngineError(err);
      setCopy({ status: "none" });
      if (failure.kind === "cancelled") setNotice("Protected copy cancelled. Your file was not changed.");
      else setError(failure);
    } finally {
      if (copyTag.current === tag) copyTag.current = null;
    }
  }, [platform, scan]);

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
        </header>

        <section className="hero">
          <h1>The privacy layer between your data and&nbsp;AI.</h1>
          <p>Protect sensitive data before sending it to AI.</p>
        </section>

        <DropZone
          selection={selection}
          hovering={hovering}
          disabled={engine.state === "unavailable"}
          onBrowse={() => void browse()}
          onClear={clear}
        />

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
            <FindingsReport result={scan.result} onAction={changeAction} busy={applying || copy.status === "running"} />
            {scan.result.summary.total > 0 && (
              <ProtectedCopy
                state={copy}
                policy={scan.result.policy}
                onCreate={() => void createCopy()}
                onCancel={cancelCopy}
              />
            )}
            <ExtractionReport summary={scan.result.extraction} />
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
