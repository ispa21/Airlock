import { useCallback, useEffect, useRef, useState } from "react";

import { DropZone, type Selection } from "./components/DropZone";
import { ErrorNotice } from "./components/ErrorNotice";
import { ExtractionReport } from "./components/ExtractionReport";
import { AirlockMark, ChevronIcon } from "./components/icons";
import { ScanProgress } from "./components/ScanProgress";
import { TrustBar } from "./components/TrustBar";
import { usePlatform } from "./engine/PlatformContext";
import {
  toEngineError,
  type EngineError,
  type EngineState,
  type ExtractSummary,
  type Progress,
} from "./engine/types";

const PROFILES = [{ id: "company-default", label: "Company Default" }];

type Scan =
  | { status: "idle" }
  | { status: "running"; tag: string; progress: Progress | null }
  | { status: "done"; summary: ExtractSummary };

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
  const [profile, setProfile] = useState(PROFILES[0]!.id);
  // Ignore results from work that a newer file selection replaced.
  const latestRequest = useRef(0);
  const runningTag = useRef<string | null>(null);

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

  const stopRunningScan = useCallback(() => {
    if (runningTag.current) void platform.cancel(runningTag.current).catch(() => undefined);
    runningTag.current = null;
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
    const request = latestRequest.current;
    const tag = newTag();
    runningTag.current = tag;
    setError(null);
    setNotice(null);
    setScan({ status: "running", tag, progress: null });
    try {
      const summary = await platform.extract(selection.path, tag, (progress) => {
        if (runningTag.current === tag) setScan({ status: "running", tag, progress });
      });
      if (request !== latestRequest.current || runningTag.current !== tag) return;
      setScan({ status: "done", summary });
    } catch (err) {
      if (request !== latestRequest.current) return;
      const failure = toEngineError(err);
      setScan({ status: "idle" });
      if (failure.kind === "cancelled") setNotice("Scan cancelled. Your file was not changed.");
      else setError(failure);
    } finally {
      if (runningTag.current === tag) runningTag.current = null;
    }
  }, [platform, selection]);

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
                <select value={profile} onChange={(e) => setProfile(e.target.value)}>
                  {PROFILES.map((p) => (
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

        {scan.status === "done" && <ExtractionReport summary={scan.summary} />}

        <div className="rule" role="presentation" />

        <TrustBar engine={engine} onRetry={() => void connect()} />
      </main>

      {platform.kind === "preview" && (
        <div className="preview-badge">Browser preview · not connected to the local engine</div>
      )}
    </div>
  );
}
