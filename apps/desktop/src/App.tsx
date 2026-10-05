import { useCallback, useEffect, useRef, useState } from "react";

import { DropZone, type Selection } from "./components/DropZone";
import { ErrorNotice } from "./components/ErrorNotice";
import { AirlockMark, ChevronIcon } from "./components/icons";
import { TrustBar } from "./components/TrustBar";
import { usePlatform } from "./engine/PlatformContext";
import { toEngineError, type EngineError, type EngineState } from "./engine/types";

const PROFILES = [{ id: "company-default", label: "Company Default" }];

export function App() {
  const platform = usePlatform();
  const [engine, setEngine] = useState<EngineState>({ state: "starting" });
  const [selection, setSelection] = useState<Selection>({ status: "empty" });
  const [error, setError] = useState<EngineError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [hovering, setHovering] = useState(false);
  const [profile, setProfile] = useState(PROFILES[0]!.id);
  // Ignore results from an inspection that a newer file selection replaced.
  const latestRequest = useRef(0);

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

  const load = useCallback(
    async (paths: string[]) => {
      const path = paths[0];
      if (!path) return;
      const request = ++latestRequest.current;
      setError(null);
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
    [platform],
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
    latestRequest.current += 1;
    setSelection({ status: "empty" });
    setError(null);
    setNotice(null);
  }, []);

  const verified = selection.status === "verified" ? selection.result : null;
  const canScan = engine.state === "ready" && verified !== null && verified.scannable;

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

          <button type="button" className="primary" disabled={!canScan}>
            Scan Document
          </button>
          {verified && !verified.scannable && (
            <p className="inline-note" data-testid="scan-hint">
              File verified on this device and left unchanged. Sensitive-data scanning is not enabled
              in this build yet.
            </p>
          )}
        </div>

        <div className="rule" role="presentation" />

        <TrustBar engine={engine} onRetry={() => void connect()} />
      </main>

      {platform.kind === "preview" && (
        <div className="preview-badge">Browser preview · not connected to the local engine</div>
      )}
    </div>
  );
}
