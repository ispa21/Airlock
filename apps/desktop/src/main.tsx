import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import type { Platform } from "./engine/platform";
import { PlatformProvider } from "./engine/PlatformContext";
import { tauriPlatform } from "./engine/tauriPlatform";
import "./styles/tokens.css";
import "./styles/app.css";

async function resolvePlatform(): Promise<Platform> {
  if ("__TAURI_INTERNALS__" in window) return tauriPlatform;
  // The preview only exists in dev builds; production code never falls back to it.
  if (import.meta.env.DEV) return (await import("./engine/previewPlatform")).previewPlatform;
  return tauriPlatform;
}

const platform = await resolvePlatform();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <PlatformProvider platform={platform}>
      <App />
    </PlatformProvider>
  </StrictMode>,
);
