// Service worker: the only place that talks to the Airlock engine.
//
// The popup sends {type: "status" | "profiles" | "protect"} messages; the
// worker forwards them to the local engine over native messaging. Only this
// extension's own pages are answered, and only these three requests exist.

import { EngineBridge, HOST } from "./bridge.js";

const bridge = new EngineBridge(
  () => chrome.runtime.connectNative(HOST),
  () => (chrome.runtime.lastError && chrome.runtime.lastError.message) || "",
);

const MAX_TEXT = 200000;
const MENU_ID = "airlock-protect-selection";

async function handle(message) {
  switch (message && message.type) {
    case "status":
      return bridge.call("system.health", {}, 30000);
    case "profiles":
      return bridge.call("profiles.list", {}, 30000);
    case "protect": {
      const text = String(message.text || "");
      if (text.length > MAX_TEXT) {
        throw {
          kind: "text_too_long",
          message: "This text is too long to protect in one go.",
          next_step: "Protect it in parts, or save it as a file and use the Airlock app.",
        };
      }
      const params = { text };
      if (typeof message.profileId === "string") params.profile_id = message.profileId;
      return bridge.call("text.protect", params);
    }
    default:
      throw { kind: "unknown_request", message: "Unknown request.", next_step: null };
  }
}

/** Only this extension's own pages (the popup, also when opened in a tab). */
function fromOwnPage(sender) {
  return sender.id === chrome.runtime.id && typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!fromOwnPage(sender)) return false;
  handle(message).then(
    (result) => sendResponse({ ok: true, result }),
    (error) => sendResponse({ ok: false, error }),
  );
  return true; // the answer is sent asynchronously
});

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: MENU_ID,
    title: "Protect selected text with Airlock",
    contexts: ["selection", "editable"],
  });
});

// The selection goes to the popup through session storage (memory only,
// cleared when the browser closes); the popup takes it and clears it.
chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId !== MENU_ID) return;
  await chrome.storage.session.set({ pendingText: (info.selectionText || "").slice(0, MAX_TEXT) });
  try {
    await chrome.action.openPopup();
  } catch {
    await chrome.tabs.create({ url: chrome.runtime.getURL("src/popup.html") });
  }
});
