// Popup: paste text, protect it with the local engine, copy the result.
// Only textContent is used to show anything, so nothing from a page or the
// engine is ever interpreted as HTML.

import { findingRows, statusLabel, summaryLine } from "./view.js";

const $ = (id) => document.getElementById(id);

function ask(message) {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (reply) => {
      if (chrome.runtime.lastError || !reply) {
        reject({ kind: "extension_error", message: "Airlock's extension stopped responding.", next_step: "Try again." });
      } else if (reply.ok) resolve(reply.result);
      else reject(reply.error);
    });
  });
}

function showError(error) {
  $("error").hidden = false;
  $("error-message").textContent = (error && error.message) || "Airlock could not do this.";
  $("error-next").textContent = (error && error.next_step) || "";
}

function setStatus(health) {
  const { tone, text } = statusLabel(health);
  $("status").dataset.tone = tone;
  $("status").textContent = text;
}

async function connect() {
  try {
    setStatus(await ask({ type: "status" }));
    const list = await ask({ type: "profiles" });
    for (const profile of list.profiles) {
      const option = document.createElement("option");
      option.value = profile.id;
      option.textContent = profile.name;
      option.selected = profile.id === list.default_id;
      $("profile").append(option);
    }
    $("protect").disabled = false;
  } catch (error) {
    setStatus(null);
    showError(error);
  }
}

async function protect() {
  $("error").hidden = true;
  $("protect").disabled = true;
  $("protect").textContent = "Checking…";
  try {
    const result = await ask({ type: "protect", text: $("input").value, profileId: $("profile").value || null });
    $("output").value = result.text;
    $("summary").textContent = summaryLine(result);
    $("findings").replaceChildren(
      ...findingRows(result).map((row) => {
        const item = document.createElement("li");
        item.textContent = row;
        return item;
      }),
    );
    $("result").hidden = false;
  } catch (error) {
    showError(error);
  } finally {
    $("protect").disabled = false;
    $("protect").textContent = "Protect";
  }
}

async function copy() {
  try {
    await navigator.clipboard.writeText($("output").value);
    $("copy").textContent = "Copied";
    setTimeout(() => ($("copy").textContent = "Copy Protected Text"), 1500);
  } catch {
    showError({ message: "Airlock could not copy the text.", next_step: "Select the protected text and copy it yourself." });
  }
}

$("protect").addEventListener("click", () => void protect());
$("copy").addEventListener("click", () => void copy());

// Text sent from the "Protect selected text" menu, if any.
chrome.storage.session.get("pendingText").then(({ pendingText }) => {
  if (pendingText) {
    $("input").value = pendingText;
    void chrome.storage.session.remove("pendingText");
  }
});

void connect();
