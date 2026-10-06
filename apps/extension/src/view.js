// Text for the popup, kept free of DOM code so it can be tested on its own.

const ACTION_PAST = {
  MASK: "masked",
  REDACT: "removed",
  GENERALIZE: "generalised",
  BLOCK: "removed (blocked)",
  ALLOW: "kept",
};

function plural(n, one, many = `${one}s`) {
  return `${n} ${n === 1 ? one : many}`;
}

/** One line under "Protected text". */
export function summaryLine(result) {
  if (!result.findings.length) return "Nothing sensitive was found. The text is unchanged.";
  const parts = Object.entries(result.actions || {})
    .filter(([, n]) => n > 0)
    .map(([action, n]) => `${n} ${ACTION_PAST[action] || action.toLowerCase()}`);
  let line = `${plural(result.findings.length, "item")} found with ${result.profile.name}: ${parts.join(", ")}.`;
  if (result.blocked > 0) {
    line += ` ${plural(result.blocked, "password, key or token", "passwords, keys or tokens")} could not be shared and ${
      result.blocked === 1 ? "was" : "were"
    } removed.`;
  }
  return line;
}

/** "E-mail address · r••••@example.invalid · masked" rows (masked previews only). */
export function findingRows(result) {
  return result.findings.map((f) => `${f.entity_label} · ${f.preview} · ${ACTION_PAST[f.action] || f.action}`);
}

export function statusLabel(health) {
  if (!health) return { tone: "bad", text: "Airlock app not found" };
  return health.network_isolation
    ? { tone: "ok", text: "Checking on this computer" }
    : { tone: "wait", text: "Network isolation off" };
}
