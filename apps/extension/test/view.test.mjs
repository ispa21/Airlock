import assert from "node:assert/strict";
import { test } from "node:test";

import { findingRows, statusLabel, summaryLine } from "../src/view.js";

const RESULT = {
  text: "Owner [EMAIL_1], password [REDACTED]",
  changed: 2,
  blocked: 1,
  actions: { MASK: 1, BLOCK: 1 },
  findings: [
    { entity_type: "EMAIL", entity_label: "E-mail address", preview: "r••••@example.invalid", action: "MASK" },
    { entity_type: "PASSWORD", entity_label: "Password or secret", preview: "••••••••", action: "BLOCK" },
  ],
  profile: { id: "company-default", name: "Company Default" },
};

test("the summary says what happened, including blocked items", () => {
  assert.equal(
    summaryLine(RESULT),
    "2 items found with Company Default: 1 masked, 1 removed (blocked). 1 password, key or token could not be shared and was removed.",
  );
  assert.equal(summaryLine({ ...RESULT, findings: [], actions: {} }), "Nothing sensitive was found. The text is unchanged.");
});

test("rows show masked previews only", () => {
  assert.deepEqual(findingRows(RESULT), [
    "E-mail address · r••••@example.invalid · masked",
    "Password or secret · •••••••• · removed (blocked)",
  ]);
});

test("status reflects the engine's network isolation", () => {
  assert.deepEqual(statusLabel({ network_isolation: true }), { tone: "ok", text: "Checking on this computer" });
  assert.equal(statusLabel({ network_isolation: false }).tone, "wait");
  assert.equal(statusLabel(null).text, "Airlock app not found");
});
