import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { test } from "node:test";

const root = new URL("../", import.meta.url);
const manifest = JSON.parse(readFileSync(new URL("manifest.json", root), "utf8"));

test("the extension cannot reach the network or read pages", () => {
  assert.equal(manifest.manifest_version, 3);
  const csp = manifest.content_security_policy.extension_pages;
  assert.match(csp, /connect-src 'none'/);
  assert.match(csp, /script-src 'self';/);
  assert.equal(manifest.host_permissions, undefined);
  assert.equal(manifest.content_scripts, undefined);
  assert.equal(manifest.externally_connectable, undefined);
  assert.deepEqual([...manifest.permissions].sort(), ["clipboardWrite", "contextMenus", "nativeMessaging", "storage"]);
});

test("pages load only the extension's own scripts and never build HTML from strings", () => {
  const src = new URL("src/", root);
  for (const name of readdirSync(src)) {
    const text = readFileSync(new URL(name, src), "utf8");
    if (name.endsWith(".html")) {
      for (const [, url] of text.matchAll(/(?:src|href)="([^"]+)"/g)) assert.doesNotMatch(url, /^(https?:)?\/\//, `${name}: ${url}`);
    }
    if (name.endsWith(".js")) {
      assert.doesNotMatch(text, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(|new Function/, name);
      assert.doesNotMatch(text, /\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon/, name);
    }
  }
});
