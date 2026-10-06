import assert from "node:assert/strict";
import { test } from "node:test";

import { EngineBridge, disconnectError, toError } from "../src/bridge.js";

function fakePort() {
  const listeners = { message: [], disconnect: [] };
  return {
    sent: [],
    postMessage(message) {
      this.sent.push(message);
    },
    onMessage: { addListener: (fn) => listeners.message.push(fn) },
    onDisconnect: { addListener: (fn) => listeners.disconnect.push(fn) },
    reply(message) {
      for (const fn of listeners.message) fn(message);
    },
    close() {
      for (const fn of listeners.disconnect) fn();
    },
    disconnected: false,
    disconnect() {
      this.disconnected = true; // the browser does not fire onDisconnect on this side
    },
  };
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

test("calls are JSON-RPC requests matched by id; notifications are ignored", async () => {
  const port = fakePort();
  let connects = 0;
  const bridge = new EngineBridge(() => (connects++, port), () => "", 1);
  const first = bridge.call("system.health");
  const second = bridge.call("text.protect", { text: "hi" });
  assert.equal(connects, 1);
  assert.deepEqual(port.sent[1], { jsonrpc: "2.0", id: 2, method: "text.protect", params: { text: "hi" } });
  port.reply({ jsonrpc: "2.0", method: "$/progress", params: { stage: "detect" } });
  port.reply({ jsonrpc: "2.0", id: 2, result: { text: "[EMAIL_1]" } });
  port.reply({ jsonrpc: "2.0", id: 1, result: { status: "ok" } });
  assert.deepEqual(await first, { status: "ok" });
  assert.deepEqual(await second, { text: "[EMAIL_1]" });
});

test("engine errors become user-facing errors", async () => {
  const port = fakePort();
  const bridge = new EngineBridge(() => port, () => "", 1);
  const pending = bridge.call("text.protect", {});
  port.reply({
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32000, message: "m", data: { kind: "profile_not_found", message: "Gone.", next_step: "Pick another." } },
  });
  await assert.rejects(pending, { kind: "profile_not_found", message: "Gone.", next_step: "Pick another." });
  assert.equal(toError({ code: -32601, message: "Method not found" }).kind, "not_allowed");
});

test("a missing app and a closed connection are told apart, and the next call reconnects", async () => {
  const ports = [fakePort(), fakePort()];
  let reason = "Specified native messaging host not found.";
  const bridge = new EngineBridge(() => ports.shift() ?? fakePort(), () => reason, 1);
  const pending = bridge.call("system.health");
  bridge.port.close();
  await assert.rejects(pending, { kind: "app_not_found" });
  reason = "Native host has exited.";
  const again = bridge.call("system.health");
  bridge.port.close();
  await assert.rejects(again, { kind: "bridge_closed" });
  assert.equal(disconnectError("Access to the specified native messaging host is forbidden.").kind, "app_not_found");
});

test("calls time out instead of waiting forever", async () => {
  const bridge = new EngineBridge(() => fakePort(), () => "", 1);
  await assert.rejects(bridge.call("system.health", {}, 10), { kind: "timeout" });
  assert.equal(bridge.pending.size, 0);
});

test("an idle connection is closed so the engine can exit; the next call reconnects", async () => {
  const ports = [];
  const bridge = new EngineBridge(() => (ports.push(fakePort()), ports.at(-1)), () => "", 30);
  const slow = bridge.call("text.protect", { text: "hi" });
  await sleep(60);
  assert.equal(ports[0].disconnected, false, "never closed while a call is waiting");
  ports[0].reply({ jsonrpc: "2.0", id: 1, result: { text: "hi" } });
  await slow;
  const quick = bridge.call("system.health");
  ports[0].reply({ jsonrpc: "2.0", id: 2, result: { status: "ok" } });
  await quick;
  await sleep(10);
  assert.equal(ports[0].disconnected, false, "the countdown restarts after each call");
  await sleep(60);
  assert.equal(ports[0].disconnected, true);
  assert.equal(bridge.port, null);
  const again = bridge.call("system.health");
  assert.equal(ports.length, 2);
  ports[1].reply({ jsonrpc: "2.0", id: 3, result: { status: "ok" } });
  assert.deepEqual(await again, { status: "ok" });
});
