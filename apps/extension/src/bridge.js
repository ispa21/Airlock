// JSON-RPC 2.0 to the Airlock engine over a native-messaging port.
//
// The browser starts the installed engine (`com.airlock.engine`) and relays
// messages over stdio; nothing goes over the network. Progress notifications
// (messages without an id) are ignored here.
//
// An open port keeps the service worker, and with it the engine and its
// language model, alive. The port is closed after a few idle minutes so the
// engine exits; the next call starts it again.

export const HOST = "com.airlock.engine";
export const IDLE_MS = 5 * 60 * 1000;

const NOT_INSTALLED = {
  kind: "app_not_found",
  message: "The Airlock app was not found on this computer.",
  next_step: "Install Airlock for Windows, then try again.",
};

const CLOSED = {
  kind: "bridge_closed",
  message: "The connection to the Airlock app closed unexpectedly.",
  next_step: "Try again.",
};

/** An engine error ({code, message, data}) as the user-facing shape. */
export function toError(error) {
  const data = (error && error.data) || {};
  return {
    kind: data.kind || (error && error.code === -32601 ? "not_allowed" : "engine_error"),
    message: data.message || (error && error.message) || "Airlock could not do this.",
    next_step: data.next_step || null,
  };
}

/** Why the port closed, from `chrome.runtime.lastError`. */
export function disconnectError(reason) {
  return /not found|not exist|forbidden/i.test(reason || "") ? NOT_INSTALLED : CLOSED;
}

export class EngineBridge {
  /**
   * @param {() => chrome.runtime.Port} connect  opens a native-messaging port
   * @param {() => string} lastError            reads chrome.runtime.lastError
   * @param {number} idleMs                      close the port after this long unused
   */
  constructor(connect, lastError = () => "", idleMs = IDLE_MS) {
    this.connect = connect;
    this.lastError = lastError;
    this.idleMs = idleMs;
    this.idleTimer = null;
    this.port = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  ensure() {
    clearTimeout(this.idleTimer);
    this.idleTimer = null;
    if (this.port) return this.port;
    const port = this.connect();
    port.onMessage.addListener((message) => this.onMessage(message));
    port.onDisconnect.addListener(() => this.onDisconnect(port));
    this.port = port;
    return port;
  }

  onMessage(message) {
    if (!message || message.id === undefined || message.id === null) return;
    const waiting = this.pending.get(message.id);
    if (!waiting) return;
    this.pending.delete(message.id);
    if (message.error) waiting.reject(toError(message.error));
    else waiting.resolve(message.result);
  }

  /** Called when a call settles: start the idle countdown once nothing is waiting. */
  settled() {
    if (this.pending.size || !this.port) return;
    clearTimeout(this.idleTimer);
    this.idleTimer = setTimeout(() => {
      this.idleTimer = null;
      if (this.pending.size || !this.port) return;
      const port = this.port;
      this.port = null;
      port.disconnect();
    }, this.idleMs);
  }

  onDisconnect(port) {
    if (this.port !== port) return;
    clearTimeout(this.idleTimer);
    this.idleTimer = null;
    this.port = null;
    const error = disconnectError(this.lastError());
    for (const waiting of this.pending.values()) waiting.reject(error);
    this.pending.clear();
  }

  call(method, params = {}, timeoutMs = 120000) {
    const port = this.ensure();
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject({ kind: "timeout", message: "Airlock took too long to answer.", next_step: "Try again." });
        this.settled();
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (value) => {
          clearTimeout(timer);
          resolve(value);
          this.settled();
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
          this.settled();
        },
      });
      port.postMessage({ jsonrpc: "2.0", id, method, params });
    });
  }
}
