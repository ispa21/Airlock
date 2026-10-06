//! Supervisor and JSON-RPC client for the local Python engine.
//!
//! The engine is a child process speaking newline-delimited JSON-RPC 2.0 over
//! its stdin/stdout (see docs/IPC.md). There is no network socket: only this
//! process holds the pipes. The supervisor starts the engine lazily, performs
//! the protocol handshake, routes responses to waiting callers, forwards
//! engine notifications, restarts the engine after a crash (with a budget),
//! and shuts it down when the app exits.
//!
//! Document content never passes through here: requests carry file paths and
//! the engine reads files itself.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{json, Value};

use crate::logsink::LogSink;

pub const PROTOCOL_VERSION: &str = "1.0";
const MAX_FRAME_BYTES: u64 = 64 * 1024 * 1024;
/// First launch of a frozen engine can be slow (antivirus scans the binary).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(45);
const SHUTDOWN_GRACE: Duration = Duration::from_secs(3);
const MAX_RESTARTS: usize = 3;
const RESTART_WINDOW: Duration = Duration::from_secs(60);
const PROXY_VARS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "FTP_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "ftp_proxy",
    "no_proxy",
];

#[derive(Clone, Debug, Default)]
pub struct LaunchSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    /// SHA-256 the program must have (release builds). Checked before every start.
    pub expected_sha256: Option<String>,
}

/// SHA-256 of a file, as lowercase hex.
fn sha256_file(path: &std::path::Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

#[derive(Clone, Debug, Serialize)]
pub struct EngineInfo {
    pub engine_version: String,
    pub protocol_version: String,
    pub network_isolation: bool,
    pub methods: Vec<String>,
}

/// Error shape returned to the UI. Mirrors the engine's AirlockError data:
/// what happened, whether the original was affected, and what to do next.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct EngineError {
    pub kind: String,
    pub message: String,
    pub next_step: Option<String>,
    pub original_affected: bool,
}

impl EngineError {
    pub(crate) fn new(kind: &str, message: &str, next_step: &str) -> Self {
        Self {
            kind: kind.into(),
            message: message.into(),
            next_step: Some(next_step.into()),
            original_affected: false,
        }
    }

    pub fn engine_missing() -> Self {
        Self::new(
            "engine_missing",
            "Airlock could not start its local privacy engine because it is missing.",
            "Reinstall Airlock. Your files have not been touched.",
        )
    }

    pub fn engine_tampered() -> Self {
        Self::new(
            "engine_tampered",
            "Airlock's privacy engine has changed since it was installed, so Airlock will not run it.",
            "Reinstall Airlock from the original installer. Your files have not been touched.",
        )
    }

    pub fn engine_unavailable() -> Self {
        Self::new(
            "engine_unavailable",
            "Airlock's local privacy engine stopped responding.",
            "Try again. If it keeps happening, restart Airlock.",
        )
    }

    pub fn engine_crashed() -> Self {
        Self::new(
            "engine_crashed",
            "Airlock's local privacy engine stopped unexpectedly while working on this request.",
            "Try again. The engine restarts automatically.",
        )
    }

    pub fn restart_budget_exhausted() -> Self {
        Self::new(
            "engine_failing",
            "Airlock's local privacy engine keeps stopping, so Airlock paused restarting it.",
            "Restart Airlock. If this continues, reinstall it.",
        )
    }

    pub fn incompatible() -> Self {
        Self::new(
            "engine_incompatible",
            "Airlock's privacy engine does not match this version of the app.",
            "Reinstall Airlock to repair the installation.",
        )
    }

    pub fn timeout() -> Self {
        Self::new(
            "timeout",
            "This operation took too long and was stopped.",
            "Try again with a smaller file.",
        )
    }

    pub fn method_not_allowed() -> Self {
        Self::new(
            "not_allowed",
            "This operation is not available.",
            "Update Airlock to the latest version.",
        )
    }

    pub fn invalid_params() -> Self {
        Self::new(
            "invalid_params",
            "Airlock received an invalid request.",
            "Try again. If it keeps happening, restart Airlock.",
        )
    }

    /// Convert a JSON-RPC error object from the engine.
    fn from_rpc(error: &Value) -> Self {
        if let Some(data) = error.get("data").filter(|d| d.is_object()) {
            let text = |k: &str| data.get(k).and_then(Value::as_str).map(str::to_owned);
            if let (Some(kind), Some(message)) = (text("kind"), text("message")) {
                return Self {
                    kind,
                    message,
                    next_step: text("next_step"),
                    original_affected: data
                        .get("original_affected")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                };
            }
        }
        match error.get("code").and_then(Value::as_i64) {
            Some(-32001) => Self::new(
                "cancelled",
                "The operation was cancelled.",
                "Start it again when ready.",
            ),
            Some(-32601) => Self::method_not_allowed(),
            Some(-32602) => Self::invalid_params(),
            _ => Self::engine_unavailable(),
        }
    }
}

type Reply = Result<Value, EngineError>;
type Pending = Arc<Mutex<HashMap<u64, Sender<Reply>>>>;
pub type NotificationSink = Arc<dyn Fn(Value) + Send + Sync>;

struct Running {
    child: Child,
    /// `None` once closed during shutdown (EOF tells the engine to exit).
    stdin: Option<ChildStdin>,
    pending: Pending,
    alive: Arc<AtomicBool>,
    info: Option<EngineInfo>,
}

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Engine {
    spec: LaunchSpec,
    state: Mutex<Option<Running>>,
    next_id: AtomicU64,
    restarts: Mutex<Vec<Instant>>,
    notify: NotificationSink,
    log: Arc<LogSink>,
    /// In-flight request id -> UI tag, so the UI can follow progress and cancel.
    tags: Arc<Mutex<HashMap<u64, String>>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding a lock must not wedge the app forever.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Engine {
    pub fn new(spec: LaunchSpec, notify: NotificationSink, log: Arc<LogSink>) -> Self {
        Self {
            spec,
            state: Mutex::new(None),
            next_id: AtomicU64::new(1),
            restarts: Mutex::new(Vec::new()),
            notify,
            log,
            tags: Arc::default(),
        }
    }

    /// Start the engine if needed and return its handshake information.
    pub fn info(&self) -> Result<EngineInfo, EngineError> {
        let mut state = lock(&self.state);
        self.ensure_running(&mut state)?;
        Ok(state
            .as_ref()
            .and_then(|r| r.info.clone())
            .expect("running engine has completed its handshake"))
    }

    /// Send a request and block until the response, a crash or the timeout.
    #[cfg(test)]
    pub fn call(&self, method: &str, params: Value, timeout: Duration) -> Reply {
        self.call_tagged(method, params, timeout, None)
    }

    /// Like [`Engine::call`]; `tag` lets the UI match progress notifications
    /// to this request and cancel it with [`Engine::cancel`].
    pub fn call_tagged(
        &self,
        method: &str,
        params: Value,
        timeout: Duration,
        tag: Option<&str>,
    ) -> Reply {
        let (id, rx) = {
            let mut state = lock(&self.state);
            self.ensure_running(&mut state)?;
            let running = state.as_mut().expect("ensure_running guarantees Some");
            let id = self.next_id.fetch_add(1, Ordering::Relaxed);
            if let Some(tag) = tag {
                lock(&self.tags).insert(id, tag.to_owned());
            }
            match Self::send_request(running, id, method, params) {
                Ok(rx) => (id, rx),
                Err(err) => {
                    lock(&self.tags).remove(&id);
                    return Err(err);
                }
            }
        };
        let reply = match rx.recv_timeout(timeout) {
            Ok(reply) => reply,
            Err(RecvTimeoutError::Timeout) => {
                if let Some(running) = lock(&self.state).as_mut() {
                    lock(&running.pending).remove(&id);
                }
                self.send_cancel(id);
                Err(EngineError::timeout())
            }
            Err(RecvTimeoutError::Disconnected) => Err(EngineError::engine_crashed()),
        };
        lock(&self.tags).remove(&id);
        reply
    }

    /// Ask the engine to cancel the in-flight request carrying `tag`.
    /// The waiting call then completes with a `cancelled` error.
    pub fn cancel(&self, tag: &str) -> bool {
        let id = lock(&self.tags)
            .iter()
            .find(|(_, t)| t.as_str() == tag)
            .map(|(id, _)| *id);
        match id {
            Some(id) => {
                self.send_cancel(id);
                true
            }
            None => false,
        }
    }

    fn send_cancel(&self, id: u64) {
        let cancel = json!({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": id}});
        if let Some(running) = lock(&self.state).as_mut() {
            if let Some(stdin) = running.stdin.as_mut() {
                let _ = write_frame(stdin, &cancel);
            }
        }
    }

    /// Ask the engine to exit, then make sure it has.
    pub fn shutdown(&self) {
        let Some(mut running) = lock(&self.state).take() else {
            return;
        };
        let bye = json!({"jsonrpc": "2.0", "method": "system.shutdown"});
        if let Some(mut stdin) = running.stdin.take() {
            let _ = write_frame(&mut stdin, &bye);
        } // stdin dropped here: EOF
        let deadline = Instant::now() + SHUTDOWN_GRACE;
        while Instant::now() < deadline {
            if let Ok(Some(_)) = running.child.try_wait() {
                break;
            }
            thread::sleep(Duration::from_millis(25));
        }
        self.log.host_event("engine_stopped", &[]);
        // Drop kills the process if it is still running.
    }

    fn send_request(
        running: &mut Running,
        id: u64,
        method: &str,
        params: Value,
    ) -> Result<Receiver<Reply>, EngineError> {
        let (tx, rx) = mpsc::channel();
        lock(&running.pending).insert(id, tx);
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        let written = match running.stdin.as_mut() {
            Some(stdin) => write_frame(stdin, &frame).is_ok(),
            None => false,
        };
        if !written {
            lock(&running.pending).remove(&id);
            running.alive.store(false, Ordering::SeqCst);
            return Err(EngineError::engine_unavailable());
        }
        Ok(rx)
    }

    fn ensure_running(&self, state: &mut Option<Running>) -> Result<(), EngineError> {
        if let Some(running) = state.as_ref() {
            if running.alive.load(Ordering::SeqCst) {
                return Ok(());
            }
            self.log.host_event("engine_exited", &[]);
        }
        *state = None; // drops (and reaps) a dead engine
        self.take_restart_slot()?;
        *state = Some(self.spawn()?);
        Ok(())
    }

    fn take_restart_slot(&self) -> Result<(), EngineError> {
        let mut starts = lock(&self.restarts);
        let now = Instant::now();
        starts.retain(|t| now.duration_since(*t) < RESTART_WINDOW);
        // One initial start plus MAX_RESTARTS restarts per window.
        if starts.len() > MAX_RESTARTS {
            self.log.host_event("engine_restart_budget_exhausted", &[]);
            return Err(EngineError::restart_budget_exhausted());
        }
        starts.push(now);
        Ok(())
    }

    fn spawn(&self) -> Result<Running, EngineError> {
        if let Some(expected) = &self.spec.expected_sha256 {
            match sha256_file(&self.spec.program) {
                Ok(actual) if actual == *expected => {}
                Ok(_) => {
                    self.log.host_event("engine_integrity_failed", &[]);
                    return Err(EngineError::engine_tampered());
                }
                Err(_) => {
                    self.log.host_event("engine_spawn_failed", &[]);
                    return Err(EngineError::engine_missing());
                }
            }
        }
        let mut cmd = Command::new(&self.spec.program);
        cmd.args(&self.spec.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .env("PYTHONIOENCODING", "utf-8")
            .env("PYTHONUNBUFFERED", "1")
            .env("PYTHONDONTWRITEBYTECODE", "1")
            .env("PYTHONNOUSERSITE", "1");
        for var in PROXY_VARS {
            cmd.env_remove(var);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let started = Instant::now();
        let mut child = cmd.spawn().map_err(|_| {
            self.log.host_event("engine_spawn_failed", &[]);
            EngineError::engine_missing()
        })?;
        let stdin = child.stdin.take().expect("stdin is piped");
        let stdout = child.stdout.take().expect("stdout is piped");
        let stderr = child.stderr.take().expect("stderr is piped");

        let pending: Pending = Arc::default();
        let alive = Arc::new(AtomicBool::new(true));
        {
            // Attach the UI tag to progress notifications for tagged requests.
            let (tags, forward) = (self.tags.clone(), self.notify.clone());
            let notify: NotificationSink = Arc::new(move |mut message: Value| {
                let id = message
                    .pointer("/params/request_id")
                    .and_then(Value::as_u64);
                if let Some(tag) = id.and_then(|id| lock(&tags).get(&id).cloned()) {
                    if let Some(params) = message.get_mut("params").and_then(Value::as_object_mut) {
                        params.insert("tag".into(), Value::from(tag));
                    }
                }
                forward(message);
            });
            let (pending, alive) = (pending.clone(), alive.clone());
            thread::Builder::new()
                .name("engine-stdout".into())
                .spawn(move || read_loop(stdout, pending, alive, notify))
                .map_err(|_| EngineError::engine_unavailable())?;
        }
        {
            let log = self.log.clone();
            thread::Builder::new()
                .name("engine-stderr".into())
                .spawn(move || log.forward_engine_stderr(stderr))
                .map_err(|_| EngineError::engine_unavailable())?;
        }

        let mut running = Running {
            child,
            stdin: Some(stdin),
            pending,
            alive,
            info: None,
        };
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let rx = Self::send_request(
            &mut running,
            id,
            "system.hello",
            json!({"protocol_version": PROTOCOL_VERSION}),
        )?;
        let hello = match rx.recv_timeout(HANDSHAKE_TIMEOUT) {
            Ok(Ok(value)) => value,
            _ => {
                self.log.host_event("engine_handshake_failed", &[]);
                return Err(EngineError::engine_unavailable());
            }
        };
        if hello.get("compatible").and_then(Value::as_bool) != Some(true) {
            self.log.host_event("engine_incompatible", &[]);
            return Err(EngineError::incompatible());
        }
        let text = |k: &str| {
            hello
                .get(k)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        running.info = Some(EngineInfo {
            engine_version: text("engine_version"),
            protocol_version: text("protocol_version"),
            network_isolation: hello.get("network_isolation").and_then(Value::as_bool)
                == Some(true),
            methods: hello
                .get("methods")
                .and_then(Value::as_array)
                .map(|m| {
                    m.iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
        });
        let ms = started.elapsed().as_millis() as u64;
        self.log
            .host_event("engine_ready", &[("duration_ms", json!(ms))]);
        Ok(running)
    }
}

fn write_frame(stdin: &mut ChildStdin, message: &Value) -> std::io::Result<()> {
    // serde_json escapes control characters, so a frame never contains '\n'.
    let mut bytes = serde_json::to_vec(message)?;
    bytes.push(b'\n');
    stdin.write_all(&bytes)?;
    stdin.flush()
}

fn read_loop(
    stdout: ChildStdout,
    pending: Pending,
    alive: Arc<AtomicBool>,
    notify: NotificationSink,
) {
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::with_capacity(8 * 1024);
    loop {
        line.clear();
        match (&mut reader)
            .take(MAX_FRAME_BYTES + 1)
            .read_until(b'\n', &mut line)
        {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        if line.len() as u64 > MAX_FRAME_BYTES {
            break; // protocol violation: treat the engine as dead
        }
        let Ok(message) = serde_json::from_slice::<Value>(&line) else {
            continue;
        };
        if let Some(id) = message.get("id").and_then(Value::as_u64) {
            if let Some(tx) = lock(&pending).remove(&id) {
                let reply = match (message.get("result"), message.get("error")) {
                    (Some(result), None) => Ok(result.clone()),
                    (_, Some(error)) => Err(EngineError::from_rpc(error)),
                    _ => Err(EngineError::engine_unavailable()),
                };
                let _ = tx.send(reply);
            }
        } else if message.get("method").and_then(Value::as_str).is_some() {
            notify(message);
        }
    }
    alive.store(false, Ordering::SeqCst);
    for (_, tx) in lock(&pending).drain() {
        let _ = tx.send(Err(EngineError::engine_crashed()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn engine_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../engine")
    }

    fn venv_python() -> Option<PathBuf> {
        let dir = engine_dir().join(".venv");
        [dir.join("bin/python"), dir.join("Scripts/python.exe")]
            .into_iter()
            .find(|p| p.exists())
    }

    fn engine_with(spec: LaunchSpec) -> (Engine, Arc<Mutex<Vec<Value>>>) {
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let sink = seen.clone();
        let notify: NotificationSink = Arc::new(move |v| lock(&sink).push(v));
        (
            Engine::new(spec, notify, Arc::new(LogSink::disabled())),
            seen,
        )
    }

    fn python_script(python: &Path, script: &str) -> LaunchSpec {
        LaunchSpec {
            program: python.to_path_buf(),
            args: vec!["-c".into(), script.into()],
            ..Default::default()
        }
    }

    #[test]
    fn real_engine_handshake_and_calls() {
        let Some(python) = venv_python() else {
            eprintln!("skipping: engine venv not found (run `uv sync` in engine/)");
            return;
        };
        let spec = LaunchSpec {
            program: python,
            args: vec!["-m".into(), "airlock_engine".into()],
            ..Default::default()
        };
        let (engine, _) = engine_with(spec);
        let info = engine.info().expect("engine starts");
        assert_eq!(info.protocol_version, PROTOCOL_VERSION);
        assert!(info.network_isolation);
        assert!(info.methods.contains(&"document.inspect".to_string()));

        let health = engine
            .call("system.health", json!({}), Duration::from_secs(10))
            .unwrap();
        assert_eq!(health["status"], "ok");

        let missing = engine
            .call(
                "document.inspect",
                json!({"path": "/definitely/not/here.pdf"}),
                Duration::from_secs(10),
            )
            .unwrap_err();
        assert_eq!(missing.kind, "file_not_found");
        assert!(!missing.original_affected);
        assert!(missing.next_step.is_some());

        let manifest = engine_dir().join("pyproject.toml").canonicalize().unwrap();
        let inspected = engine
            .call(
                "document.inspect",
                json!({"path": manifest}),
                Duration::from_secs(10),
            )
            .unwrap();
        assert_eq!(inspected["format"], "toml");
        engine.shutdown();
    }

    /// A fake engine that answers the handshake, then exits on the next request.
    const CRASHY: &str = r#"
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "system.hello":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {
            "compatible": True, "engine_version": "test", "protocol_version": "1.0",
            "network_isolation": True, "methods": []}}), flush=True)
    else:
        print(json.dumps({"jsonrpc": "2.0", "method": "$/progress", "params": {"stage": "x"}}), flush=True)
        sys.exit(3)
"#;

    #[test]
    fn crash_fails_pending_call_restarts_and_respects_budget() {
        let Some(python) = venv_python() else { return };
        let (engine, seen) = engine_with(python_script(&python, CRASHY));
        for _ in 0..=MAX_RESTARTS {
            let err = engine
                .call("x.y", json!({}), Duration::from_secs(10))
                .unwrap_err();
            assert_eq!(err.kind, "engine_crashed");
        }
        // Budget exhausted: no further restarts inside the window.
        let err = engine
            .call("x.y", json!({}), Duration::from_secs(10))
            .unwrap_err();
        assert_eq!(err.kind, "engine_failing");
        assert!(!lock(&seen).is_empty(), "notifications are forwarded");
    }

    #[test]
    fn incompatible_engine_is_rejected() {
        let Some(python) = venv_python() else { return };
        let script = r#"
import json, sys
msg = json.loads(sys.stdin.readline())
print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"compatible": False}}), flush=True)
sys.stdin.read()
"#;
        let (engine, _) = engine_with(python_script(&python, script));
        assert_eq!(engine.info().unwrap_err().kind, "engine_incompatible");
    }

    #[test]
    fn timeout_is_reported() {
        let Some(python) = venv_python() else { return };
        let script = r#"
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "system.hello":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"compatible": True}}), flush=True)
"#;
        let (engine, _) = engine_with(python_script(&python, script));
        let err = engine
            .call("slow", json!({}), Duration::from_millis(300))
            .unwrap_err();
        assert_eq!(err.kind, "timeout");
        engine.shutdown();
    }

    /// A fake engine that reports progress, then waits for cancellation.
    const CANCELLABLE: &str = r#"
import json, sys
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "system.hello":
        print(json.dumps({"jsonrpc": "2.0", "id": msg["id"], "result": {"compatible": True}}), flush=True)
    elif msg.get("method") == "slow":
        slow_id = msg["id"]
        print(json.dumps({"jsonrpc": "2.0", "method": "$/progress",
                          "params": {"request_id": slow_id, "stage": "pages", "done": 1, "total": 9}}), flush=True)
    elif msg.get("method") == "$/cancelRequest" and msg["params"]["id"] == slow_id:
        print(json.dumps({"jsonrpc": "2.0", "id": slow_id, "error": {"code": -32001, "message": "cancelled"}}), flush=True)
"#;

    #[test]
    fn tagged_requests_get_tagged_progress_and_can_be_cancelled() {
        let Some(python) = venv_python() else { return };
        let (engine, seen) = engine_with(python_script(&python, CANCELLABLE));
        let engine = Arc::new(engine);
        let worker = {
            let engine = engine.clone();
            thread::spawn(move || {
                engine.call_tagged("slow", json!({}), Duration::from_secs(10), Some("scan-1"))
            })
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        while lock(&seen).is_empty() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(lock(&seen)[0]["params"]["tag"], "scan-1");
        assert!(engine.cancel("scan-1"));
        assert!(!engine.cancel("unknown"));
        let err = worker.join().unwrap().unwrap_err();
        assert_eq!(err.kind, "cancelled");
        assert!(lock(&engine.tags).is_empty());
        engine.shutdown();
    }

    #[test]
    fn missing_binary_gives_actionable_error() {
        let spec = LaunchSpec {
            program: PathBuf::from("/nonexistent/airlock-engine"),
            args: vec![],
            ..Default::default()
        };
        let (engine, _) = engine_with(spec);
        let err = engine.info().unwrap_err();
        assert_eq!(err.kind, "engine_missing");
        assert!(err.next_step.unwrap().contains("Reinstall"));
    }

    #[test]
    fn only_the_engine_that_was_shipped_is_started() {
        let Some(python) = venv_python() else {
            eprintln!("skipping: engine venv not found (run `uv sync` in engine/)");
            return;
        };
        let genuine = sha256_file(&python).expect("hash the interpreter");
        assert_eq!(genuine.len(), 64);
        let spec = LaunchSpec {
            program: python.clone(),
            args: vec!["-m".into(), "airlock_engine".into()],
            expected_sha256: Some(genuine),
        };
        let (engine, _) = engine_with(spec);
        assert!(engine.info().is_ok());
        engine.shutdown();

        let spec = LaunchSpec {
            program: python,
            args: vec!["-m".into(), "airlock_engine".into()],
            expected_sha256: Some("0".repeat(64)),
        };
        let (engine, _) = engine_with(spec);
        let err = engine.info().unwrap_err();
        assert_eq!(err.kind, "engine_tampered");
        assert!(err.next_step.unwrap().contains("Reinstall"));
    }

    #[test]
    fn rpc_errors_map_to_user_errors() {
        let structured = json!({"code": -32000, "message": "m", "data": {
            "kind": "format_mismatch", "message": "Bad file.", "next_step": "Save again.", "original_affected": false}});
        let e = EngineError::from_rpc(&structured);
        assert_eq!(
            (e.kind.as_str(), e.message.as_str()),
            ("format_mismatch", "Bad file.")
        );
        assert_eq!(
            EngineError::from_rpc(&json!({"code": -32001})).kind,
            "cancelled"
        );
        assert_eq!(
            EngineError::from_rpc(&json!({"code": -32603})).kind,
            "engine_unavailable"
        );
    }
}
