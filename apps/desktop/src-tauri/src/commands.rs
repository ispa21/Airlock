//! Tauri commands exposed to the web view.
//!
//! The web view can only reach the engine through `engine_call`, and only for
//! the methods in `ALLOWED_METHODS`. Lifecycle methods such as
//! `system.shutdown` are reserved for the host.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::State;

use crate::engine::{Engine, EngineError, EngineInfo};

const ALLOWED_METHODS: &[&str] = &[
    "system.health",
    "document.inspect",
    "document.extract",
    "scan.start",
    "scan.set_profile",
    "scan.override",
    "scan.discard",
    "profiles.list",
    "profiles.create",
    "profiles.update",
    "profiles.delete",
    "profiles.set_default",
    "rules.list",
    "rules.create",
    "rules.update",
    "rules.delete",
    "rules.add_category",
];

fn timeout_for(method: &str) -> Duration {
    match method {
        "document.inspect" => Duration::from_secs(30),
        // The engine enforces its own 15-minute extraction limit; this only
        // guards against a wedged engine.
        "document.extract" => Duration::from_secs(1_000),
        // Extraction (≤ 15 min, enforced by the engine) plus detection.
        "scan.start" => Duration::from_secs(1_500),
        _ => Duration::from_secs(10),
    }
}

/// UI request tags are short opaque tokens.
fn valid_tag(tag: &str) -> bool {
    (1..=64).contains(&tag.len())
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, EngineError> + Send + 'static,
) -> Result<T, EngineError> {
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|_| EngineError::engine_unavailable())?
}

/// Starts the engine if necessary and returns its handshake details.
#[tauri::command]
pub async fn engine_status(engine: State<'_, Arc<Engine>>) -> Result<EngineInfo, EngineError> {
    let engine = engine.inner().clone();
    blocking(move || engine.info()).await
}

#[tauri::command]
pub async fn engine_call(
    engine: State<'_, Arc<Engine>>,
    method: String,
    params: Option<Value>,
    tag: Option<String>,
) -> Result<Value, EngineError> {
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(EngineError::method_not_allowed());
    }
    let params = params.unwrap_or_else(|| json!({}));
    if !params.is_object() || tag.as_deref().is_some_and(|t| !valid_tag(t)) {
        return Err(EngineError::invalid_params());
    }
    let engine = engine.inner().clone();
    let timeout = timeout_for(&method);
    blocking(move || engine.call_tagged(&method, params, timeout, tag.as_deref())).await
}

/// Cancel the in-flight request started with `tag`. Returns whether one was found.
#[tauri::command]
pub async fn engine_cancel(
    engine: State<'_, Arc<Engine>>,
    tag: String,
) -> Result<bool, EngineError> {
    if !valid_tag(&tag) {
        return Err(EngineError::invalid_params());
    }
    let engine = engine.inner().clone();
    blocking(move || Ok(engine.cancel(&tag))).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_methods_are_not_exposed() {
        assert!(!ALLOWED_METHODS.contains(&"system.shutdown"));
        assert!(!ALLOWED_METHODS.contains(&"system.hello"));
        assert!(ALLOWED_METHODS.iter().all(|m| !m.starts_with("$/")));
    }

    #[test]
    fn scan_methods_are_exposed_with_a_long_timeout() {
        assert!(ALLOWED_METHODS.contains(&"scan.start"));
        assert!(ALLOWED_METHODS.contains(&"rules.create"));
        assert!(ALLOWED_METHODS.contains(&"scan.override"));
        assert!(ALLOWED_METHODS.contains(&"profiles.list"));
        assert!(timeout_for("scan.start") > timeout_for("document.extract"));
    }

    #[test]
    fn tags_are_short_opaque_tokens() {
        assert!(valid_tag("scan-1a2b_3"));
        assert!(!valid_tag(""));
        assert!(!valid_tag("../etc"));
        assert!(!valid_tag(&"x".repeat(65)));
    }
}
