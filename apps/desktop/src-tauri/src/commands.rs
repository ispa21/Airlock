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

const ALLOWED_METHODS: &[&str] = &["system.health", "document.inspect"];

fn timeout_for(method: &str) -> Duration {
    match method {
        "document.inspect" => Duration::from_secs(30),
        _ => Duration::from_secs(10),
    }
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
) -> Result<Value, EngineError> {
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return Err(EngineError::method_not_allowed());
    }
    let params = params.unwrap_or_else(|| json!({}));
    if !params.is_object() {
        return Err(EngineError::invalid_params());
    }
    let engine = engine.inner().clone();
    let timeout = timeout_for(&method);
    blocking(move || engine.call(&method, params, timeout)).await
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
}
