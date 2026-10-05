//! Finds the engine executable.
//!
//! Release builds run the frozen engine bundled with the installer
//! (`<resources>/engine/airlock-engine[.exe]`). Debug builds run the engine
//! from source using `engine/.venv`, or `AIRLOCK_ENGINE_PYTHON` if set.

use std::path::PathBuf;

use tauri::{AppHandle, Manager};

use crate::engine::LaunchSpec;

const ENGINE_BIN: &str = if cfg!(windows) {
    "airlock-engine.exe"
} else {
    "airlock-engine"
};

pub fn launch_spec(app: &AppHandle) -> LaunchSpec {
    #[cfg(debug_assertions)]
    if let Some(spec) = dev_launch_spec() {
        return spec;
    }
    let program = app
        .path()
        .resource_dir()
        .map(|dir| dir.join("engine").join(ENGINE_BIN))
        .unwrap_or_else(|_| PathBuf::from(ENGINE_BIN));
    LaunchSpec {
        program,
        args: vec!["--log-level".into(), "info".into()],
    }
}

#[cfg(debug_assertions)]
fn dev_launch_spec() -> Option<LaunchSpec> {
    let args = vec![
        "-m".into(),
        "airlock_engine".into(),
        "--log-level".into(),
        "debug".into(),
    ];
    if let Some(python) = std::env::var_os("AIRLOCK_ENGINE_PYTHON") {
        return Some(LaunchSpec {
            program: python.into(),
            args,
        });
    }
    let venv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../engine/.venv");
    [venv.join("Scripts/python.exe"), venv.join("bin/python")]
        .into_iter()
        .find(|p| p.exists())
        .map(|program| LaunchSpec { program, args })
}
