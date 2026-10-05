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

/// The engine keeps its settings database (company rules, allow-list) in the
/// per-user app data folder, `%LOCALAPPDATA%\com.airlock.desktop` on Windows.
fn data_dir_args(app: &AppHandle) -> Vec<String> {
    match app.path().app_local_data_dir() {
        Ok(dir) => vec!["--data-dir".into(), dir.to_string_lossy().into_owned()],
        // No profile folder: rules live in memory for this session only.
        Err(_) => vec!["--memory-only".into()],
    }
}

pub fn launch_spec(app: &AppHandle) -> LaunchSpec {
    let mut spec = base_launch_spec(app);
    spec.args.extend(data_dir_args(app));
    spec
}

fn base_launch_spec(app: &AppHandle) -> LaunchSpec {
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
        // Set by the release build (build.rs); the host runs only that engine.
        expected_sha256: option_env!("AIRLOCK_ENGINE_SHA256").map(str::to_owned),
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
            expected_sha256: None,
        });
    }
    let venv = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../engine/.venv");
    [venv.join("Scripts/python.exe"), venv.join("bin/python")]
        .into_iter()
        .find(|p| p.exists())
        .map(|program| LaunchSpec {
            program,
            args,
            expected_sha256: None,
        })
}
