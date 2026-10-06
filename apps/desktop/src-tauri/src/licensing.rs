//! Licence commands for the web view: status, import, online activation, removal.
//!
//! Everything runs in the host. Online activation is the only network call the
//! app makes, it happens only when the user clicks "Activate", and it sends the
//! licence key, the machine code and the app version, nothing else. The
//! privacy engine is never involved, and no licence state limits scanning.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tauri::{AppHandle, Manager, State};
use tauri_plugin_dialog::DialogExt;

use crate::engine::EngineError;
use crate::license::{self, Keys, LicenseError, Store};
use crate::logsink::LogSink;

/// Set at build time for releases, e.g. `https://activate.example.com/v1/activate`.
const ACTIVATION_URL: Option<&str> = option_env!("AIRLOCK_ACTIVATION_URL");

pub struct Licensing {
    keys: Keys,
    store: Store,
    machine: String,
    log: Arc<LogSink>,
}

fn activation_url() -> Option<&'static str> {
    ACTIVATION_URL.filter(|url| {
        url.starts_with("https://")
            || (cfg!(debug_assertions)
                && (url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:")))
    })
}

fn license_error(e: LicenseError) -> EngineError {
    EngineError::new(e.kind(), e.message(), e.next_step())
}

/// `ALK-XXXXX-XXXXX-XXXXX-XXXXX`, any letter case; returned in upper case.
fn normalize_key(key: &str) -> Option<String> {
    let key = key.trim().to_ascii_uppercase();
    let groups: Vec<&str> = key.split('-').collect();
    let ok = groups.len() == 5
        && groups[0] == "ALK"
        && groups[1..].iter().all(|g| {
            g.len() == 5
                && g.bytes()
                    .all(|b| b.is_ascii_uppercase() || (b'2'..=b'9').contains(&b))
        });
    ok.then_some(key)
}

impl Licensing {
    pub fn new(data_dir: PathBuf, log: Arc<LogSink>) -> Self {
        Self {
            keys: Keys::builtin(),
            machine: license::machine_code(&data_dir),
            store: Store::new(&data_dir),
            log,
        }
    }

    pub fn status(&self) -> Value {
        let base = |state: &str| {
            json!({
                "state": state,
                "license": null,
                "problem": null,
                "machine_code": self.machine,
                "activation_available": activation_url().is_some(),
            })
        };
        let Some(text) = self.store.load() else {
            return base("unlicensed");
        };
        match license::verify(&text, &self.keys, &self.machine, &license::today()) {
            Ok(l) => {
                let mut status = base("licensed");
                status["license"] = json!({
                    "license_id": l.license_id,
                    "plan": l.plan,
                    "customer": l.customer,
                    "email": l.email,
                    "seats": l.seats,
                    "issued_at": l.issued_at,
                    "updates_until": l.updates_until,
                    "bound": l.machine.is_some(),
                });
                status
            }
            Err(e) => {
                let mut status = base("invalid");
                status["problem"] =
                    json!({"kind": e.kind(), "message": e.message(), "next_step": e.next_step()});
                status
            }
        }
    }

    fn install(&self, text: &str, event: &str) -> Result<Value, EngineError> {
        if text.len() > license::MAX_TEXT_BYTES {
            return Err(license_error(LicenseError::NotFound));
        }
        let verified = license::verify(text, &self.keys, &self.machine, &license::today());
        if let Err(e) = verified {
            self.log
                .host_event("license_rejected", &[("status", json!(e.kind()))]);
            return Err(license_error(e));
        }
        let token = license::extract_token(text).expect("verified text has a token");
        self.store.save(token).map_err(|_| {
            EngineError::new(
                "license_not_saved",
                "Airlock could not save the licence on this computer.",
                "Check that your user profile folder is writable, then try again.",
            )
        })?;
        self.log.host_event(event, &[]);
        Ok(self.status())
    }

    fn activate(&self, key: &str) -> Result<Value, EngineError> {
        let Some(url) = activation_url() else {
            return Err(EngineError::new(
                "activation_unavailable",
                "Online activation is not available in this version of Airlock.",
                "Import the licence file you received instead.",
            ));
        };
        let Some(key) = normalize_key(key) else {
            return Err(EngineError::new(
                "license_key_invalid",
                "That doesn't look like an Airlock licence key.",
                "Licence keys look like ALK-XXXXX-XXXXX-XXXXX-XXXXX. Copy it again from your e-mail.",
            ));
        };
        // A corporate proxy from the environment is honoured, except for a
        // loopback server (local testing), which must never go through one.
        let loopback = url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:");
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(20))
            .try_proxy_from_env(!loopback)
            .build();
        let reply = agent.post(url).send_json(json!({
            "license_key": key,
            "machine": self.machine,
            "app_version": env!("CARGO_PKG_VERSION"),
        }));
        let refused = |kind: &str, message: &str, next: &str| {
            self.log
                .host_event("license_activation_failed", &[("status", json!(kind))]);
            Err(EngineError::new(kind, message, next))
        };
        let body: Value = match reply {
            Ok(response) => response.into_json().unwrap_or(Value::Null),
            Err(ureq::Error::Status(404, _)) => {
                return refused(
                    "license_key_unknown",
                    "This licence key is not valid.",
                    "Check the key in your purchase e-mail, or contact support.",
                )
            }
            Err(ureq::Error::Status(409, _)) => {
                return refused(
                    "license_no_seats",
                    "This licence key is already active on all the computers it covers.",
                    "Contact support to move it from a computer you no longer use.",
                )
            }
            Err(ureq::Error::Status(429, _)) => {
                return refused(
                    "activation_busy",
                    "Too many activation attempts.",
                    "Wait a minute, then try again.",
                )
            }
            Err(_) => {
                return refused(
                    "activation_unreachable",
                    "Airlock could not reach the activation server.",
                    "Check the internet connection, or import a licence file instead.",
                )
            }
        };
        let token = body["license"].as_str().unwrap_or_default().to_owned();
        self.install(&token, "license_activated")
    }

    fn remove(&self) -> Result<Value, EngineError> {
        self.store.remove().map_err(|_| {
            EngineError::new(
                "license_not_removed",
                "Airlock could not remove the licence.",
                "Try again.",
            )
        })?;
        self.log.host_event("license_removed", &[]);
        Ok(self.status())
    }
}

async fn blocking<T: Send + 'static>(
    job: impl FnOnce() -> Result<T, EngineError> + Send + 'static,
) -> Result<T, EngineError> {
    tauri::async_runtime::spawn_blocking(job)
        .await
        .map_err(|_| EngineError::engine_unavailable())?
}

#[tauri::command]
pub fn license_status(licensing: State<'_, Arc<Licensing>>) -> Value {
    licensing.status()
}

/// Licence text pasted from an e-mail.
#[tauri::command]
pub fn license_import_text(
    licensing: State<'_, Arc<Licensing>>,
    text: String,
) -> Result<Value, EngineError> {
    licensing.install(&text, "license_installed")
}

/// A licence file chosen in the native open dialog (the web view never reads files).
#[tauri::command]
pub async fn license_import_file(
    app: AppHandle,
    licensing: State<'_, Arc<Licensing>>,
) -> Result<Value, EngineError> {
    let licensing = licensing.inner().clone();
    blocking(move || {
        let mut dialog = app
            .dialog()
            .file()
            .set_title("Choose your Airlock licence")
            .add_filter("Airlock licence", &["airlock-license", "txt"]);
        if let Some(window) = app.get_webview_window("main") {
            dialog = dialog.set_parent(&window);
        }
        let Some(chosen) = dialog.blocking_pick_file() else {
            return Ok(licensing.status());
        };
        let path = chosen
            .into_path()
            .map_err(|_| license_error(LicenseError::NotFound))?;
        let too_big = std::fs::metadata(&path)
            .map(|m| m.len() > license::MAX_TEXT_BYTES as u64)
            .unwrap_or(true);
        if too_big {
            return Err(license_error(LicenseError::NotFound));
        }
        let text =
            std::fs::read_to_string(&path).map_err(|_| license_error(LicenseError::NotFound))?;
        licensing.install(&text, "license_installed")
    })
    .await
}

#[tauri::command]
pub async fn license_activate(
    licensing: State<'_, Arc<Licensing>>,
    key: String,
) -> Result<Value, EngineError> {
    let licensing = licensing.inner().clone();
    blocking(move || licensing.activate(&key)).await
}

#[tauri::command]
pub fn license_remove(licensing: State<'_, Arc<Licensing>>) -> Result<Value, EngineError> {
    licensing.remove()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn licence_keys_are_normalised() {
        assert_eq!(
            normalize_key(" alk-abcde-fghjk-mnpqr-stuv2 ").as_deref(),
            Some("ALK-ABCDE-FGHJK-MNPQR-STUV2")
        );
        assert_eq!(normalize_key("ALK-ABCDE-FGHJK-MNPQR"), None);
        assert_eq!(normalize_key("XYZ-ABCDE-FGHJK-MNPQR-STUVW"), None);
        assert_eq!(normalize_key("ALK-ABCD!-FGHJK-MNPQR-STUVW"), None);
    }

    #[test]
    fn status_without_a_licence_and_with_a_bad_one() {
        let dir = std::env::temp_dir().join(format!("airlock-licensing-{}", std::process::id()));
        let licensing = Licensing::new(dir.clone(), Arc::new(LogSink::disabled()));
        let status = licensing.status();
        assert_eq!(status["state"], "unlicensed");
        assert_eq!(status["machine_code"].as_str().unwrap().len(), 24);

        let err = licensing
            .install("AIRLOCK1.unknown.e30.AAAA", "license_installed")
            .unwrap_err();
        assert_eq!(err.kind, "license_unknown_key");
        assert_eq!(licensing.status()["state"], "unlicensed");

        // A stored licence that no longer verifies is reported, not hidden.
        Store::new(&dir).save("AIRLOCK1.unknown.e30.AAAA").unwrap();
        let status = licensing.status();
        assert_eq!(status["state"], "invalid");
        assert_eq!(status["problem"]["kind"], "license_unknown_key");
        assert_eq!(licensing.remove().unwrap()["state"], "unlicensed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn activation_needs_https_in_release_builds() {
        if let Some(url) = activation_url() {
            assert!(url.starts_with("https://") || cfg!(debug_assertions));
        }
    }
}
