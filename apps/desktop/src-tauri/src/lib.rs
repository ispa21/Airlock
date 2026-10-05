//! Airlock desktop host.
//!
//! Owns the window and the lifecycle of the local privacy engine. The web view
//! talks to the engine only through the allowlisted commands in `commands`.

mod commands;
mod engine;
mod locate;
mod logsink;

use std::sync::Arc;

use tauri::{Emitter, Manager, RunEvent};

use engine::{Engine, NotificationSink};
use logsink::LogSink;

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let log = Arc::new(match app.path().app_log_dir() {
                Ok(dir) => LogSink::open(&dir),
                Err(_) => LogSink::disabled(),
            });
            log.host_event("app_started", &[]);

            let handle = app.handle().clone();
            let notify: NotificationSink = Arc::new(move |message| {
                let _ = handle.emit("engine://notification", message);
            });
            let engine = Arc::new(Engine::new(locate::launch_spec(app.handle()), notify, log));

            // Warm the engine up so the UI can show "ready" without waiting
            // for the first user action.
            let warm = engine.clone();
            std::thread::spawn(move || {
                let _ = warm.info();
            });
            app.manage(engine);
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::engine_status,
            commands::engine_call
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Airlock application");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(engine) = handle.try_state::<Arc<Engine>>() {
                engine.shutdown();
            }
        }
    });
}
