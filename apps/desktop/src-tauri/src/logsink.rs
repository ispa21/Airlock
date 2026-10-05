//! Persistent, content-free log file.
//!
//! The engine writes structured JSON records to stderr. This sink persists a
//! record only if it passes an independent allowlist check (known keys,
//! numbers, or short lowercase identifier tokens). Anything else, such as a
//! stray print from a library or a traceback that might quote document text,
//! is dropped and only counted. Host-side events go through the same check.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::ChildStderr;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value};

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;
const MAX_LINE_BYTES: u64 = 64 * 1024;
const ALLOWED_KEYS: &[&str] = &[
    "ts",
    "level",
    "event",
    "source",
    "method",
    "file_type",
    "format",
    "error_kind",
    "detector",
    "entity_type",
    "entity_count",
    "segment_count",
    "finding_count",
    "remaining_count",
    "size_bytes",
    "duration_ms",
    "request_id",
    "pid",
    "version",
    "protocol",
    "status",
    "exception_type",
    "logger",
    "dropped_fields",
    "count",
];

pub struct LogSink {
    file: Mutex<Option<File>>,
}

fn is_token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_.-".contains(&b))
}

/// True if every key is allowlisted and every value is a number or a token.
pub fn is_safe_record(record: &Map<String, Value>) -> bool {
    record.contains_key("event")
        && record.iter().all(|(key, value)| {
            ALLOWED_KEYS.contains(&key.as_str())
                && match value {
                    Value::Number(_) => true,
                    Value::String(s) => is_token(s),
                    _ => false,
                }
        })
}

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

impl LogSink {
    pub fn disabled() -> Self {
        Self {
            file: Mutex::new(None),
        }
    }

    pub fn open(dir: &Path) -> Self {
        let file = (|| -> std::io::Result<File> {
            fs::create_dir_all(dir)?;
            let path = dir.join("airlock.log");
            if fs::metadata(&path)
                .map(|m| m.len() > MAX_LOG_BYTES)
                .unwrap_or(false)
            {
                let _ = fs::rename(&path, dir.join("airlock.log.1"));
            }
            OpenOptions::new().create(true).append(true).open(path)
        })()
        .ok();
        Self {
            file: Mutex::new(file),
        }
    }

    fn write(&self, record: &Map<String, Value>) {
        if !is_safe_record(record) {
            return;
        }
        let mut guard = self.file.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(file) = guard.as_mut() {
            if let Ok(mut line) = serde_json::to_vec(record) {
                line.push(b'\n');
                let _ = file.write_all(&line);
            }
        }
    }

    pub fn host_event(&self, event: &str, fields: &[(&str, Value)]) {
        let mut record = Map::new();
        record.insert("ts".into(), Value::from((now() * 1000.0).round() / 1000.0));
        record.insert("level".into(), Value::from("info"));
        record.insert("source".into(), Value::from("host"));
        record.insert("event".into(), Value::from(event));
        for (key, value) in fields {
            record.insert((*key).to_owned(), value.clone());
        }
        self.write(&record);
    }

    /// Runs on a dedicated thread until the engine closes stderr.
    pub fn forward_engine_stderr(&self, stderr: ChildStderr) {
        let mut reader = BufReader::new(stderr);
        let mut line = Vec::new();
        let mut dropped: u64 = 0;
        loop {
            line.clear();
            match (&mut reader)
                .take(MAX_LINE_BYTES)
                .read_until(b'\n', &mut line)
            {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            match serde_json::from_slice::<Value>(&line) {
                Ok(Value::Object(mut record)) if is_safe_record(&record) => {
                    record.insert("source".into(), Value::from("engine"));
                    self.write(&record);
                }
                _ => dropped += 1,
            }
        }
        if dropped > 0 {
            self.host_event(
                "engine_unstructured_output_dropped",
                &[("count", Value::from(dropped))],
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn accepts_structured_records() {
        assert!(is_safe_record(&obj(
            json!({"ts": 1.5, "level": "info", "event": "scan_completed", "entity_count": 27, "file_type": "pdf"})
        )));
    }

    #[test]
    fn rejects_anything_that_could_carry_content() {
        for bad in [
            json!({"event": "x", "content": "hello"}),
            json!({"event": "x", "file_type": "Rahul Sharma"}),
            json!({"event": "x", "entity_type": "rahul@example.com"}),
            json!({"event": "x", "method": "C:\\Users\\me\\salary.xlsx"}),
            json!({"event": "x", "status": ["nested"]}),
            json!({"event": "x", "status": {"a": 1}}),
            json!({"event": "x", "status": true}),
            json!({"level": "info"}),
        ] {
            assert!(!is_safe_record(&obj(bad.clone())), "{bad}");
        }
    }

    #[test]
    fn host_events_are_written_and_validated() {
        let dir = std::env::temp_dir().join(format!("airlock-logsink-{}", std::process::id()));
        let sink = LogSink::open(&dir);
        sink.host_event("engine_ready", &[("duration_ms", json!(12))]);
        sink.host_event("Contains Spaces", &[]);
        sink.host_event("engine_ready", &[("leak", json!("secret"))]);
        let text = fs::read_to_string(dir.join("airlock.log")).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert!(text.contains("\"engine_ready\"") && !text.contains("secret"));
        let _ = fs::remove_dir_all(dir);
    }
}
