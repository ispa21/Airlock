fn main() {
    // Release packaging passes the SHA-256 of the frozen engine executable;
    // the host then refuses to start any other engine (see locate.rs).
    println!("cargo:rerun-if-env-changed=AIRLOCK_ENGINE_SHA256");
    if let Ok(hash) = std::env::var("AIRLOCK_ENGINE_SHA256") {
        let hash = hash.trim().to_ascii_lowercase();
        assert!(
            hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()),
            "AIRLOCK_ENGINE_SHA256 must be 64 hex digits"
        );
        println!("cargo:rustc-env=AIRLOCK_ENGINE_SHA256={hash}");
    }
    tauri_build::build()
}
