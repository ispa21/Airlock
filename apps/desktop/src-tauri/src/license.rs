//! Lifetime licences, verified offline in the host.
//!
//! A licence is one line: `AIRLOCK1.<key id>.<payload>.<signature>`, where the
//! payload is base64url JSON and the signature is Ed25519 over those payload
//! bytes (see `licensing/airlock_license.py`). The public keys come from
//! `licensing/public-keys.json`, compiled into the app. Nothing here touches
//! the privacy engine, and scanning never depends on the licence.
//!
//! A licence may be bound to a machine code: a one-way hash of the computer's
//! ID, so the ID itself is never shown or sent anywhere.

use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PREFIX: &str = "AIRLOCK1";
/// A licence file or pasted e-mail is never larger than this.
pub const MAX_TEXT_BYTES: usize = 64 * 1024;
const PUBLIC_KEYS: &str = include_str!("../../../../licensing/public-keys.json");

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct License {
    pub license_id: String,
    pub plan: String,
    pub customer: String,
    #[serde(default)]
    pub email: Option<String>,
    pub seats: u32,
    #[serde(default)]
    pub features: Vec<String>,
    pub issued_at: String,
    #[serde(default)]
    pub expiry: Option<String>,
    #[serde(default)]
    pub updates_until: Option<String>,
    #[serde(default)]
    pub machine: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenseError {
    NotFound,
    Malformed,
    UnknownKey,
    BadSignature,
    OtherMachine,
    Expired,
}

impl LicenseError {
    pub fn kind(self) -> &'static str {
        match self {
            Self::NotFound => "license_not_found",
            Self::Malformed => "license_malformed",
            Self::UnknownKey => "license_unknown_key",
            Self::BadSignature => "license_bad_signature",
            Self::OtherMachine => "license_other_machine",
            Self::Expired => "license_expired",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::NotFound => "No Airlock licence was found in this text or file.",
            Self::Malformed => "This licence is damaged or incomplete.",
            Self::UnknownKey => "This licence was not issued by Airlock.",
            Self::BadSignature => "This licence has been changed, so it is not valid.",
            Self::OtherMachine => "This licence belongs to another computer.",
            Self::Expired => "This licence has expired.",
        }
    }

    pub fn next_step(self) -> &'static str {
        match self {
            Self::OtherMachine => {
                "Activate your licence key on this computer, or ask for a licence for this machine code."
            }
            _ => "Copy the whole licence again from the e-mail or file you received, or contact support.",
        }
    }
}

/// Public keys the app accepts licences from.
pub struct Keys(Vec<(String, VerifyingKey)>);

impl Keys {
    /// The keys in `licensing/public-keys.json`, plus a development key from
    /// `AIRLOCK_DEV_LICENSE_KEY` (`id:base64url`) when the build sets one.
    pub fn builtin() -> Self {
        let mut keys = Self::from_json(PUBLIC_KEYS);
        if let Some(dev) = option_env!("AIRLOCK_DEV_LICENSE_KEY") {
            if let Some((id, raw)) = dev.split_once(':') {
                if let Some(key) = decode_key(raw) {
                    keys.0.push((id.to_owned(), key));
                }
            }
        }
        keys
    }

    pub fn from_json(text: &str) -> Self {
        #[derive(Deserialize)]
        struct Entry {
            id: String,
            ed25519: String,
        }
        #[derive(Deserialize)]
        struct File {
            #[serde(default)]
            keys: Vec<Entry>,
        }
        let file: File = serde_json::from_str(text).unwrap_or(File { keys: vec![] });
        Self(
            file.keys
                .into_iter()
                .filter_map(|e| decode_key(&e.ed25519).map(|k| (e.id, k)))
                .collect(),
        )
    }

    #[cfg(test)]
    pub fn from_pairs(pairs: Vec<(String, VerifyingKey)>) -> Self {
        Self(pairs)
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn get(&self, id: &str) -> Option<&VerifyingKey> {
        self.0.iter().find(|(k, _)| k == id).map(|(_, v)| v)
    }
}

fn decode_key(text: &str) -> Option<VerifyingKey> {
    let raw = URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .or_else(|_| STANDARD.decode(text))
        .ok()?;
    VerifyingKey::from_bytes(&raw.try_into().ok()?).ok()
}

/// The licence line in a file or an e-mail body; other lines are ignored.
pub fn extract_token(text: &str) -> Option<&str> {
    text.lines()
        .map(str::trim)
        .find(|line| line.starts_with(PREFIX) && line[PREFIX.len()..].starts_with('.'))
}

/// Check the signature, then the machine binding. `today` is `YYYY-MM-DD`.
pub fn verify(
    text: &str,
    keys: &Keys,
    machine_code: &str,
    today: &str,
) -> Result<License, LicenseError> {
    let token = extract_token(text).ok_or(LicenseError::NotFound)?;
    let parts: Vec<&str> = token.split('.').collect();
    let [_, key_id, body, signature] = parts[..] else {
        return Err(LicenseError::Malformed);
    };
    let key = keys.get(key_id).ok_or(LicenseError::UnknownKey)?;
    let body = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| LicenseError::Malformed)?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .and_then(|s| Signature::from_slice(&s).ok())
        .ok_or(LicenseError::Malformed)?;
    key.verify_strict(&body, &signature)
        .map_err(|_| LicenseError::BadSignature)?;
    let license: License = serde_json::from_slice(&body).map_err(|_| LicenseError::Malformed)?;
    if let Some(bound) = &license.machine {
        if bound != machine_code {
            return Err(LicenseError::OtherMachine);
        }
    }
    if let Some(expiry) = &license.expiry {
        if expiry.get(..10).is_some_and(|day| day < today) {
            return Err(LicenseError::Expired);
        }
    }
    Ok(license)
}

/// RFC 4648 base32, upper case, no padding.
fn base32(data: &[u8]) -> String {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in data {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ALPHABET[((buffer >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ALPHABET[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// `ABCD-EFGH-IJKL-MNOP-QRST`: 100 bits of SHA-256 over the machine ID.
pub fn machine_code_from(machine_id: &str) -> String {
    let digest = Sha256::digest(format!("airlock-machine-v1:{}", machine_id.trim()).as_bytes());
    let text = base32(&digest);
    text.as_bytes()[..20]
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or_default())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(windows)]
fn platform_machine_id() -> Option<String> {
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ, KEY_WOW64_64KEY};
    winreg::RegKey::predef(HKEY_LOCAL_MACHINE)
        .open_subkey_with_flags(
            r"SOFTWARE\Microsoft\Cryptography",
            KEY_READ | KEY_WOW64_64KEY,
        )
        .ok()?
        .get_value::<String, _>("MachineGuid")
        .ok()
}

#[cfg(not(windows))]
fn platform_machine_id() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .iter()
        .find_map(|p| fs::read_to_string(p).ok())
        .map(|s| s.trim().to_owned())
        .filter(|s| !s.is_empty())
}

/// The machine code for this computer. Falls back to a random ID kept in the
/// app's data folder when the system has none.
pub fn machine_code(data_dir: &Path) -> String {
    if let Some(id) = platform_machine_id() {
        return machine_code_from(&id);
    }
    let path = data_dir.join("machine-id");
    let id = fs::read_to_string(&path)
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            let id = format!(
                "{:x}",
                Sha256::digest(format!("{:?}", std::time::SystemTime::now()))
            );
            let _ = fs::create_dir_all(data_dir);
            let _ = fs::write(&path, &id);
            id
        });
    machine_code_from(&id)
}

/// Where the installed licence is kept: `<app data>/license/airlock.license`.
pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            path: data_dir.join("license").join("airlock.license"),
        }
    }

    pub fn load(&self) -> Option<String> {
        fs::read_to_string(&self.path).ok()
    }

    pub fn save(&self, token: &str) -> std::io::Result<()> {
        let dir = self.path.parent().expect("licence path has a parent");
        fs::create_dir_all(dir)?;
        let temporary = dir.join("airlock.license.tmp");
        fs::write(&temporary, format!("{token}\n"))?;
        fs::rename(&temporary, &self.path)
    }

    pub fn remove(&self) -> std::io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

/// Today's date (UTC) as `YYYY-MM-DD`, without a date crate.
pub fn today() -> String {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    // Civil-from-days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const MACHINE: &str = "ABCD-EFGH-IJKL-MNOP-QRST";

    fn signing() -> SigningKey {
        SigningKey::from_bytes(&std::array::from_fn(|i| i as u8))
    }

    fn keys() -> Keys {
        Keys::from_pairs(vec![("test-key".into(), signing().verifying_key())])
    }

    fn token(payload: &str) -> String {
        let signature = signing().sign(payload.as_bytes());
        format!(
            "{PREFIX}.test-key.{}.{}",
            URL_SAFE_NO_PAD.encode(payload),
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    const PAYLOAD: &str = r#"{"license_id":"lic_X","plan":"lifetime","customer":"Acme Pvt Ltd","email":null,"seats":3,"features":[],"issued_at":"2026-10-06T00:00:00Z","expiry":null,"updates_until":null,"machine":null}"#;

    #[test]
    fn a_signed_licence_verifies_and_reads() {
        let license = verify(
            &format!("Your licence:\n  {}  \n", token(PAYLOAD)),
            &keys(),
            MACHINE,
            "2026-10-06",
        )
        .unwrap();
        assert_eq!(license.customer, "Acme Pvt Ltd");
        assert_eq!(license.seats, 3);
        assert_eq!(license.machine, None);
    }

    #[test]
    fn a_licence_from_the_python_issuer_verifies() {
        // Issued with licensing/airlock_license.py and the same test seed.
        const FROM_PYTHON: &str = include_str!("../tests/fixtures/python-issued.license");
        let license = verify(FROM_PYTHON, &keys(), MACHINE, "2026-10-06").unwrap();
        assert_eq!(license.customer, "Acme Pvt Ltd");
        assert_eq!(license.machine.as_deref(), Some(MACHINE));
        assert_eq!(
            verify(
                FROM_PYTHON,
                &keys(),
                "ZZZZ-EFGH-IJKL-MNOP-QRST",
                "2026-10-06"
            ),
            Err(LicenseError::OtherMachine)
        );
    }

    #[test]
    fn changed_unknown_and_broken_licences_are_refused() {
        let good = token(PAYLOAD);
        let changed = good.replacen(
            &URL_SAFE_NO_PAD.encode(PAYLOAD),
            &URL_SAFE_NO_PAD.encode(PAYLOAD.replace("\"seats\":3", "\"seats\":999")),
            1,
        );
        let k = keys();
        assert_eq!(
            verify(&changed, &k, MACHINE, "2026-10-06"),
            Err(LicenseError::BadSignature)
        );
        assert_eq!(
            verify(
                &good.replace("test-key", "other"),
                &k,
                MACHINE,
                "2026-10-06"
            ),
            Err(LicenseError::UnknownKey)
        );
        assert_eq!(
            verify("hello", &k, MACHINE, "2026-10-06"),
            Err(LicenseError::NotFound)
        );
        assert_eq!(
            verify("AIRLOCK1.test-key.@@@.###", &k, MACHINE, "2026-10-06"),
            Err(LicenseError::Malformed)
        );
        let expired = PAYLOAD.replace("\"expiry\":null", "\"expiry\":\"2026-01-01\"");
        assert_eq!(
            verify(&token(&expired), &k, MACHINE, "2026-10-06"),
            Err(LicenseError::Expired)
        );
    }

    #[test]
    fn machine_codes_are_stable_hashes() {
        let code = machine_code_from("4c4c4544-0042-3010-8051-b4c04f4e3132");
        assert_eq!(code.len(), 24);
        assert_eq!(
            code,
            machine_code_from(" 4c4c4544-0042-3010-8051-b4c04f4e3132\n")
        );
        assert_ne!(code, machine_code_from("another-machine"));
        assert!(code.split('-').all(|g| g.len() == 4
            && g.bytes()
                .all(|b| b.is_ascii_uppercase() || (b'2'..=b'7').contains(&b))));
        assert!(!code.contains("4c4c4544"));
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    #[test]
    fn the_store_round_trips() {
        let dir = std::env::temp_dir().join(format!("airlock-license-{}", std::process::id()));
        let store = Store::new(&dir);
        assert_eq!(store.load(), None);
        store.save("AIRLOCK1.a.b.c").unwrap();
        assert_eq!(
            store.load().as_deref().map(str::trim),
            Some("AIRLOCK1.a.b.c")
        );
        store.remove().unwrap();
        store.remove().unwrap();
        assert_eq!(store.load(), None);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn today_is_a_calendar_date() {
        let day = today();
        assert_eq!(day.len(), 10);
        assert!(day.as_str() >= "2026-01-01");
        assert!(Keys::from_json("{\"keys\": []}").is_empty());
        assert!(Keys::from_json("not json").is_empty());
    }
}
