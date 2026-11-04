//! Shared on-disk format for Installer Forge.
//!
//! A generated installer is just the prebuilt `stub` binary with a small
//! config "footer" appended to its tail:
//!
//! ```text
//! [ ...original stub bytes... ][ config JSON ][ u64 LE json length ][ 16-byte MAGIC ]
//! ```
//!
//! The stub reads its *own* file at runtime, finds the magic at the very end,
//! and recovers the JSON that tells it where to download the payload from.
//! This is the classic self-extracting trick: no compiler needed to stamp out
//! a new installer, just a byte append.

use serde::{Deserialize, Serialize};

/// Marks the end of an installer file. 16 bytes exactly.
pub const MAGIC: &[u8; 16] = b"FORGE-INSTALLER1";

/// What kind of thing the payload is, which decides how the stub installs it.
///
/// `Executable` is the classic case: a program (`.exe`, an ELF, an AppImage)
/// that gets the executable bit set and can be launched after install.
///
/// `Data` is a raw binary blob (`.bin`, a firmware image, a ROM, a disk image,
/// model weights, …) that is *not* itself a program. It is written out verbatim
/// with ordinary file permissions, never marked executable, and never launched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PayloadKind {
    Executable,
    Data,
}

impl Default for PayloadKind {
    fn default() -> Self {
        // Installers produced before this field existed were always executables,
        // so that's the back-compatible default when the field is absent.
        PayloadKind::Executable
    }
}

impl PayloadKind {
    pub fn is_data(self) -> bool {
        matches!(self, PayloadKind::Data)
    }
}

/// Bytes of bookkeeping after the JSON blob: u64 length + magic.
const TRAILER_LEN: usize = 8 + 16;

/// Everything a stub needs to fetch and install its payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallerConfig {
    /// Human-facing name of the application being installed.
    pub app_name: String,
    /// Optional version string, shown to the user.
    pub version: String,
    /// Base URL of the forge's download server, e.g. "http://192.168.1.10:8080".
    pub server_url: String,
    /// Path on the server that serves the payload, e.g. "/download/myapp".
    pub download_path: String,
    /// File name to write the payload as on the target machine, e.g. "myapp".
    pub file_name: String,
    /// Expected size of the payload in bytes (for the progress bar / sanity check).
    pub payload_len: u64,
    /// SHA-256 of the payload, lowercase hex, verified after download.
    pub sha256: String,
    /// Launch the installed executable once the install finishes. Ignored for
    /// `Data` payloads, which are never executed.
    #[serde(default)]
    pub run_after_install: bool,
    /// Whether the payload is a program or a raw data blob. Absent in installers
    /// built before this field existed, where it defaults to `Executable`.
    #[serde(default)]
    pub payload_kind: PayloadKind,
}

/// Build the bytes of a finished installer: the stub, followed by the footer.
pub fn write_installer(stub_bytes: &[u8], config: &InstallerConfig) -> Result<Vec<u8>, String> {
    let json = serde_json::to_vec(config).map_err(|e| format!("serialize config: {e}"))?;
    let mut out = Vec::with_capacity(stub_bytes.len() + json.len() + TRAILER_LEN);
    out.extend_from_slice(stub_bytes);
    out.extend_from_slice(&json);
    out.extend_from_slice(&(json.len() as u64).to_le_bytes());
    out.extend_from_slice(MAGIC);
    Ok(out)
}

/// Recover the config from the tail of a full installer image.
pub fn read_embedded_config(exe_bytes: &[u8]) -> Result<InstallerConfig, String> {
    if exe_bytes.len() < TRAILER_LEN {
        return Err("file too small to contain a config footer".into());
    }
    let magic_at = exe_bytes.len() - 16;
    if &exe_bytes[magic_at..] != MAGIC {
        return Err("no Forge installer footer found (magic missing)".into());
    }
    let len_at = magic_at - 8;
    let mut len_buf = [0u8; 8];
    len_buf.copy_from_slice(&exe_bytes[len_at..magic_at]);
    let json_len = u64::from_le_bytes(len_buf) as usize;

    if json_len > len_at {
        return Err("config length points before start of file".into());
    }
    let json_at = len_at - json_len;
    let json = &exe_bytes[json_at..len_at];
    serde_json::from_slice(json).map_err(|e| format!("parse config: {e}"))
}

/// Read the config embedded in the currently-running executable.
pub fn read_self_config() -> Result<InstallerConfig, String> {
    let path = std::env::current_exe().map_err(|e| format!("locate self: {e}"))?;
    let bytes = std::fs::read(&path).map_err(|e| format!("read self: {e}"))?;
    read_embedded_config(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cfg = InstallerConfig {
            app_name: "Demo".into(),
            version: "1.2.3".into(),
            server_url: "http://localhost:8080".into(),
            download_path: "/download/demo".into(),
            file_name: "demo".into(),
            payload_len: 42,
            sha256: "abc".into(),
            run_after_install: false,
            payload_kind: PayloadKind::Data,
        };
        let fake_stub = b"\x7fELF this is a pretend binary body".to_vec();
        let image = write_installer(&fake_stub, &cfg).unwrap();
        assert!(image.starts_with(&fake_stub));
        let back = read_embedded_config(&image).unwrap();
        assert_eq!(back.app_name, "Demo");
        assert_eq!(back.payload_len, 42);
        assert_eq!(back.payload_kind, PayloadKind::Data);
    }

    #[test]
    fn rejects_plain_binary() {
        assert!(read_embedded_config(b"just some bytes without a footer here!!").is_err());
    }

    #[test]
    fn old_config_without_kind_defaults_to_executable() {
        // A config JSON written before `payload_kind` existed must still parse,
        // and come back as an executable so old installers behave as they did.
        let legacy = br#"{"app_name":"Old","version":"1","server_url":"http://h:80",
            "download_path":"/download/old","file_name":"old","payload_len":1,"sha256":""}"#;
        let cfg: InstallerConfig = serde_json::from_slice(legacy).unwrap();
        assert_eq!(cfg.payload_kind, PayloadKind::Executable);
        assert!(!cfg.payload_kind.is_data());
    }

    #[test]
    fn payload_kind_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&PayloadKind::Data).unwrap(), "\"data\"");
        assert_eq!(
            serde_json::to_string(&PayloadKind::Executable).unwrap(),
            "\"executable\""
        );
    }
}
