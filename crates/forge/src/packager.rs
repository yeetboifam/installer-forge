//! Turning a dropped executable into (a) a hosted payload and (b) an installer.

use std::fs;
use std::path::{Path, PathBuf};

use forgefmt::{InstallerConfig, PayloadKind};
use sha2::{Digest, Sha256};

/// Result of packaging one application.
pub struct Package {
    pub app_name: String,
    pub installer_path: PathBuf,
    pub download_url: String,
    pub size: u64,
    pub payload_kind: PayloadKind,
}

/// Inputs gathered from the UI for one packaging run.
pub struct PackageRequest {
    /// The executable the user dropped in.
    pub source_exe: PathBuf,
    pub app_name: String,
    pub version: String,
    /// Host (and optional port) used in the URL baked into the installer,
    /// e.g. "192.168.1.10:8080".
    pub server_host: String,
    /// Directory the server serves files from.
    pub store_dir: PathBuf,
    /// Directory generated installers are written to.
    pub out_dir: PathBuf,
    /// The prebuilt stub binary to clone for the installer.
    pub stub_path: PathBuf,
    /// Whether the output installer is a Windows `.exe` (vs. a Linux ELF).
    pub target_windows: bool,
    /// Launch the app on the target machine once installed. Forced off for data
    /// payloads, which are never executed.
    pub run_after_install: bool,
    /// Whether the dropped file is a program or a raw data blob (`.bin`, etc.).
    pub payload_kind: PayloadKind,
}

pub fn package(req: &PackageRequest) -> Result<Package, String> {
    let payload = fs::read(&req.source_exe)
        .map_err(|e| format!("read {}: {e}", req.source_exe.display()))?;
    if payload.is_empty() {
        return Err("the dropped file is empty".into());
    }

    let stub = fs::read(&req.stub_path).map_err(|e| {
        format!(
            "could not read the installer stub at {}: {e}\n\
             (build it first with: cargo build --release -p stub)",
            req.stub_path.display()
        )
    })?;
    if forgefmt::read_embedded_config(&stub).is_ok() {
        return Err("the stub already has a config footer; use the fresh build output".into());
    }

    // Keep the original file's extension (e.g. ".exe") — Windows needs it to run
    // the file. `base` names the installer; `payload_name` is what gets served and
    // written on the target machine.
    let base = sanitize(&req.app_name);
    let payload_name = match payload_extension(&req.source_exe) {
        Some(ext) => format!("{base}.{ext}"),
        None => base.clone(),
    };
    let server_url = format!("http://{}", req.server_host.trim_end_matches('/'));
    let download_path = format!("/download/{payload_name}");

    // Publish the payload into the server's store directory.
    fs::create_dir_all(&req.store_dir)
        .map_err(|e| format!("create store dir: {e}"))?;
    let stored = req.store_dir.join(&payload_name);
    fs::write(&stored, &payload)
        .map_err(|e| format!("write payload to store: {e}"))?;

    let sha = sha256_hex(&payload);

    let config = InstallerConfig {
        app_name: req.app_name.clone(),
        version: req.version.clone(),
        server_url: server_url.clone(),
        download_path: download_path.clone(),
        file_name: payload_name.clone(),
        payload_len: payload.len() as u64,
        sha256: sha,
        // A data blob is never executed, so "run after install" can't apply.
        run_after_install: req.run_after_install && !req.payload_kind.is_data(),
        payload_kind: req.payload_kind,
    };

    let image = forgefmt::write_installer(&stub, &config)?;

    fs::create_dir_all(&req.out_dir).map_err(|e| format!("create out dir: {e}"))?;
    let installer_path = req
        .out_dir
        .join(installer_file_name(&base, req.target_windows));
    fs::write(&installer_path, &image)
        .map_err(|e| format!("write installer: {e}"))?;
    make_executable(&installer_path)?;

    Ok(Package {
        app_name: req.app_name.clone(),
        installer_path,
        download_url: format!("{server_url}{download_path}"),
        size: payload.len() as u64,
        payload_kind: config.payload_kind,
    })
}

/// Best guess at whether a dropped file is a program or a raw data blob, from
/// its extension alone. Used only as the *default* the UI shows when a file is
/// picked — the user can always override it before forging.
///
/// Known executable formats map to `Executable`; `.bin` and other raw-image
/// extensions map to `Data`. Anything unrecognised stays `Executable`, which is
/// the historical behaviour (e.g. an extension-less ELF).
pub fn guess_payload_kind(path: &Path) -> PayloadKind {
    match payload_extension(path).as_deref() {
        // Raw blobs and signed binary blobs (`.sgn`, and the `.bin.sgn` pair) are
        // data: written out verbatim, never marked executable, never launched.
        Some(
            "bin" | "dat" | "img" | "rom" | "iso" | "fw" | "pak" | "raw" | "blob" | "sgn"
            | "bin.sgn",
        ) => PayloadKind::Data,
        _ => PayloadKind::Executable,
    }
}

/// How many leading bytes are enough to recognise any of the executable
/// formats below. The PE check needs to reach the PE-header pointer at 0x3C
/// plus the signature it points at, which for real binaries sits well within
/// 1 KiB; 1 KiB also comfortably covers ELF/Mach-O/shebang magics.
pub const SNIFF_LEN: usize = 1024;

/// Does `header` (the first [`SNIFF_LEN`] or so bytes of a file) begin with a
/// format the OS can actually load and run?
///
/// Recognises:
///   * **ELF** — Linux/Unix binaries, AppImages (`\x7fELF`)
///   * **PE**  — Windows `.exe`/`.dll` (`MZ` … `PE\0\0`)
///   * **Mach-O** — macOS binaries (feedface / feedfacf, either endianness)
///   * **`#!` scripts** — interpreter scripts
///
/// Everything else — firmware, ROMs, disk images, model weights, raw shellcode
/// — has no such header and is *not* an executable file: it needs a loader to
/// run, which this tool deliberately does not provide. So it is treated as data.
pub fn looks_executable(header: &[u8]) -> bool {
    // ELF.
    if header.starts_with(&[0x7f, b'E', b'L', b'F']) {
        return true;
    }
    // Interpreter script.
    if header.starts_with(b"#!") {
        return true;
    }
    // Mach-O thin images, 32/64-bit, both byte orders.
    if header.len() >= 4 {
        const MACHO: [[u8; 4]; 4] = [
            [0xFE, 0xED, 0xFA, 0xCE],
            [0xCE, 0xFA, 0xED, 0xFE],
            [0xFE, 0xED, 0xFA, 0xCF],
            [0xCF, 0xFA, 0xED, 0xFE],
        ];
        if MACHO.iter().any(|m| &header[..4] == m) {
            return true;
        }
    }
    // PE: "MZ" at the start, then a "PE\0\0" signature at the offset stored at
    // 0x3C. If we can read that pointer, require the real signature so arbitrary
    // data that merely starts with "MZ" isn't misread as a program.
    if header.starts_with(b"MZ") {
        if header.len() >= 0x40 {
            let off = u32::from_le_bytes([
                header[0x3c],
                header[0x3d],
                header[0x3e],
                header[0x3f],
            ]) as usize;
            if off.saturating_add(4) <= header.len() {
                return &header[off..off + 4] == b"PE\0\0";
            }
        }
        // Too short to see the PE header here; the MZ magic alone is a fair hint.
        return true;
    }
    false
}

/// Classify a payload by its actual contents, falling back to the extension.
///
/// Content wins because it is reliable: a genuine ELF/PE named `foo.bin` is
/// correctly seen as a program, and a raw blob named `foo.exe` is correctly seen
/// as data. The extension guess is used only when no bytes could be read.
pub fn detect_payload_kind(path: &Path, header: &[u8]) -> PayloadKind {
    if looks_executable(header) {
        PayloadKind::Executable
    } else if header.is_empty() {
        guess_payload_kind(path)
    } else {
        PayloadKind::Data
    }
}

/// Multi-part extensions that must be kept whole. A signed binary blob is
/// `name.bin.sgn`: the `.bin` says it's a raw image and the `.sgn` is its
/// detached signature, so both halves have to travel with the file and the
/// `.bin` must not be dropped. Checked before the single-extension path.
const COMPOUND_EXTENSIONS: &[&str] = &["bin.sgn"];

/// The extension used to name the stored/installed payload. Like
/// [`original_extension`] but recognises known compound extensions (e.g.
/// `.bin.sgn`) and returns them whole, so a signed blob keeps its full
/// `name.bin.sgn` form on the target machine.
fn payload_extension(path: &Path) -> Option<String> {
    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_ascii_lowercase();
        for compound in COMPOUND_EXTENSIONS {
            if lower.ends_with(&format!(".{compound}")) {
                return Some((*compound).to_string());
            }
        }
    }
    original_extension(path)
}

/// The dropped file's extension, lowercased and sanitized to safe chars, if any.
fn original_extension(path: &Path) -> Option<String> {
    let ext = path.extension()?.to_str()?.to_ascii_lowercase();
    let clean: String = ext.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    if clean.is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn installer_file_name(base: &str, windows: bool) -> String {
    if windows {
        format!("{base}-installer.exe")
    } else {
        format!("{base}-installer")
    }
}

/// Reduce an app name to a safe, single-segment file name.
fn sanitize(name: &str) -> String {
    let mut out: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect();
    while out.contains("--") {
        out = out.replace("--", "-");
    }
    let out = out.trim_matches(['-', '.'].as_ref()).to_string();
    if out.is_empty() {
        "app".to_string()
    } else {
        out
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn make_executable(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .map_err(|e| format!("stat installer: {e}"))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).map_err(|e| format!("chmod installer: {e}"))?;
    }
    let _ = path;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn keeps_exe_extension() {
        assert_eq!(original_extension(&PathBuf::from("/x/Aaa.exe")).as_deref(), Some("exe"));
        assert_eq!(original_extension(&PathBuf::from("/x/App.AppImage")).as_deref(), Some("appimage"));
        assert_eq!(original_extension(&PathBuf::from("/x/binary")), None);
    }

    #[test]
    fn payload_name_has_extension() {
        let base = sanitize("Aaa");
        let name = format!("{base}.{}", original_extension(&PathBuf::from("Aaa.exe")).unwrap());
        assert_eq!(name, "aaa.exe");
    }

    #[test]
    fn bin_and_raw_images_guess_as_data() {
        for p in ["/x/firmware.bin", "/x/disk.img", "/x/game.rom", "/x/BLOB.DAT"] {
            assert_eq!(guess_payload_kind(&PathBuf::from(p)), PayloadKind::Data, "{p}");
        }
    }

    #[test]
    fn signed_blobs_guess_as_data() {
        for p in ["/x/firmware.bin.sgn", "/x/update.sgn", "/x/IMAGE.BIN.SGN"] {
            assert_eq!(guess_payload_kind(&PathBuf::from(p)), PayloadKind::Data, "{p}");
        }
    }

    #[test]
    fn compound_extension_is_kept_whole() {
        // A signed blob must keep both halves: name.bin.sgn, not name.sgn.
        assert_eq!(
            payload_extension(&PathBuf::from("/x/Firmware.bin.sgn")).as_deref(),
            Some("bin.sgn")
        );
        // A bare .sgn still works and is preserved.
        assert_eq!(
            payload_extension(&PathBuf::from("/x/update.SGN")).as_deref(),
            Some("sgn")
        );
    }

    #[test]
    fn sniffs_real_executable_formats() {
        // ELF.
        assert!(looks_executable(b"\x7fELF\x02\x01\x01"));
        // Shebang script.
        assert!(looks_executable(b"#!/bin/sh\n"));
        // Mach-O 64-bit.
        assert!(looks_executable(&[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0]));
        // PE: MZ header with a PE signature at the 0x3C pointer.
        let mut pe = vec![0u8; 0x100];
        pe[0] = b'M';
        pe[1] = b'Z';
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert!(looks_executable(&pe));
    }

    #[test]
    fn raw_data_and_bare_mz_are_not_executable() {
        // Firmware/ROM-ish bytes: no program header.
        assert!(!looks_executable(&[0x00, 0x01, 0x02, 0x03, 0xff, 0xee]));
        // Starts with "MZ" but has no valid PE signature at the pointer: data.
        let mut fake = vec![0u8; 0x100];
        fake[0] = b'M';
        fake[1] = b'Z';
        fake[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        // 0x80.. left as zeroes — not "PE\0\0".
        assert!(!looks_executable(&fake));
    }

    #[test]
    fn detect_prefers_content_then_extension() {
        // A real ELF named `.bin` is a program, extension notwithstanding.
        assert_eq!(
            detect_payload_kind(&PathBuf::from("/x/firmware.bin"), b"\x7fELF\x02"),
            PayloadKind::Executable
        );
        // Raw bytes named `.exe` are still just data.
        assert_eq!(
            detect_payload_kind(&PathBuf::from("/x/thing.exe"), &[0, 1, 2, 3]),
            PayloadKind::Data
        );
        // No bytes readable → fall back to the extension guess.
        assert_eq!(
            detect_payload_kind(&PathBuf::from("/x/app.exe"), &[]),
            PayloadKind::Executable
        );
    }

    #[test]
    fn programs_and_unknowns_guess_as_executable() {
        for p in ["/x/app.exe", "/x/App.AppImage", "/x/tool", "/x/weird.xyz"] {
            assert_eq!(
                guess_payload_kind(&PathBuf::from(p)),
                PayloadKind::Executable,
                "{p}"
            );
        }
    }

    #[test]
    fn packaging_a_bin_marks_it_data_and_disables_launch() {
        let tmp = std::env::temp_dir().join(format!("forge-pkg-{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        // A footer-less "stub" to clone, and a .bin payload to package.
        let stub_path = tmp.join("stub");
        fs::write(&stub_path, b"\x7fELF pretend stub body").unwrap();
        let src = tmp.join("firmware.bin");
        fs::write(&src, b"\x00\x01\x02 raw blob").unwrap();

        let req = PackageRequest {
            source_exe: src.clone(),
            app_name: "Firmware".into(),
            version: "1.0.0".into(),
            server_host: "127.0.0.1:8080".into(),
            store_dir: tmp.join("store"),
            out_dir: tmp.join("out"),
            stub_path,
            target_windows: false,
            // Even though the user asked to run it, a data blob must never launch.
            run_after_install: true,
            payload_kind: guess_payload_kind(&src),
        };

        let pkg = package(&req).unwrap();
        assert_eq!(pkg.payload_kind, PayloadKind::Data);

        // The config baked into the installer must say "data" and launch=false.
        let image = fs::read(&pkg.installer_path).unwrap();
        let cfg = forgefmt::read_embedded_config(&image).unwrap();
        assert_eq!(cfg.payload_kind, PayloadKind::Data);
        assert!(!cfg.run_after_install);
        assert_eq!(cfg.file_name, "firmware.bin");

        fs::remove_dir_all(&tmp).ok();
    }
}
