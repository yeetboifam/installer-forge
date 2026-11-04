//! Shared installer logic for both stub variants.
//!
//! No payload is baked in. Installer Forge appends a config footer (see
//! `forgefmt`) to a copy of a stub binary; at runtime we read that footer out of
//! our own file, download the application over plain HTTP, verify it, install it,
//! and optionally launch it.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};

use forgefmt::{InstallerConfig, PayloadKind};
use sha2::{Digest, Sha256};

/// Entry point used by both the console and silent binaries.
///
/// `silent` means: no console prompts, install to the default location, and stay
/// quiet (errors are written to a log file next to the temp dir instead of the
/// screen). The console variant passes `false` and interacts with the user.
pub fn run(silent: bool) {
    match install(silent) {
        Ok(_) => {
            if !silent {
                pause();
            }
        }
        Err(e) => {
            if silent {
                report_silent_error(&e);
            } else {
                eprintln!("\n  Installation failed: {e}");
                pause();
            }
            std::process::exit(1);
        }
    }
}

fn install(silent: bool) -> Result<(), String> {
    let cfg = forgefmt::read_self_config().map_err(|e| {
        format!("{e}\n  (this file was not produced by Installer Forge)")
    })?;

    if !silent {
        banner(&cfg);
    }

    let dest_dir = if silent {
        default_install_dir()
    } else {
        prompt_install_dir(&cfg)?
    };
    std::fs::create_dir_all(&dest_dir)
        .map_err(|e| format!("could not create {}: {e}", dest_dir.display()))?;

    let bytes = download(&cfg, silent)?;
    verify(&bytes, &cfg, silent)?;

    let dest = dest_dir.join(&cfg.file_name);
    write_payload(&dest, &bytes, cfg.payload_kind)?;

    if !silent {
        let noun = if cfg.payload_kind.is_data() { "data file" } else { "" };
        if noun.is_empty() {
            println!("\n  Installed {} {} to:", cfg.app_name, cfg.version);
        } else {
            println!("\n  Installed {} {} ({noun}) to:", cfg.app_name, cfg.version);
        }
        println!("    {}", dest.display());
    }

    // Data blobs are not programs, so there is nothing to launch — honour the
    // flag only for executables.
    if cfg.run_after_install && !cfg.payload_kind.is_data() {
        launch(&dest)?;
        if !silent {
            println!("\n  Launched {}.", cfg.app_name);
        }
    }

    if !silent {
        println!("\n  Done.");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Minimal HTTP/1.0 client — plain GET, no TLS, no URL crate.
// ---------------------------------------------------------------------------

fn download(cfg: &InstallerConfig, silent: bool) -> Result<Vec<u8>, String> {
    let (host, port) = parse_authority(&cfg.server_url)?;
    let path = &cfg.download_path;

    if !silent {
        println!("\n  Downloading from {}{} ...", cfg.server_url, path);
    }

    let addr = format!("{host}:{port}");
    let stream = TcpStream::connect(&addr).map_err(|e| format!("connect {addr}: {e}"))?;
    let mut reader = BufReader::new(stream);

    let request = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: forge-installer\r\nConnection: close\r\n\r\n"
    );
    reader
        .get_mut()
        .write_all(request.as_bytes())
        .map_err(|e| format!("send request: {e}"))?;

    // Status line, e.g. "HTTP/1.0 200 OK".
    let mut status = String::new();
    reader
        .read_line(&mut status)
        .map_err(|e| format!("read status: {e}"))?;
    let code = status
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| format!("bad status line: {status:?}"))?;
    if code != 200 {
        return Err(format!("server returned HTTP {code} for {path}"));
    }

    // Headers until a blank line; pull out Content-Length if present.
    let mut content_len: u64 = 0;
    loop {
        let mut line = String::new();
        let n = reader
            .read_line(&mut line)
            .map_err(|e| format!("read header: {e}"))?;
        if n == 0 || line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(v) = header_value(&line, "content-length") {
            content_len = v.trim().parse().unwrap_or(0);
        }
    }
    if content_len == 0 {
        content_len = cfg.payload_len;
    }

    // Body.
    let mut body = Vec::with_capacity(content_len as usize);
    let mut chunk = [0u8; 64 * 1024];
    let mut last_pct = u64::MAX;
    loop {
        let n = reader.read(&mut chunk).map_err(|e| format!("read body: {e}"))?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
        if !silent && content_len > 0 {
            let pct = (body.len() as u64 * 100 / content_len).min(100);
            if pct != last_pct {
                print!("\r  Progress: {pct:>3}%  ({})      ", human_size(body.len() as u64));
                io::stdout().flush().ok();
                last_pct = pct;
            }
        }
    }
    if !silent {
        println!();
    }
    Ok(body)
}

/// Split "http://host:port" into (host, port). Rejects https (no TLS here).
fn parse_authority(server_url: &str) -> Result<(String, u16), String> {
    let rest = server_url
        .strip_prefix("http://")
        .ok_or_else(|| {
            if server_url.starts_with("https://") {
                "this installer is HTTP-only; rebuild the stub with TLS for https servers".to_string()
            } else {
                format!("server URL must start with http:// (got {server_url:?})")
            }
        })?;
    let authority = rest.split('/').next().unwrap_or(rest).trim_end_matches('/');
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse::<u16>().map_err(|_| format!("bad port in {authority:?}"))?;
            Ok((h.to_string(), port))
        }
        None => Ok((authority.to_string(), 80)),
    }
}

fn header_value<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let (k, v) = line.split_once(':')?;
    if k.trim().eq_ignore_ascii_case(name) {
        Some(v.trim_end_matches(['\r', '\n']))
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Install / verify / launch
// ---------------------------------------------------------------------------

fn verify(bytes: &[u8], cfg: &InstallerConfig, silent: bool) -> Result<(), String> {
    if cfg.payload_len != 0 && bytes.len() as u64 != cfg.payload_len {
        return Err(format!(
            "size mismatch: got {} bytes, expected {}",
            bytes.len(),
            cfg.payload_len
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let got = hex(&hasher.finalize());
    if !cfg.sha256.is_empty() && got != cfg.sha256 {
        return Err(format!(
            "checksum mismatch\n    expected {}\n    got      {}",
            cfg.sha256, got
        ));
    }
    if !silent {
        println!("  Verified checksum OK.");
    }
    Ok(())
}

/// Write the downloaded payload to `dest`. Executables get the executable bit
/// (0o755) so they can be run; data blobs are written with ordinary read/write
/// permissions (0o644) and are never marked executable.
fn write_payload(dest: &Path, bytes: &[u8], kind: PayloadKind) -> Result<(), String> {
    std::fs::write(dest, bytes).map_err(|e| format!("write {}: {e}", dest.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(dest)
            .map_err(|e| format!("stat {}: {e}", dest.display()))?
            .permissions();
        perms.set_mode(if kind.is_data() { 0o644 } else { 0o755 });
        std::fs::set_permissions(dest, perms)
            .map_err(|e| format!("chmod {}: {e}", dest.display()))?;
    }
    Ok(())
}

fn launch(dest: &Path) -> Result<(), String> {
    std::process::Command::new(dest)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not launch {}: {e}", dest.display()))
}

// ---------------------------------------------------------------------------
// Console I/O helpers (only used by the interactive variant)
// ---------------------------------------------------------------------------

fn banner(cfg: &InstallerConfig) {
    println!("\n  ==================================================");
    println!("   {} {} — Installer", cfg.app_name, cfg.version);
    println!("  ==================================================");
    println!("   Source : {}", cfg.server_url);
    println!("   Size   : {}", human_size(cfg.payload_len));
    if cfg.payload_kind.is_data() {
        println!("   Type   : data file (installed as-is, not run)");
    }
    if cfg.run_after_install && !cfg.payload_kind.is_data() {
        println!("   Note   : will launch the app after installing");
    }
    println!("  --------------------------------------------------");
}

fn prompt_install_dir(cfg: &InstallerConfig) -> Result<PathBuf, String> {
    let default = default_install_dir();
    print!("\n  Install {} to [{}]: ", cfg.app_name, default.display());
    io::stdout().flush().ok();

    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| format!("read input: {e}"))?;
    let line = line.trim();
    if line.is_empty() {
        Ok(default)
    } else {
        Ok(expand(line))
    }
}

/// A per-user install location that doesn't need admin rights.
fn default_install_dir() -> PathBuf {
    if cfg!(windows) {
        if let Ok(local) = std::env::var("LOCALAPPDATA") {
            return PathBuf::from(local).join("Programs").join("ForgeApps");
        }
    } else if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".local").join("bin");
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

fn expand(input: &str) -> PathBuf {
    if let Some(rest) = input.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    PathBuf::from(input)
}

/// In silent mode there's no console, so leave a breadcrumb on failure.
fn report_silent_error(msg: &str) {
    let mut path = std::env::temp_dir();
    path.push("forge-installer-error.log");
    let _ = std::fs::write(&path, format!("Installer Forge failed:\n{msg}\n"));
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn human_size(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

fn pause() {
    print!("\n  Press Enter to close...");
    io::stdout().flush().ok();
    let mut s = String::new();
    io::stdin().read_line(&mut s).ok();
}
