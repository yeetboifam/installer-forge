//! The download server that hosts packaged payloads over HTTP.
//!
//! Serves any file that lives directly in the store directory at
//! `GET /download/<name>`, plus a small `GET /` index. Used two ways:
//! - [`ForgeServer::start`] runs it in background threads (the GUI uses this).
//! - [`serve_blocking`] runs it in the foreground, logging to stdout (the
//!   headless `serve` binary uses this — handy on a VPS over SSH).
//!
//! Files are streamed from disk (not buffered into memory), so it stays light on
//! a weak box, and a small pool of worker threads means one slow download won't
//! block everyone else.

use std::fs;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use tiny_http::{Header, Response, Server};

/// Collected log lines, drained by the UI (or printed, in the CLI).
pub type Log = Arc<Mutex<Vec<String>>>;

const WORKERS: usize = 4;

pub struct ForgeServer {
    pub bind: String,
    pub port: u16,
    pub log: Log,
}

impl ForgeServer {
    /// Bind and start serving in background worker threads.
    pub fn start(store_dir: PathBuf, bind: &str, port: u16) -> io::Result<Self> {
        fs::create_dir_all(&store_dir)?;
        let server = Server::http((bind, port))
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        let server = Arc::new(server);

        let log: Log = Arc::new(Mutex::new(Vec::new()));
        push(&log, format!("Server listening on {bind}:{port}"));

        for _ in 0..WORKERS {
            let server = server.clone();
            let store = store_dir.clone();
            let log = log.clone();
            thread::spawn(move || loop {
                match server.recv() {
                    Ok(request) => {
                        push(&log, format!("{} {}", request.method(), request.url()));
                        handle(request, &store, &log);
                    }
                    Err(_) => break,
                }
            });
        }

        Ok(Self {
            bind: bind.to_string(),
            port,
            log,
        })
    }

    /// Drain the pending log lines for display.
    pub fn take_logs(&self) -> Vec<String> {
        let mut guard = self.log.lock().unwrap();
        std::mem::take(&mut *guard)
    }
}

/// Run the server in the foreground, echoing its log to stdout. Never returns
/// under normal operation (Ctrl-C to stop).
pub fn serve_blocking(store_dir: PathBuf, bind: &str, port: u16) -> io::Result<()> {
    let server = ForgeServer::start(store_dir, bind, port)?;
    loop {
        for line in server.take_logs() {
            println!("{line}");
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn handle(request: tiny_http::Request, store: &Path, log: &Log) {
    let url = request.url().to_string();

    if url == "/" || url == "/index.html" {
        let body = index_page(store);
        let header = Header::from_bytes(b"Content-Type", b"text/html; charset=utf-8").unwrap();
        let _ = request.respond(Response::from_string(body).with_header(header));
        return;
    }

    if let Some(name) = url.strip_prefix("/download/") {
        let name = name.split('?').next().unwrap_or(name);
        match safe_path(store, name) {
            Some(path) if path.is_file() => match fs::File::open(&path) {
                // Stream from disk — content-length is taken from the file size.
                Ok(file) => {
                    let ct =
                        Header::from_bytes(b"Content-Type", b"application/octet-stream").unwrap();
                    let resp = Response::from_file(file)
                        .with_header(ct)
                        .with_header(content_disposition(name));
                    let _ = request.respond(resp);
                }
                Err(e) => {
                    push(log, format!("ERROR opening {}: {e}", path.display()));
                    let _ = request
                        .respond(Response::from_string("read error").with_status_code(500));
                }
            },
            _ => {
                let _ = request.respond(Response::from_string("not found").with_status_code(404));
            }
        }
        return;
    }

    let _ = request.respond(Response::from_string("not found").with_status_code(404));
}

/// Resolve `<store>/<name>` only if `name` is a plain file name (no traversal).
fn safe_path(store: &Path, name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') || name.contains('\\') || name.contains("..") {
        return None;
    }
    Some(store.join(name))
}

fn content_disposition(name: &str) -> Header {
    let value = format!("attachment; filename=\"{name}\"");
    Header::from_bytes(b"Content-Disposition", value.as_bytes())
        .unwrap_or_else(|_| Header::from_bytes(b"X-Name", b"file").unwrap())
}

fn index_page(store: &Path) -> String {
    let mut rows = String::new();
    if let Ok(entries) = fs::read_dir(store) {
        for e in entries.flatten() {
            if e.path().is_file() {
                let name = e.file_name().to_string_lossy().to_string();
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                rows.push_str(&format!(
                    "<li><a href=\"/download/{name}\">{name}</a> — {size} bytes</li>"
                ));
            }
        }
    }
    if rows.is_empty() {
        rows.push_str("<li><em>no payloads published yet</em></li>");
    }
    format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Installer Forge</title></head>\
         <body style=\"font-family:sans-serif;max-width:640px;margin:3rem auto\">\
         <h1>Installer Forge — download server</h1><ul>{rows}</ul></body></html>"
    )
}

fn push(log: &Log, line: String) {
    if let Ok(mut g) = log.lock() {
        g.push(line);
    }
}

/// Best-effort discovery of this machine's outbound-interface IP (LAN, or the
/// VPN tunnel IP when a full-tunnel VPN is up). No packets are actually sent.
pub fn local_ip() -> Option<String> {
    use std::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

/// Best-effort discovery of the *public* IP as seen from the internet, via a
/// plain-HTTP lookup service. With a full-tunnel VPN up, this returns the VPN
/// exit IP — the address installers should point at. Returns None on any error.
pub fn public_ip() -> Option<String> {
    http_get_text("api.ipify.org", 80, "/")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty() && s.len() < 64)
}

fn http_get_text(host: &str, port: u16, path: &str) -> io::Result<String> {
    use std::io::{Read, Write};
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no address"))?;
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: forge\r\n\r\n"
    );
    stream.write_all(req.as_bytes())?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf)?;
    // Body is everything after the blank line.
    let body = buf
        .split_once("\r\n\r\n")
        .map(|(_, b)| b)
        .unwrap_or("")
        .to_string();
    Ok(body)
}
