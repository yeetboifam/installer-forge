//! Installer Forge — drop an executable in, get a hosted payload and a
//! ready-to-share installer out.

#![cfg_attr(windows, windows_subsystem = "windows")]

mod packager;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui;
use forgefmt::PayloadKind;
use forgeserver::ForgeServer;

use packager::{detect_payload_kind, guess_payload_kind, package, Package, PackageRequest, SNIFF_LEN};

const DEFAULT_PORT: u16 = 8080;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 620.0])
            .with_min_inner_size([560.0, 460.0])
            .with_title("Installer Forge"),
        ..Default::default()
    };
    eframe::run_native(
        "Installer Forge",
        options,
        Box::new(|cc| Box::new(ForgeApp::new(cc))),
    )
}

struct ForgeApp {
    // Config / inputs
    app_name: String,
    version: String,
    /// Host:port baked into installers (the address clients will reach — e.g. a
    /// public/VPN IP:port). Independent of the local bind port below.
    server_host: String,
    /// Local port the download server binds to (e.g. a VPN-forwarded port).
    port: u16,
    port_input: String,
    /// True until the user edits the host field; lets background public-IP
    /// detection fill it in without clobbering a manual entry.
    host_auto: bool,
    /// Receives the detected public IP (once) from a background thread.
    pub_ip_rx: Option<Receiver<Option<String>>>,

    // Paths
    data_dir: PathBuf,
    store_dir: PathBuf,
    out_dir: PathBuf,

    // Which kind of installer to emit, and the stub binaries available to clone.
    target: Target,
    silent: bool,
    run_after_install: bool,
    /// Whether the dropped file is treated as a program or a raw data blob.
    /// Auto-set from the file's extension when one is picked; user-overridable.
    payload_kind: PayloadKind,
    stub_linux: Option<PathBuf>,
    stub_linux_silent: Option<PathBuf>,
    stub_windows: Option<PathBuf>,
    stub_windows_silent: Option<PathBuf>,

    // Runtime
    server: Option<ForgeServer>,
    server_error: Option<String>,
    pending_drop: Option<PathBuf>,
    status: Status,
    packages: Vec<Package>,
    logs: Vec<String>,
}

enum Status {
    Idle,
    Ok(String),
    Error(String),
}

/// The kind of installer the forge produces. Independent of the OS the forge
/// itself runs on — a Linux forge can stamp out a Windows installer by cloning
/// the Windows stub.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Target {
    Linux,
    Windows,
}

impl ForgeApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let data_dir = cwd.join("forge-data");
        let store_dir = data_dir.join("store");
        let out_dir = data_dir.join("installers");

        // Remembered port from a previous run (e.g. your VPN-forwarded port),
        // falling back to the default.
        let port = load_port(&data_dir).unwrap_or(DEFAULT_PORT);

        let (server, server_error) = match ForgeServer::start(store_dir.clone(), "0.0.0.0", port) {
            Ok(s) => (Some(s), None),
            Err(e) => (None, Some(format!("Could not start server on port {port}: {e}"))),
        };

        let ip = forgeserver::local_ip().unwrap_or_else(|| "127.0.0.1".to_string());

        // Detect the public IP off-thread so the window opens instantly. On a
        // full-tunnel VPN this is the exit IP, which is what installers need.
        let (tx, pub_ip_rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(forgeserver::public_ip());
        });

        let stub_linux = find_stub("stub");
        let stub_linux_silent = find_stub("stub-silent");
        let stub_windows = find_stub("stub.exe");
        let stub_windows_silent = find_stub("stub-silent.exe");
        // Default to whatever is available, preferring Windows since that's the
        // common reason to cross-build.
        let target = if stub_windows.is_some() || stub_windows_silent.is_some() {
            Target::Windows
        } else {
            Target::Linux
        };

        Self {
            app_name: String::new(),
            version: "1.0.0".to_string(),
            server_host: format!("{ip}:{port}"),
            port,
            port_input: port.to_string(),
            host_auto: true,
            pub_ip_rx: Some(pub_ip_rx),
            data_dir,
            store_dir,
            out_dir,
            target,
            silent: false,
            run_after_install: false,
            payload_kind: PayloadKind::Executable,
            stub_linux,
            stub_linux_silent,
            stub_windows,
            stub_windows_silent,
            server,
            server_error,
            pending_drop: None,
            status: Status::Idle,
            packages: Vec::new(),
            logs: Vec::new(),
        }
    }

    fn run_package(&mut self) {
        let Some(source) = self.pending_drop.clone() else {
            self.status = Status::Error("No file selected. Drop an executable first.".into());
            return;
        };
        let Some(stub_path) = self.current_stub() else {
            self.status = Status::Error(match (self.target, self.silent) {
                (Target::Windows, _) => "Windows stub not found. Build it with:  \
                     cargo build --release --target x86_64-pc-windows-gnu -p stub"
                    .into(),
                (Target::Linux, _) => {
                    "Linux stub not found. Build it with:  cargo build --release -p stub".into()
                }
            });
            return;
        };
        if self.app_name.trim().is_empty() {
            self.status = Status::Error("Give the app a name first.".into());
            return;
        }

        let req = PackageRequest {
            source_exe: source,
            app_name: self.app_name.trim().to_string(),
            version: self.version.trim().to_string(),
            server_host: self.server_host.trim().to_string(),
            store_dir: self.store_dir.clone(),
            out_dir: self.out_dir.clone(),
            stub_path,
            target_windows: self.target == Target::Windows,
            run_after_install: self.run_after_install,
            payload_kind: self.payload_kind,
        };

        match package(&req) {
            Ok(pkg) => {
                self.status = Status::Ok(format!(
                    "Built installer for {} — hosted and ready to share.",
                    pkg.app_name
                ));
                self.packages.insert(0, pkg);
            }
            Err(e) => self.status = Status::Error(e),
        }
    }

    /// Rebind the download server to the port currently in the port field.
    fn restart_server(&mut self) {
        let port: u16 = match self.port_input.trim().parse() {
            Ok(p) if p > 0 => p,
            _ => {
                self.server_error = Some("Port must be a number 1-65535".into());
                return;
            }
        };
        // Drop the old server first so the port frees up before we rebind.
        self.server = None;
        match ForgeServer::start(self.store_dir.clone(), "0.0.0.0", port) {
            Ok(s) => {
                self.server = Some(s);
                self.server_error = None;
                self.port = port;
                save_port(&self.data_dir, port); // remember it for next launch
                // Keep the host field's port in sync if it looks like host:port.
                if let Some((host, _)) = self.server_host.rsplit_once(':') {
                    self.server_host = format!("{host}:{port}");
                }
            }
            Err(e) => {
                self.server_error = Some(format!("Could not bind port {port}: {e}"));
            }
        }
    }

    fn ingest_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .filter_map(|f| f.path.clone())
                .collect()
        });
        if let Some(path) = dropped.into_iter().next() {
            self.accept_file(path);
        }
    }

    fn accept_file(&mut self, path: PathBuf) {
        if self.app_name.trim().is_empty() {
            if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                self.app_name = stem.to_string();
            }
        }
        // Default the payload type by sniffing the file's actual contents: a
        // real ELF/PE is recognised as a program even if it's named `.bin`, and
        // raw data (firmware, ROMs, shellcode) stays Data. The extension is only
        // a fallback when the bytes can't be read. The user can still override.
        self.payload_kind = match read_header(&path, SNIFF_LEN) {
            Some(header) => detect_payload_kind(&path, &header),
            None => guess_payload_kind(&path),
        };
        self.pending_drop = Some(path);
        self.status = Status::Idle;
    }

    /// The stub binary matching the currently selected target + mode, if present.
    fn current_stub(&self) -> Option<PathBuf> {
        match (self.target, self.silent) {
            (Target::Linux, false) => self.stub_linux.clone(),
            (Target::Linux, true) => self.stub_linux_silent.clone(),
            (Target::Windows, false) => self.stub_windows.clone(),
            (Target::Windows, true) => self.stub_windows_silent.clone(),
        }
    }

    /// Whether a silent stub exists for the currently selected target.
    fn silent_available(&self) -> bool {
        match self.target {
            Target::Linux => self.stub_linux_silent.is_some(),
            Target::Windows => self.stub_windows_silent.is_some(),
        }
    }
}

impl eframe::App for ForgeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ingest_drops(ctx);

        // Background public-IP detection result (one-shot).
        if let Some(rx) = &self.pub_ip_rx {
            if let Ok(result) = rx.try_recv() {
                if let (Some(ip), true) = (result, self.host_auto) {
                    self.server_host = format!("{ip}:{}", self.port);
                }
                self.pub_ip_rx = None;
            }
        }

        if let Some(s) = &self.server {
            let mut new = s.take_logs();
            if !new.is_empty() {
                self.logs.append(&mut new);
                let overflow = self.logs.len().saturating_sub(300);
                if overflow > 0 {
                    self.logs.drain(0..overflow);
                }
            }
        }

        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.heading("🔨  Installer Forge");
            ui.label(
                egui::RichText::new(
                    "Drop an executable or .bin in → it gets hosted and packaged into a shareable installer.",
                )
                .weak(),
            );
            ui.add_space(6.0);
            self.server_status_line(ui);
            self.server_config_line(ui);
            ui.add_space(6.0);
        });

        egui::TopBottomPanel::bottom("log").resizable(true).default_height(150.0).show(ctx, |ui| {
            ui.add_space(4.0);
            ui.label(egui::RichText::new("Server log").strong());
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if self.logs.is_empty() {
                        ui.label(egui::RichText::new("(no requests yet)").weak());
                    }
                    for line in &self.logs {
                        ui.monospace(line);
                    }
                });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            self.drop_zone(ui);
            ui.add_space(10.0);
            self.inputs(ui);
            ui.add_space(8.0);
            self.status_line(ui);
            ui.separator();
            self.package_list(ui, ctx);
        });

        // Keep logs flowing while the window is idle.
        ctx.request_repaint_after(Duration::from_millis(400));
    }
}

impl ForgeApp {
    fn server_status_line(&self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if let Some(err) = &self.server_error {
                ui.colored_label(egui::Color32::from_rgb(220, 90, 90), format!("● {err}"));
            } else {
                ui.colored_label(
                    egui::Color32::from_rgb(90, 190, 120),
                    format!("● Listening on 0.0.0.0:{}", self.port),
                );
            }
            if self.current_stub().is_none() {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 70),
                    "  ⚠ no stub for selected target",
                );
            }
        });
    }

    /// Row for the local bind port and public-address helpers.
    fn server_config_line(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label("Bind port");
            ui.add(
                egui::TextEdit::singleline(&mut self.port_input)
                    .desired_width(70.0)
                    .hint_text("8080"),
            );
            if ui.button("Restart server").clicked() {
                self.restart_server();
            }
            ui.separator();
            if ui
                .button("Detect public IP")
                .on_hover_text("Looks up the IP the internet sees (VPN exit IP if a VPN is up)")
                .clicked()
            {
                match forgeserver::public_ip() {
                    Some(ip) => {
                        self.server_host = format!("{ip}:{}", self.port);
                        self.status =
                            Status::Ok(format!("Public IP {ip} — set as installer host."));
                    }
                    None => {
                        self.status =
                            Status::Error("Could not detect public IP (no internet?)".into());
                    }
                }
            }
        });
    }

    fn drop_zone(&mut self, ui: &mut egui::Ui) {
        let desired = egui::vec2(ui.available_width(), 120.0);
        let (rect, _resp) = ui.allocate_exact_size(desired, egui::Sense::hover());
        let visuals = ui.visuals();
        ui.painter().rect(
            rect,
            egui::Rounding::same(10.0),
            visuals.extreme_bg_color,
            egui::Stroke::new(1.5_f32, visuals.widgets.inactive.fg_stroke.color),
        );
        let text = match &self.pending_drop {
            Some(p) => format!("Selected:  {}", p.display()),
            None => "⬇  Drop an executable or .bin anywhere in this window".to_string(),
        };
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            text,
            egui::FontId::proportional(16.0),
            visuals.text_color(),
        );
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            if ui.button("Browse…").clicked() {
                if let Some(path) = rfd::FileDialog::new().pick_file() {
                    self.accept_file(path);
                }
            }
            if self.pending_drop.is_some() && ui.button("Clear").clicked() {
                self.pending_drop = None;
            }
        });
    }

    fn inputs(&mut self, ui: &mut egui::Ui) {
        egui::Grid::new("inputs")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .show(ui, |ui| {
                ui.label("App name");
                ui.add(egui::TextEdit::singleline(&mut self.app_name).desired_width(f32::INFINITY));
                ui.end_row();

                ui.label("Version");
                ui.add(egui::TextEdit::singleline(&mut self.version).desired_width(f32::INFINITY));
                ui.end_row();

                ui.label("Server host");
                let host_resp = ui.add(
                    egui::TextEdit::singleline(&mut self.server_host)
                        .hint_text("public ip:port baked into the installer")
                        .desired_width(f32::INFINITY),
                );
                if host_resp.changed() {
                    // User took over; stop auto-filling from detection.
                    self.host_auto = false;
                }
                ui.end_row();

                ui.label("Payload type");
                ui.horizontal(|ui| {
                    ui.radio_value(
                        &mut self.payload_kind,
                        PayloadKind::Executable,
                        "Executable (run it)",
                    )
                    .on_hover_text("A program — installed with the executable bit, can be launched");
                    ui.radio_value(&mut self.payload_kind, PayloadKind::Data, "Data file (.bin, raw)")
                        .on_hover_text(
                            "A raw binary blob (firmware, ROM, disk image, …) — installed \
                             as-is, never marked executable or launched",
                        );
                });
                ui.end_row();

                ui.label("Installer target");
                ui.horizontal(|ui| {
                    let win_ok = self.stub_windows.is_some();
                    let lin_ok = self.stub_linux.is_some();
                    ui.add_enabled_ui(win_ok, |ui| {
                        ui.radio_value(&mut self.target, Target::Windows, "Windows (.exe)");
                    });
                    ui.add_enabled_ui(lin_ok, |ui| {
                        ui.radio_value(&mut self.target, Target::Linux, "Linux (ELF)");
                    });
                    if !win_ok {
                        ui.weak("(build stub.exe for Windows)");
                    }
                });
                ui.end_row();

                ui.label("Options");
                ui.vertical(|ui| {
                    let silent_ok = self.silent_available();
                    ui.add_enabled_ui(silent_ok, |ui| {
                        ui.checkbox(
                            &mut self.silent,
                            "Silent install (no console window, uses default folder)",
                        );
                    });
                    if !silent_ok {
                        self.silent = false;
                        ui.weak("  silent stub not built for this target (build stub-silent)");
                    }
                    // Data blobs are never executed, so launching makes no sense.
                    let is_data = self.payload_kind.is_data();
                    if is_data {
                        self.run_after_install = false;
                    }
                    ui.add_enabled_ui(!is_data, |ui| {
                        ui.checkbox(
                            &mut self.run_after_install,
                            "Run the app automatically after installing",
                        );
                    });
                    if is_data {
                        ui.weak("  (data files are installed as-is, never run)");
                    }
                });
                ui.end_row();
            });

        ui.add_space(8.0);
        let ready = self.pending_drop.is_some() && self.current_stub().is_some();
        if ui
            .add_enabled(
                ready,
                egui::Button::new(egui::RichText::new("⚙  Forge installer").size(16.0)),
            )
            .clicked()
        {
            self.run_package();
        }
    }

    fn status_line(&self, ui: &mut egui::Ui) {
        match &self.status {
            Status::Idle => {}
            Status::Ok(msg) => {
                ui.colored_label(egui::Color32::from_rgb(90, 190, 120), format!("✔ {msg}"));
            }
            Status::Error(msg) => {
                ui.colored_label(egui::Color32::from_rgb(220, 90, 90), format!("✖ {msg}"));
            }
        }
    }

    fn package_list(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label(egui::RichText::new("Forged installers").strong());
        if self.packages.is_empty() {
            ui.label(egui::RichText::new("Nothing forged yet.").weak());
            return;
        }
        egui::ScrollArea::vertical()
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for pkg in &self.packages {
                    egui::Frame::group(ui.style()).show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.strong(&pkg.app_name);
                            ui.weak(human_size(pkg.size));
                            if pkg.payload_kind.is_data() {
                                ui.weak("· data");
                            }
                        });
                        ui.horizontal(|ui| {
                            ui.monospace(&pkg.download_url);
                            if ui.small_button("copy url").clicked() {
                                ctx.output_mut(|o| o.copied_text = pkg.download_url.clone());
                            }
                        });
                        ui.horizontal(|ui| {
                            let p = pkg.installer_path.display().to_string();
                            ui.monospace(&p);
                            if ui.small_button("copy path").clicked() {
                                ctx.output_mut(|o| o.copied_text = p.clone());
                            }
                            if ui.small_button("open folder").clicked() {
                                if let Some(dir) = pkg.installer_path.parent() {
                                    let _ = open_in_file_manager(dir);
                                }
                            }
                        });
                    });
                    ui.add_space(4.0);
                }
            });
    }
}

/// Read up to `max` leading bytes of a file, for magic-byte sniffing. Returns
/// `None` if the file can't be opened/read at all, so the caller can fall back
/// to classifying by extension.
fn read_header(path: &std::path::Path, max: usize) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; max];
    let n = f.read(&mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Path of the little settings file that remembers the chosen port.
fn config_path(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("forge.cfg")
}

/// Read the remembered bind port, if a config file exists.
fn load_port(data_dir: &std::path::Path) -> Option<u16> {
    let text = std::fs::read_to_string(config_path(data_dir)).ok()?;
    for line in text.lines() {
        if let Some(v) = line.trim().strip_prefix("port=") {
            if let Ok(p) = v.trim().parse::<u16>() {
                if p > 0 {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Persist the chosen bind port so the next launch starts on it.
fn save_port(data_dir: &std::path::Path, port: u16) {
    let _ = std::fs::create_dir_all(data_dir);
    let _ = std::fs::write(config_path(data_dir), format!("port={port}\n"));
}

/// Locate a prebuilt stub binary (`stub` or `stub.exe`) by searching next to the
/// forge executable and across the usual cargo output directories — including the
/// Windows cross-compile target, so a Linux forge can find the Windows stub.
fn find_stub(file_name: &str) -> Option<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            dirs.push(dir.to_path_buf());
            if let Some(target) = dir.parent() {
                dirs.push(target.join("release"));
                dirs.push(target.join("debug"));
            }
        }
    }

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for base in [&cwd, &cwd.join("installer-forge")] {
        dirs.push(base.join("target/release"));
        dirs.push(base.join("target/debug"));
        dirs.push(base.join("target/x86_64-pc-windows-gnu/release"));
        dirs.push(base.join("target/x86_64-pc-windows-gnu/debug"));
        dirs.push(base.join("dist-windows"));
    }

    dirs.into_iter()
        .map(|d| d.join(file_name))
        .find(|p| p.is_file())
}

fn open_in_file_manager(dir: &std::path::Path) -> std::io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(dir).spawn()?;
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(dir).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("explorer").arg(dir).spawn()?;
    }
    Ok(())
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

#[cfg(test)]
mod config_tests {
    use super::{load_port, save_port};

    #[test]
    fn port_round_trips() {
        let dir = std::env::temp_dir().join(format!("forge-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_port(&dir), None); // nothing saved yet
        save_port(&dir, 57065);
        assert_eq!(load_port(&dir), Some(57065));
        save_port(&dir, 8080);
        assert_eq!(load_port(&dir), Some(8080));
        std::fs::remove_dir_all(&dir).ok();
    }
}
