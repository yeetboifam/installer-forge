# Installer Forge

Drop an executable into a native GUI → it gets **hosted on a built-in download
server** and packaged into a **new standalone installer** you can hand to anyone.
When they run that installer it pulls your app down from the server and installs
it into a folder they choose.

This is the "web installer" / "stub installer" pattern used by lots of real apps
(e.g. the small Chrome setup that downloads the rest): the installer you ship is
tiny and the actual payload lives on your server.

```
  your app.exe  ──drop──▶  [ Installer Forge ]  ──▶  yourapp-installer   (share this)
                                   │                        │
                                   ▼                        ▼
                          hosts payload at          on the target machine:
                          http://host:8080/...      downloads + verifies + installs
```

## Layout

| Crate        | What it is                                                              |
|--------------|------------------------------------------------------------------------|
| `forge`       | The GUI builder (egui). Drop zone, download server, installer output.  |
| `stub`        | The installer template. Every generated installer is a copy of this.   |
| `forgefmt`    | Shared code: the config "footer" format appended to each installer.    |
| `forgeserver` | The download server (lib) + a headless `serve` binary for VPS/VPN use. |

### How an installer is made (no compiler needed per build)

The `stub` binary is built **once**. To produce an installer, the forge copies the
stub and appends a footer to its tail:

```
[ ...stub binary... ][ config JSON ][ u64 length ][ 16-byte magic ]
```

At runtime the stub reads its **own** file, finds the magic at the end, recovers
the JSON (server URL, app name, size, SHA-256), downloads the payload, verifies
it, and installs it.

## Build

Needs the Rust toolchain. On a Debian/Ubuntu/Pop!_OS box you also need a few dev
libraries for the GUI:

```bash
sudo apt install -y libxkbcommon-dev libwayland-dev libgl1-mesa-dev \
                    libxcb1-dev libxkbcommon-x11-dev
```

Then:

```bash
# 1. Build the installer stubs first — the forge clones these for every installer.
#    This builds BOTH variants: `stub` (interactive console) and
#    `stub-silent` (no console window, installs silently).
cargo build --release -p stub

# 1b. (optional) Build Windows stubs from Linux, so the forge can emit .exe
#     installers. Needs mingw-w64:  sudo apt install mingw-w64
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p stub

# 2. Run the GUI builder.
cargo run --release -p forge
```

### Options in the GUI

- **Installer target** — emit a Windows `.exe` or a Linux ELF installer,
  regardless of which OS the forge runs on.
- **Silent install** — clones the no-console stub: no prompts, installs to the
  default per-user folder, no terminal window. (Errors are written to
  `forge-installer-error.log` in the temp dir.)
- **Run after install** — launches the app automatically once it's installed.
- **Payload type** — choose whether the dropped file is an **Executable** (a
  program: gets the executable bit, can be launched) or a **Data file** (a raw
  `.bin` blob — firmware, ROM, disk image, data — installed verbatim, never
  marked executable and never run). It's auto-detected from the extension when
  you drop a file (`.bin`, `.img`, `.rom`, `.iso`, … default to Data) and you
  can override it before forging. Picking Data also disables "Run after install".

Run the tests for the on-disk format:

```bash
cargo test -p forgefmt
```

## Using it

1. Launch `forge`. The status bar shows the download server URL (your LAN IP +
   port 8080).
2. Drop an executable or a `.bin`/data file onto the window (or **Browse…**).
3. Set the app name / version. The **Server host** field is the `ip:port` baked
   into the installer — set it to an address the target machine can actually
   reach.
4. Click **Forge installer**. You get:
   - the payload published at `http://<host>:8080/download/<name>`
   - a new installer at `forge-data/installers/<name>-installer`
5. Share the installer. Running it downloads + installs your app.

Generated files live under `forge-data/` next to where you launched the forge.

## Hosting publicly: headless server, VPS, and VPN port-forwarding

The GUI needs a desktop, so on a **headless VPS (SSH only)** run the standalone
server instead:

```bash
cargo build --release -p forgeserver        # builds the `serve` binary (~485 KB)

# serve payloads on a port (point installers at <public-ip>:<port>)
./target/release/serve --dir forge-data/store --port 57065

# keep it running after you log out
nohup ./target/release/serve --dir forge-data/store --port 57065 >serve.log 2>&1 &

# print the public IP (the VPN exit IP, if a VPN is up)
./target/release/serve --public-ip
```

It streams files from disk (low memory) and uses a small worker pool, so it's
happy next to other services on a weak box. To host apps there, copy the payload
files into the VPS's `forge-data/store/` (e.g. `scp`), and build the installers
locally with the GUI using the VPS's public IP as the **Server host**.

> Portability: a binary built on a newer glibc may not run on an older VPS. Build
> `serve` *on* the VPS, or make a fully static one:
> `rustup target add x86_64-unknown-linux-musl && cargo build --release --target x86_64-unknown-linux-musl -p forgeserver`

### AirVPN (WireGuard) port-forwarding → public downloads

If you don't have a public IP, AirVPN's port-forwarding gives you one. Say AirVPN
forwards port **57065** to your machine:

1. **Connect the VPN** (WireGuard): `wg-quick up airvpn` (or your toggle script).
2. **Listen on the forwarded port.** Either set the GUI's **Bind port** to `57065`
   and click *Restart server*, or run `serve --dir forge-data/store --port 57065`.
3. **Find your public address.** Click **Detect public IP** in the GUI, or run
   `serve --public-ip` — with the tunnel up this returns the **AirVPN exit IP**.
4. **Point installers at it.** Set **Server host** to `<exit-ip>:57065` and forge.
   Installers now download over the internet via the VPN.

Notes:
- If AirVPN maps an *external* port to a *different local* port, bind the **local**
  port and put the **external** port in the Server host field.
- The server must stay running and the VPN connected while people download.
- AirVPN WireGuard is usually full-tunnel (all traffic via VPN) — fine for this,
  but it reroutes your whole machine while connected.

## Notes & scope

- **HTTP only.** The server and stub speak plain HTTP (great for LAN / internal
  distribution). For public distribution, put it behind a TLS reverse proxy, or
  switch `stub`'s `ureq` to its TLS feature and use `https://` hosts.
- **Cross-platform.** Built natively per-OS. On Linux "executable" means an ELF
  binary; to produce Windows `.exe` installers, cross-compile the `stub` for
  `x86_64-pc-windows-gnu` and point the forge at that stub.
- The installer is deliberately **honest**: it shows the source URL and size and
  installs to a user-chosen, non-privileged folder. It is a distribution tool for
  software you have the right to distribute.
