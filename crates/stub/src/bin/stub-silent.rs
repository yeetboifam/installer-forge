//! Silent installer: no console window on Windows, installs to the default dir
//! with no prompts. Pair with "run after install" for a double-click experience.

#![cfg_attr(windows, windows_subsystem = "windows")]

fn main() {
    stub::run(true);
}
