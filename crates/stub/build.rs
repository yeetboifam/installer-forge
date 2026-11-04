//! Embeds Windows PE resources into the stub binaries (version info, icon,
//! application manifest). This is standard software-distribution hygiene: it
//! makes the installer present as normal, identifiable software rather than a
//! bare, metadata-less binary. Runs only when the build target is Windows.

fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        return;
    }

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap_or_else(|_| ".".into());
    let icon = format!("{manifest_dir}/assets/installer.ico");
    let manifest = format!("{manifest_dir}/assets/installer.manifest");

    println!("cargo:rerun-if-changed=assets/installer.ico");
    println!("cargo:rerun-if-changed=assets/installer.manifest");

    let mut res = winresource::WindowsResource::new();
    res.set("ProductName", "Installer Forge")
        .set("FileDescription", "Application installer")
        .set("CompanyName", "Installer Forge")
        .set("LegalCopyright", "")
        .set("InternalName", "installer")
        .set("OriginalFilename", "installer.exe")
        .set("FileVersion", "1.0.0.0")
        .set("ProductVersion", "1.0.0.0");
    res.set_icon(&icon);
    res.set_manifest_file(&manifest);

    if let Err(e) = res.compile() {
        // Don't fail the build if the resource compiler isn't present; the stub
        // still works, it just won't carry the metadata.
        println!("cargo:warning=winresource: could not embed PE resources: {e}");
    }
}
