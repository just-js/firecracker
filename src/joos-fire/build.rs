// Resolves vmlinux/initrd/config paths (env-overridable, defaulting to this
// project's usual build outputs) and builds fixed-capacity, length-prefixed
// "slot" files for each - not the raw asset bytes directly.
//
// Why: each slot gets embedded into its own dedicated ELF section
// (#[link_section] in main.rs) at generous fixed capacity. As long as a new
// vmlinux/initrd/config fits within that capacity, `objcopy --update-section`
// can overwrite just that section's bytes directly in the already-built
// binary - no cargo/rustc/mold involved at all. See tools/patch_fire2.sh and
// FIRECRACKER.md. Only a real `cargo build` (which reruns this script) is
// needed when Rust source changes, or an asset outgrows its slot.
//
// Slot format: 8-byte little-endian length, followed by the real file's
// bytes, followed by zero padding out to the slot's fixed capacity.

use std::path::{Path, PathBuf};

// Must match the MAX constants in src/main.rs.
const VMLINUX_MAX: usize = 24 * 1024 * 1024;
const INITRD_MAX: usize = 12 * 1024 * 1024;
const CONFIG_MAX: usize = 64 * 1024;

fn resolve(env_var: &str, default_rel: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let raw = std::env::var(env_var).unwrap_or_else(|_| default_rel.to_string());
    let path = Path::new(&manifest_dir).join(raw);
    path.canonicalize()
        .unwrap_or_else(|e| panic!("{env_var}: cannot resolve {path:?}: {e}"))
}

/// Writes `dest` as an 8-byte LE length prefix + `content` + zero padding to
/// `capacity` total bytes (capacity here excludes the 8-byte prefix itself,
/// matching how main.rs slices `[8..8+len]` out of a `capacity`-sized data
/// region following the prefix).
fn write_slot(dest: &Path, content: &[u8], capacity: usize) {
    if content.len() > capacity {
        panic!(
            "{dest:?}: content is {} bytes, exceeds slot capacity of {capacity} bytes - bump the \
             MAX constant in build.rs and src/main.rs (they must match) and rebuild",
            content.len()
        );
    }
    let mut out = Vec::with_capacity(8 + capacity);
    out.extend_from_slice(&(content.len() as u64).to_le_bytes());
    out.extend_from_slice(content);
    out.resize(8 + capacity, 0);
    std::fs::write(dest, out).unwrap_or_else(|e| panic!("cannot write {dest:?}: {e}"));
}

fn main() {
    // Bare filenames by default - real usage always sets these explicitly
    // (see the Makefile), pointing at the joos project's build/ directory.
    let vmlinux = resolve("JOOS_VMLINUX", "vmlinux");
    let initrd = resolve("JOOS_INITRD", "initrd.cpio");
    let config_src = resolve("JOOS_CONFIG", "fire_mem.json");

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let vmlinux_bytes =
        std::fs::read(&vmlinux).unwrap_or_else(|e| panic!("cannot read {vmlinux:?}: {e}"));
    let vmlinux_slot = Path::new(&out_dir).join("vmlinux.slot");
    write_slot(&vmlinux_slot, &vmlinux_bytes, VMLINUX_MAX);
    println!("cargo:rustc-env=JOOS_VMLINUX_SLOT_PATH={}", vmlinux_slot.display());

    let initrd_bytes =
        std::fs::read(&initrd).unwrap_or_else(|e| panic!("cannot read {initrd:?}: {e}"));
    let initrd_slot = Path::new(&out_dir).join("initrd.slot");
    write_slot(&initrd_slot, &initrd_bytes, INITRD_MAX);
    println!("cargo:rustc-env=JOOS_INITRD_SLOT_PATH={}", initrd_slot.display());

    let raw = std::fs::read_to_string(&config_src)
        .unwrap_or_else(|e| panic!("cannot read {config_src:?}: {e}"));
    let mut value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("cannot parse {config_src:?} as JSON: {e}"));
    if let Some(boot_source) = value.get_mut("boot-source") {
        boot_source["kernel_image_path"] = serde_json::Value::String("/dev/null".to_string());
        if let Some(obj) = boot_source.as_object_mut() {
            obj.remove("initrd_path");
        }
    }
    let config_slot = Path::new(&out_dir).join("config.slot");
    write_slot(
        &config_slot,
        serde_json::to_string(&value).unwrap().as_bytes(),
        CONFIG_MAX,
    );
    println!("cargo:rustc-env=JOOS_CONFIG_SLOT_PATH={}", config_slot.display());

    println!("cargo:rerun-if-changed={}", vmlinux.display());
    println!("cargo:rerun-if-changed={}", initrd.display());
    println!("cargo:rerun-if-changed={}", config_src.display());
    println!("cargo:rerun-if-env-changed=JOOS_VMLINUX");
    println!("cargo:rerun-if-env-changed=JOOS_INITRD");
    println!("cargo:rerun-if-env-changed=JOOS_CONFIG");
}
