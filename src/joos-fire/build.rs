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

// Note on candidate #1 in joos/INIT.md ("Plan: zero-copy vmlinux/initrd
// loading in VMM construction"): vmlinux's PT_LOAD segment table/entry
// point/PVH-boot-protocol flag used to be parsed *here*, at build time, and
// baked into main.rs as compile-time constants. That's wrong: `make
// patch-fire2` (tools/joos-fire-patch) overwrites a slot's *content*
// in-place in an already-built `fire2` binary without ever re-running this
// script - so build-time constants describing "the vmlinux that was present
// during the last real `cargo build`" go silently stale the moment someone
// hot-patches in a different vmlinux, and the VM boots pointed at the wrong
// entry address for the bytes actually embedded (observed directly: instant
// `Unexpected exit reason on vcpu run: Shutdown` after a hot-patch). Fixed
// by moving this parsing to run at *runtime* in main.rs, against the
// actually-embedded slot bytes (`slot_data(&VMLINUX_SLOT.0)`) every time -
// see `parse_vmlinux_layout` there instead.

// Defaults if JOOS_VMLINUX_MAX/JOOS_INITRD_MAX aren't set - current usage is
// ~15.65MB/~6.2MB, so these have plenty of headroom out of the box. The
// resolved values (default or overridden) get passed to main.rs via
// cargo:rustc-env below, so build.rs's padding and main.rs's array sizes
// always agree - no hardcoded constant to keep in sync by hand anymore.
const DEFAULT_VMLINUX_MAX: usize = 24 * 1024 * 1024;
const DEFAULT_INITRD_MAX: usize = 12 * 1024 * 1024;
const CONFIG_MAX: usize = 64 * 1024;

fn resolve(env_var: &str, default_rel: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let raw = std::env::var(env_var).unwrap_or_else(|_| default_rel.to_string());
    let path = Path::new(&manifest_dir).join(raw);
    path.canonicalize()
        .unwrap_or_else(|e| panic!("{env_var}: cannot resolve {path:?}: {e}"))
}

/// Resolves a slot capacity from an env var (e.g. `JOOS_VMLINUX_MAX=33554432
/// cargo build ...`), falling back to `default`, and re-exports the
/// resolved value via `cargo:rustc-env` so main.rs's `env!()` always sees
/// the exact same number build.rs used to pad the slot file with.
fn resolve_size(env_var: &str, default: usize) -> usize {
    let value = std::env::var(env_var)
        .ok()
        .filter(|v| !v.is_empty()) // e.g. `JOOS_VMLINUX_MAX=` from an unset Makefile var
        .map(|v| {
            v.parse::<usize>()
                .unwrap_or_else(|e| panic!("{env_var}={v:?}: not a valid size in bytes: {e}"))
        })
        .unwrap_or(default);
    println!("cargo:rustc-env={env_var}={value}");
    println!("cargo:rerun-if-env-changed={env_var}");
    value
}

/// Writes `dest` as `content` + zero padding to `capacity` bytes + an 8-byte
/// LE length trailer, `capacity + 8` bytes total. The length lives at the
/// *end* (not the start) specifically so `content` begins at offset 0 of
/// the slot - required for the zero-copy plan (joos/INIT.md) to `mmap()`
/// this slot's section directly: content has to start at a page-aligned
/// file offset, and while `PageAligned` (main.rs) makes the *section's own*
/// offset page-aligned, an 8-byte prefix ahead of the content would still
/// shift content 8 bytes past that alignment. `joos-fire-patch` must build
/// the exact same layout when hot-patching - see its own write there.
fn write_slot(dest: &Path, content: &[u8], capacity: usize) {
    if content.len() > capacity {
        panic!(
            "{dest:?}: content is {} bytes, exceeds slot capacity of {capacity} bytes - bump the \
             MAX constant in build.rs and src/main.rs (they must match) and rebuild",
            content.len()
        );
    }
    let mut out = Vec::with_capacity(8 + capacity);
    out.extend_from_slice(content);
    out.resize(capacity, 0);
    out.extend_from_slice(&(content.len() as u64).to_le_bytes());
    std::fs::write(dest, out).unwrap_or_else(|e| panic!("cannot write {dest:?}: {e}"));
}

fn main() {
    // Bare filenames by default - real usage always sets these explicitly
    // (see the Makefile), pointing at the joos project's build/ directory.
    let vmlinux = resolve("JOOS_VMLINUX", "vmlinux");
    let initrd = resolve("JOOS_INITRD", "initrd.cpio");
    let config_src = resolve("JOOS_CONFIG", "fire_mem.json");

    let vmlinux_max = resolve_size("JOOS_VMLINUX_MAX", DEFAULT_VMLINUX_MAX);
    let initrd_max = resolve_size("JOOS_INITRD_MAX", DEFAULT_INITRD_MAX);

    let out_dir = std::env::var("OUT_DIR").unwrap();

    let vmlinux_bytes =
        std::fs::read(&vmlinux).unwrap_or_else(|e| panic!("cannot read {vmlinux:?}: {e}"));
    let vmlinux_slot = Path::new(&out_dir).join("vmlinux.slot");
    write_slot(&vmlinux_slot, &vmlinux_bytes, vmlinux_max);
    println!("cargo:rustc-env=JOOS_VMLINUX_SLOT_PATH={}", vmlinux_slot.display());

    let initrd_bytes =
        std::fs::read(&initrd).unwrap_or_else(|e| panic!("cannot read {initrd:?}: {e}"));
    let initrd_slot = Path::new(&out_dir).join("initrd.slot");
    write_slot(&initrd_slot, &initrd_bytes, initrd_max);
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
