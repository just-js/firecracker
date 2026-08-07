// Resolves vmlinux/initrd/config paths (env-overridable, defaulting to this
// project's usual build outputs) to absolute paths, patches the config's
// boot-source section (its kernel_image_path/initrd_path point at
// wrapper-provided memfds that don't exist here - see main.rs, which loads
// the kernel/initrd from the embedded bytes directly instead), and wires up
// `cargo:rerun-if-changed` so touching vmlinux/initrd.cpio/fire_mem.json is
// enough to get a rebuild - no separate bundling step needed.

use std::path::{Path, PathBuf};

fn resolve(env_var: &str, default_rel: &str) -> PathBuf {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let raw = std::env::var(env_var).unwrap_or_else(|_| default_rel.to_string());
    let path = Path::new(&manifest_dir).join(raw);
    path.canonicalize()
        .unwrap_or_else(|e| panic!("{env_var}: cannot resolve {path:?}: {e}"))
}

fn main() {
    // Bare filenames by default - real usage always sets these explicitly
    // (see the Makefile), pointing at the joos project's build/ directory.
    let vmlinux = resolve("JOOS_VMLINUX", "vmlinux");
    let initrd = resolve("JOOS_INITRD", "initrd.cpio");
    let config_src = resolve("JOOS_CONFIG", "fire_mem.json");

    println!("cargo:rustc-env=JOOS_VMLINUX_PATH={}", vmlinux.display());
    println!("cargo:rustc-env=JOOS_INITRD_PATH={}", initrd.display());

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

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let patched_path = Path::new(&out_dir).join("config.json");
    std::fs::write(&patched_path, serde_json::to_string(&value).unwrap())
        .unwrap_or_else(|e| panic!("cannot write {patched_path:?}: {e}"));
    println!("cargo:rustc-env=JOOS_CONFIG_PATH={}", patched_path.display());

    println!("cargo:rerun-if-changed={}", vmlinux.display());
    println!("cargo:rerun-if-changed={}", initrd.display());
    println!("cargo:rerun-if-changed={}", config_src.display());
    println!("cargo:rerun-if-env-changed=JOOS_VMLINUX");
    println!("cargo:rerun-if-env-changed=JOOS_INITRD");
    println!("cargo:rerun-if-env-changed=JOOS_CONFIG");
}
