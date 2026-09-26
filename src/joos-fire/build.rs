// joos's tools/assemble.js appends the kernel, initrd and config to the
// built binary as one extra PT_LOAD segment (see main.rs's payload()). It
// turns a spare PT_NULL program header into that segment, so reserve one.
// Only mold has --spare-program-headers (GNU ld and lld don't), so select it
// here as well as in .cargo/config.toml, which RUSTFLAGS in the environment
// would override.
fn main() {
    println!("cargo:rustc-link-arg-bins=-fuse-ld=mold");
    println!("cargo:rustc-link-arg-bins=-Wl,--spare-program-headers=1");
}
