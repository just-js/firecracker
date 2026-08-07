#!/bin/sh
# Hot-patches build/fire2's embedded vmlinux/initrd directly via
# `objcopy --update-section`, without invoking cargo/rustc/mold at all.
#
# Slot capacities are read back from the target binary itself (its
# .joos_vmlinux/.joos_initrd section sizes), not hardcoded here - they're
# configurable at build time via JOOS_VMLINUX_MAX/JOOS_INITRD_MAX (see the
# parent joos project's Makefile / build.rs in this crate), so this stays
# correct no matter what was chosen when the binary was built. Only fails
# (safely - objcopy/pad_slot will error out, not silently truncate) if a
# new asset doesn't fit within whatever capacity that build was given, or
# if Rust source itself changed - both still need a real rebuild.
#
# The config (fire_mem.json) is deliberately not handled here - build.rs
# also transforms it (patches boot-source to point at /dev/null) before
# embedding, and it's small enough that a normal rebuild is fine for it.
#
# Lives alongside build.rs/main.rs (not in the parent joos project) because
# it hard-codes exact knowledge of their slot format (8-byte LE length
# prefix + padding) and section names - if those ever change, this has to
# change in the same commit.
set -e

FIRE2="${1:-build/fire2}"
VMLINUX="${2:-build/vmlinux}"
INITRD="${3:-build/initrd.cpio}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Compiled fresh into $TMP each run rather than cached - trivial ~60-line C
# file, well under the noise floor of the rest of this script.
cc -O2 -o "$TMP/pad_slot" "$SCRIPT_DIR/pad_slot.c"

slot_capacity() {
  # Full section size includes the 8-byte length prefix - capacity excludes it.
  section_size=$(objcopy -O binary --only-section="$1" "$FIRE2" "$TMP/probe" && wc -c <"$TMP/probe")
  echo $((section_size - 8))
}

VMLINUX_MAX=$(slot_capacity .joos_vmlinux)
INITRD_MAX=$(slot_capacity .joos_initrd)

"$TMP/pad_slot" "$VMLINUX" "$VMLINUX_MAX" "$TMP/vmlinux.slot"
"$TMP/pad_slot" "$INITRD" "$INITRD_MAX" "$TMP/initrd.slot"

objcopy --update-section .joos_vmlinux="$TMP/vmlinux.slot" "$FIRE2"
objcopy --update-section .joos_initrd="$TMP/initrd.slot" "$FIRE2"

echo "patched $FIRE2 in place (no relink) - capacities: vmlinux=$VMLINUX_MAX initrd=$INITRD_MAX bytes"
