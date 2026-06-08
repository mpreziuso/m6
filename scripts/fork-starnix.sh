#!/bin/bash
# Fork Fuchsia Starnix source code for M6.
#
# This script deterministically copies and transforms Starnix kernel code
# from a Fuchsia checkout into the m6-starnix crate. It can be re-run at
# any time to refresh from upstream.
#
# Usage: ./scripts/fork-starnix.sh [fuchsia-root]
#        Default: ~/git/fuchsia
#
# What it does:
#   1. Copies whole Starnix kernel/core source directories (recursively) so
#      every `mod` declaration in the copied mod.rs files resolves to a file.
#   2. Excludes a small set of genuinely out-of-scope subtrees (FIDL RemoteFS,
#      SELinux, non-ARM64 arch) by NOT copying them AND gating their module
#      declaration behind `#[cfg(feature = "fuchsia")]` so the tree still parses.
#   3. Applies mechanical text transformations (std->shim, drop Fuchsia deps).
#   4. Pins the upstream revision in m6-starnix/STARNIX_REV.
#
# What it does NOT do:
#   - Replace files that are M6-native (loader.rs, mm.rs, syscall_loop.rs, lib.rs)
#   - Copy non-ARM64 arch (x64/riscv64), FIDL RemoteFS, or SELinux hooks
#   - Strip async/await (that corrupts multi-line chains; async is surfaced as
#     real errors to be handled by an async-shim during porting)
#   - Fix compilation errors (that's manual iterative work)

set -euo pipefail

FUCHSIA="${1:-$HOME/git/fuchsia}"
STARNIX="$FUCHSIA/src/starnix"
M6="$(cd "$(dirname "$0")/.." && pwd)"
DEST="$M6/m6-starnix/src"

# Validate Fuchsia checkout
if [[ ! -d "$STARNIX/kernel/core" ]]; then
    echo "ERROR: Fuchsia starnix not found at $STARNIX/kernel/core"
    echo "Usage: $0 [path-to-fuchsia-root]"
    exit 1
fi

# Forked directories owned by this script (cleaned before each run for
# determinism). M6-native files (lib.rs, loader.rs, mm.rs, syscall_loop.rs)
# live alongside these and are never touched.
FORKED_DIRS=(signals arch task vfs fs mm_ref security ptrace execution device time vdso)
FORKED_TOP_FILES=(syscall_table.rs mutable_state.rs)

echo "==> Forking Starnix from $STARNIX"
echo "    Destination: $DEST"

# -- Pin the upstream revision
REV="$(git -C "$FUCHSIA" rev-parse HEAD 2>/dev/null || echo unknown)"
REV_DATE="$(git -C "$FUCHSIA" log -1 --format=%ci 2>/dev/null || echo unknown)"
{
    echo "$REV"
    echo "# Fuchsia revision this fork was generated from."
    echo "# Date: $REV_DATE"
    echo "# Regenerate with: ./scripts/fork-starnix.sh $FUCHSIA"
} > "$M6/m6-starnix/STARNIX_REV"
echo "    Upstream revision: $REV ($REV_DATE)"

# -- Clean previously-forked content for a deterministic result
for d in "${FORKED_DIRS[@]}"; do
    rm -rf "${DEST:?}/$d"
done
for f in "${FORKED_TOP_FILES[@]}"; do
    rm -f "${DEST:?}/$f"
done

# -- Helper: copy a single file with header
copy_file() {
    local src="$1"
    local dst="$2"

    if [[ ! -f "$src" ]]; then
        echo "    SKIP (not found): $src"
        return
    fi

    mkdir -p "$(dirname "$dst")"
    cp "$src" "$dst"
}

# -- Helper: recursively copy every .rs file from a directory, preserving
#    subdirectory structure. This guarantees the file set matches the module
#    declarations in the copied mod.rs files (no E0583 "file not found").
copy_tree() {
    local src="$1"
    local dst="$2"

    if [[ ! -d "$src" ]]; then
        echo "    SKIP (dir not found): $src"
        return
    fi

    local count=0
    while IFS= read -r -d '' rel; do
        mkdir -p "$dst/$(dirname "$rel")"
        cp "$src/$rel" "$dst/$rel"
        count=$((count + 1))
    done < <(cd "$src" && find . -name '*.rs' -type f -print0)
    echo "    COPY_TREE: $src -> $dst ($count files)"
}

# -- Helper: gate a module declaration behind `#[cfg(feature = "fuchsia")]`.
#    Used for out-of-scope subtrees we deliberately do NOT copy, so the
#    parent mod.rs still parses on the default (non-fuchsia) build.
gate_module() {
    local file="$1"
    local mod="$2"

    [[ -f "$file" ]] || { echo "    SKIP gate (no file): $file"; return; }
    # Insert the cfg attribute before the (optionally pub) `mod <name>;` line.
    sed -i -E "s|^([[:space:]]*)((pub )?mod ${mod};)|\1#[cfg(feature = \"fuchsia\")]\n\1\2|" "$file"
    echo "    GATE: $mod in $(basename "$(dirname "$file")")/$(basename "$file")"
}

# -- Helper: comment out a `use <prefix>...;` import, INCLUDING multi-line
#    `use <prefix>::{ ... };` blocks. The previous single-line sed left the
#    continuation lines and a dangling `};` (the time/utc.rs parse error).
#    Implementation: when a line starts with `use <prefix>`, keep appending
#    following lines until one ends in `;`, then comment out every line in the
#    accumulated block.
strip_use() {
    local f="$1" prefix="$2" label="$3"
    sed -i "/^use ${prefix}/{:a;/;[[:space:]]*\$/!{N;ba};s|^|// REMOVED(${label}) |;s|\n|\n// |g}" "$f"
}

# -- Helper: apply sed transformations to all .rs files under a directory
transform() {
    local dir="$1"
    echo "    Transforming $dir ..."

    find "$dir" -name '*.rs' -type f | while read -r f; do
        # Add M6 header (replace Fuchsia copyright with fork notice)
        sed -i '1{/^\/\/ Copyright.*Fuchsia/c\// Forked from Fuchsia'\''s Starnix for M6 (no_std, ARM64 only).\n// Original: Copyright 2024 The Fuchsia Authors. BSD license.
        }' "$f"

        # -- std -> shim replacements
        # Fully-qualified paths: ::std:: -> ::core::
        sed -i 's/::std::/::core::/g' "$f"
        # All remaining `std::` paths (imports AND bare inline paths like
        # `std::mem::size_of`) -> the m6_starnix_std shim, which mirrors std's
        # module tree. `\b` leaves `m6_starnix_std::` untouched (no word
        # boundary after the leading `_`). Run after the `::std::` rewrite so
        # those have already become `::core::`.
        sed -i 's/\bstd::/m6_starnix_std::/g' "$f"
        # Correction: the blanket rewrite above also catches primitive-module
        # paths (`std::i32::MAX`, `std::u64::MAX`, …) which the shim does NOT
        # mirror. Map those back to the primitive's associated consts
        # (`i32::MAX`), which need no import.
        sed -i -E 's/\bm6_starnix_std::(i8|i16|i32|i64|i128|isize|u8|u16|u32|u64|u128|usize|f32|f64)::/\1::/g' "$f"

        # -- this crate IS starnix_core: rewrite self-references to crate::
        sed -i 's/\bstarnix_core::/crate::/g' "$f"

        # -- Fuchsia Zircon -> M6 zx-shim
        sed -i 's/use fuchsia_zircon as zx;/use m6_zx_shim as zx;/g' "$f"
        sed -i 's/use fuchsia_zircon::/use m6_zx_shim::/g' "$f"

        # -- Drop Fuchsia-only imports (multi-line aware; leaves a marker)
        strip_use "$f" fuchsia_async   fuchsia_async
        strip_use "$f" fuchsia_trace   fuchsia_trace
        strip_use "$f" fuchsia_inspect fuchsia_inspect
        strip_use "$f" fuchsia_runtime fuchsia_runtime
        strip_use "$f" fuchsia_component fuchsia_component
        strip_use "$f" fuchsia_sync    fuchsia_sync
        strip_use "$f" fidl            fidl
        strip_use "$f" futures         futures
        strip_use "$f" inspect_stubs   inspect_stubs

        # -- Replace track_stub!(...) single-line invocations with a no-op comment
        sed -i 's/track_stub!(.*);/\/\/ TODO(track_stub)/g' "$f"

        # -- Inject the alloc prelude glob. Upstream is built as `std`, so it
        #    uses bare Box/Vec/String/format!/vec! from the std prelude. Under
        #    `#![no_std]` only the core prelude is auto-imported, so inject a
        #    glob (glob => no E0252 clash with files that import these too). The
        #    line is placed AFTER any leading comments and inner attributes
        #    (`#![...]`), which must remain first in the file.
        awk '
            BEGIN { done = 0 }
            done == 0 && $0 !~ /^[[:space:]]*\/\// && $0 !~ /^[[:space:]]*$/ && $0 !~ /^[[:space:]]*#!\[/ {
                print "#[allow(unused_imports)] use m6_starnix_std::prelude::*;"
                done = 1
            }
            { print }
            END { if (done == 0) print "#[allow(unused_imports)] use m6_starnix_std::prelude::*;" }
        ' "$f" > "$f.tmp" && mv "$f.tmp" "$f"

        # NOTE: async fn / .await are intentionally NOT stripped. Blindly
        # removing `.await` corrupts multi-line method chains. Async is left
        # intact and handled by an async-shim during porting.
    done
}

# ============================================================
# Signals (whole tree, ~0% Zircon deps)
# ============================================================
echo ""
echo "==> Signals"
copy_tree "$STARNIX/kernel/core/signals" "$DEST/signals"

# ============================================================
# Arch / ARM64 only (non-ARM64 arches are out of scope)
# ============================================================
echo ""
echo "==> Arch/ARM64"
copy_tree "$STARNIX/kernel/core/arch/arm64" "$DEST/arch"
# Generate a flat mod.rs (upstream selects arch via cfg in a parent we skip).
if [[ ! -f "$DEST/arch/mod.rs" ]]; then
    {
        echo "// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only)."
        echo "// Original: Copyright 2024 The Fuchsia Authors. BSD license."
        echo ""
        for f in "$DEST/arch/"*.rs; do
            mod=$(basename "$f" .rs)
            [[ "$mod" != "mod" ]] && echo "pub mod $mod;"
        done
    } > "$DEST/arch/mod.rs"
fi

# ============================================================
# Task management (whole tree incl. scheduler/)
# ============================================================
echo ""
echo "==> Task management"
copy_tree "$STARNIX/kernel/core/task" "$DEST/task"

# ============================================================
# VFS (whole tree incl. pseudo/ socket/ buffers/)
# ============================================================
echo ""
echo "==> VFS"
copy_tree "$STARNIX/kernel/core/vfs" "$DEST/vfs"

# ============================================================
# Filesystem implementations (exclude FIDL RemoteFS: fs/fuchsia)
# ============================================================
echo ""
echo "==> Filesystem implementations"
copy_tree "$STARNIX/kernel/core/fs" "$DEST/fs"
rm -rf "$DEST/fs/fuchsia"
gate_module "$DEST/fs/mod.rs" fuchsia

# ============================================================
# Memory management (reference for rewrite; whole tree)
# ============================================================
echo ""
echo "==> Memory management (reference)"
copy_tree "$STARNIX/kernel/core/mm" "$DEST/mm_ref"

# ============================================================
# Security (exclude SELinux hooks: M6 uses capabilities)
# ============================================================
echo ""
echo "==> Security"
copy_tree "$STARNIX/kernel/core/security" "$DEST/security"
rm -rf "$DEST/security/selinux_hooks"
gate_module "$DEST/security/mod.rs" selinux_hooks

# ============================================================
# Ptrace (whole tree)
# ============================================================
echo ""
echo "==> Ptrace"
copy_tree "$STARNIX/kernel/core/ptrace" "$DEST/ptrace"

# ============================================================
# Execution (whole tree; heavily Fuchsia-runtime, gated at lib.rs level)
# ============================================================
echo ""
echo "==> Execution"
copy_tree "$STARNIX/kernel/core/execution" "$DEST/execution"

# ============================================================
# Device subsystem (whole tree)
# ============================================================
echo ""
echo "==> Device subsystem"
copy_tree "$STARNIX/kernel/core/device" "$DEST/device"

# ============================================================
# Time subsystem (whole tree)
# ============================================================
echo ""
echo "==> Time subsystem"
copy_tree "$STARNIX/kernel/core/time" "$DEST/time"

# ============================================================
# Syscall dispatch table
# ============================================================
echo ""
echo "==> Syscall dispatch table"
copy_file "$STARNIX/kernel/syscall_loop/src/table.rs" "$DEST/syscall_table.rs"

# -- Other core/ top-level items the fork references via crate:: (were missing).
# vdso loader (crate::vdso::vdso_loader::Vdso) and the mutable_state macros
# (crate::mutable_state::{state_accessor, state_implementation, …}).
copy_tree "$STARNIX/kernel/core/vdso" "$DEST/vdso"
copy_file "$STARNIX/kernel/core/mutable_state.rs" "$DEST/mutable_state.rs"
# NOTE (gate candidates, not yet copied): core/{bpf,perf,power,syscalls,testing.rs}.
# bpf/perf/power are gated to ENOSYS; syscalls/ pulls fuchsia_runtime (UtcInstant)
# and needs its time-pointer types extracted; testing.rs is test-only.

# ============================================================
# Apply text transformations to ALL forked files
# ============================================================
echo ""
echo "==> Applying text transformations"
for dir in "${FORKED_DIRS[@]}"; do
    [[ -d "$DEST/$dir" ]] && transform "$DEST/$dir"
done
# Top-level forked files share the src dir with M6-native files; transform
# them individually rather than transforming the whole src tree.
for f in "${FORKED_TOP_FILES[@]}"; do
    if [[ -f "$DEST/$f" ]]; then
        tmpd="$(mktemp -d)"
        cp "$DEST/$f" "$tmpd/$f"
        transform "$tmpd"
        cp "$tmpd/$f" "$DEST/$f"
        rm -rf "$tmpd"
    fi
done

# ============================================================
# Summary
# ============================================================
echo ""
echo "==> Excluded (NOT copied; gated behind feature=\"fuchsia\" where declared):"
echo "    fs/fuchsia/                     — FIDL RemoteFS (gated in fs/mod.rs)"
echo "    security/selinux_hooks/         — SELinux (gated in security/mod.rs)"
echo "    arch/{x64,riscv64}/             — non-ARM64"
echo "    kernel/runner/, bpf/, perf/, power/, vdso/ — not in core/, never referenced"
echo ""
echo "==> NOT overwritten (M6-native):"
echo "    lib.rs, loader.rs, mm.rs, syscall_loop.rs"
echo ""
echo "==> Fork complete (upstream $REV). Next:"
echo "    1. Declare the forked modules in m6-starnix/src/lib.rs"
echo "    2. cargo check -p m6-starnix     (real error surface)"
echo "    3. Fix errors iteratively per review/starnix-porting-plan.md"
