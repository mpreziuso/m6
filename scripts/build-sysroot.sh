#!/bin/bash
# Build custom sysroot for aarch64-unknown-m6 target
#
# This script builds core, alloc from Rust's source and our std,
# then assembles them into a sysroot for m6-user applications.
#
# The build is gated on a fingerprint of everything that can affect the
# sysroot (toolchain, target spec, Cargo.lock, and the source of m6-std plus
# the crates it injects into the sysroot). When none of those changed, the
# existing sysroot is already correct and we skip the expensive `-Z build-std`
# rebuild of core/alloc. When they DID change we do a full clean rebuild,
# identical to the original behaviour — including wiping the per-target dir so
# user binaries are forced to relink against the new std. This matters because
# cargo's dep-info for user crates does NOT track sysroot rlibs, so a partial
# rebuild would silently leave user binaries linked against a stale std.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET="aarch64-unknown-m6"
TARGET_SPEC="$PROJECT_ROOT/targets/$TARGET.json"
SYSROOT="$PROJECT_ROOT/target/sysroot"
TARGET_DIR="$PROJECT_ROOT/target/$TARGET"
STAMP="$SYSROOT/.sysroot.stamp"

# -- Fingerprint of all sysroot inputs
#
# m6-std pulls core/alloc/compiler_builtins (toolchain) plus m6-syscall,
# m6-cap, m6-common, m6-alloc and spin (pinned via Cargo.lock) into the
# sysroot. Hash the toolchain version, the target spec, Cargo.lock and the
# full source of those local crates. Content-based so a `git checkout` or
# `touch` that doesn't change bytes won't trigger a needless rebuild.
compute_fingerprint() {
    rustc +nightly --version
    cat "$TARGET_SPEC"
    cat "$PROJECT_ROOT/Cargo.lock"
    find "$PROJECT_ROOT/m6-std" \
         "$PROJECT_ROOT/m6-syscall" \
         "$PROJECT_ROOT/m6-cap" \
         "$PROJECT_ROOT/m6-common" \
         "$PROJECT_ROOT/m6-alloc" \
         -type f -print0 2>/dev/null | sort -z | xargs -0 sha1sum
}

FINGERPRINT="$(compute_fingerprint | sha1sum | cut -d' ' -f1)"

if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$FINGERPRINT" ]; then
    echo "=== M6 sysroot up to date (fingerprint ${FINGERPRINT:0:12}); skipping rebuild ==="
    exit 0
fi

echo "=== Building M6 sysroot ==="
echo "Target: $TARGET"
echo "Output: $SYSROOT"

# Clean rebuild: wipe the sysroot and per-target dir to avoid stale or
# duplicate hashed rlibs, and to force user binaries to relink against the
# freshly built std (cargo cannot see sysroot changes on its own).
rm -rf "$SYSROOT"
rm -rf "$TARGET_DIR"
mkdir -p "$SYSROOT/lib/rustlib/$TARGET/lib"

# Build m6-std (which produces libstd.rlib) and its dependencies
# using -Z build-std to get core and alloc
echo "=== Building std and dependencies ==="
cd "$PROJECT_ROOT"

cargo +nightly build \
    --package m6-std \
    --release \
    --target "$TARGET_SPEC" \
    -Z json-target-spec \
    -Z build-std=core,alloc,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem

# Copy built libraries to sysroot (only essential runtime libraries)
echo "=== Copying libraries to sysroot ==="
DEPS_DIR="$TARGET_DIR/release/deps"

# Copy only the essential sysroot libraries
for lib in core alloc compiler_builtins std; do
    pattern="$DEPS_DIR/lib${lib}-*.rlib"
    # Newest match first by mtime, so we never copy a stale hashed rlib
    files=( $(ls -t $pattern 2>/dev/null) )
    if [ -f "${files[0]}" ]; then
        # Use only the first match (most recent)
        cp "${files[0]}" "$SYSROOT/lib/rustlib/$TARGET/lib/"
        echo "  Copied: $(basename "${files[0]}")"
    else
        echo "  Warning: $lib not found"
    fi
done

# Also copy m6-std's dependencies that are needed at runtime
for lib in m6_syscall m6_cap m6_common m6_alloc spin; do
    pattern="$DEPS_DIR/lib${lib}-*.rlib"
    # Newest match first by mtime, so we never copy a stale hashed rlib
    files=( $(ls -t $pattern 2>/dev/null) )
    if [ -f "${files[0]}" ]; then
        cp "${files[0]}" "$SYSROOT/lib/rustlib/$TARGET/lib/"
        echo "  Copied: $(basename "${files[0]}")"
    fi
done

# Record the fingerprint last, so an interrupted build is not marked complete.
echo "$FINGERPRINT" > "$STAMP"

echo ""
echo "=== Sysroot built successfully ==="
echo "Location: $SYSROOT"
echo ""
echo "Contents:"
ls -la "$SYSROOT/lib/rustlib/$TARGET/lib/"
