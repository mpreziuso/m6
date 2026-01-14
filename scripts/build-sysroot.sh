#!/bin/bash
# Build custom sysroot for aarch64-unknown-m6 target
#
# This script builds core, alloc from Rust's source and our std,
# then assembles them into a sysroot for m6-user applications.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TARGET="aarch64-unknown-m6"
TARGET_SPEC="$PROJECT_ROOT/targets/$TARGET.json"
SYSROOT="$PROJECT_ROOT/target/sysroot"
TARGET_DIR="$PROJECT_ROOT/target/$TARGET"

echo "=== Building M6 sysroot ==="
echo "Target: $TARGET"
echo "Output: $SYSROOT"

# Clean sysroot and target for this target to avoid stale artefacts
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
    -Z build-std=core,alloc,compiler_builtins \
    -Z build-std-features=compiler-builtins-mem

# Copy built libraries to sysroot (only essential runtime libraries)
echo "=== Copying libraries to sysroot ==="
DEPS_DIR="$TARGET_DIR/release/deps"

# Copy only the essential sysroot libraries
for lib in core alloc compiler_builtins std; do
    pattern="$DEPS_DIR/lib${lib}-*.rlib"
    files=( $pattern )
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
    files=( $pattern )
    if [ -f "${files[0]}" ]; then
        cp "${files[0]}" "$SYSROOT/lib/rustlib/$TARGET/lib/"
        echo "  Copied: $(basename "${files[0]}")"
    fi
done

echo ""
echo "=== Sysroot built successfully ==="
echo "Location: $SYSROOT"
echo ""
echo "Contents:"
ls -la "$SYSROOT/lib/rustlib/$TARGET/lib/"
