#!/bin/sh
# -- Build a dynamically-linked aarch64 busybox for m6-starnix bring-up.
#
# Output: linux/busybox — dynamically linked PIE
# (PT_INTERP=/lib/ld-musl-aarch64.so.1). The M6 loader maps both it and the musl
# interpreter at an ASLR base; ld-musl relocates + resolves NEEDED libc.so (which
# for musl IS the interpreter, so no extra .so is needed — only ld-musl is seeded
# into the initrd rootfs/lib). Exercises the full PT_INTERP/AT_BASE dynamic path
# with a large, real mapping footprint.
#
# Committed so it ships in the initrd without a network fetch at build time.
#
# Toolchain: aarch64-linux-musl-gcc (musl.cc tarball or distro package).
set -eu

VERSION="${BUSYBOX_VERSION:-1.36.1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${BUSYBOX_WORKDIR:-/tmp/m6-busybox-build}"
CROSS="${CROSS_COMPILE:-aarch64-linux-musl-}"

if ! command -v "${CROSS}gcc" >/dev/null 2>&1; then
    echo "error: ${CROSS}gcc not found. Install the aarch64 musl cross toolchain." >&2
    exit 1
fi

mkdir -p "$WORK"
cd "$WORK"
tarball="busybox-${VERSION}.tar.bz2"
if [ ! -f "$tarball" ]; then
    curl -sSL -o "$tarball" "https://busybox.net/downloads/${tarball}"
fi
rm -rf "busybox-${VERSION}"
tar xf "$tarball"
cd "busybox-${VERSION}"

make ARCH=arm64 CROSS_COMPILE="$CROSS" defconfig >/dev/null
# CONFIG_STATIC stays off (defconfig default) -> dynamic link against musl libc.
# Leave PIE at the toolchain default (musl-gcc emits dynamic PIE), which is the
# PT_INTERP path the M6 loader supports. --build-id=none keeps it reproducible.
sed -i 's#^CONFIG_EXTRA_LDFLAGS=.*#CONFIG_EXTRA_LDFLAGS="-Wl,--build-id=none"#' .config
# `tc` does not build against musl headers.
sed -i 's/^CONFIG_TC=y/CONFIG_TC=n/' .config
sed -i 's/^CONFIG_FEATURE_TC_INGRESS=y/CONFIG_FEATURE_TC_INGRESS=n/' .config
yes "" | make ARCH=arm64 CROSS_COMPILE="$CROSS" oldconfig >/dev/null
make ARCH=arm64 CROSS_COMPILE="$CROSS" -j"$(nproc)"
"${CROSS}strip" busybox
cp busybox "$HERE/busybox"
printf "Built %s (%s bytes): " "$HERE/busybox" "$(stat -c%s "$HERE/busybox")"
file "$HERE/busybox"
