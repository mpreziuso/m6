#!/bin/sh
# -- Build a static, non-PIE aarch64 busybox for m6-starnix bring-up.
#
# The M6 Starnix loader maps PT_LOAD segments at their absolute p_vaddr and
# has no PIE/load-bias or PT_INTERP support, so busybox must be a plain
# statically-linked ET_EXEC (musl's `-static` defaults to static-pie, which
# would NOT load — hence the explicit -no-pie).
#
# Output: linux/busybox (committed like linux/hello so it ships in the initrd
# without requiring a network fetch at build time).
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
# Static, non-PIE ET_EXEC.
sed -i 's/# CONFIG_STATIC is not set/CONFIG_STATIC=y/' .config
sed -i 's#^CONFIG_EXTRA_CFLAGS=.*#CONFIG_EXTRA_CFLAGS="-fno-PIE"#' .config
sed -i 's#^CONFIG_EXTRA_LDFLAGS=.*#CONFIG_EXTRA_LDFLAGS="-no-pie -Wl,--build-id=none"#' .config
# `tc` does not build against musl headers.
sed -i 's/^CONFIG_TC=y/CONFIG_TC=n/' .config
sed -i 's/^CONFIG_FEATURE_TC_INGRESS=y/CONFIG_FEATURE_TC_INGRESS=n/' .config
yes "" | make ARCH=arm64 CROSS_COMPILE="$CROSS" oldconfig >/dev/null

make ARCH=arm64 CROSS_COMPILE="$CROSS" -j"$(nproc)"
"${CROSS}strip" busybox
cp busybox "$HERE/busybox"
printf "Built %s (%s bytes): " "$HERE/busybox" "$(stat -c%s "$HERE/busybox")"
file "$HERE/busybox"
