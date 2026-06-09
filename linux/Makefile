# -- Linux test binaries for m6-starnix bring-up
#
# busybox is fetched + cross-compiled by build-busybox.sh into a single binary:
#   linux/busybox  dynamically linked PIE (PT_INTERP=/lib/ld-musl-aarch64.so.1)
# Committed so the initrd needs no network fetch at flash time. The top Makefile's
# initrd-full bundles it (and seeds rootfs/lib/ld-musl-aarch64.so.1 so it resolves
# its interpreter).
#
# Toolchain: aarch64-linux-musl-gcc (musl.cc tarball or distro package).

.PHONY: all busybox clean

all: busybox

busybox:
	./build-busybox.sh

clean:
	rm -f busybox
