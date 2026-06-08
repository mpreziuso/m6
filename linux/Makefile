# -- Linux test binaries for m6-starnix bring-up
#
# These are static aarch64 ELFs that exercise the restricted-mode trap
# path. They live on the FAT32 volume (virtio-blk) and are loaded by
# svc-starnix.
#
# Toolchain: prefers aarch64-linux-musl-gcc; falls back to
# aarch64-linux-gnu-gcc. Install one of:
#   - musl.cc tarball: wget https://musl.cc/aarch64-linux-musl-cross.tgz
#   - dnf install gcc-aarch64-linux-gnu  (Fedora; glibc, but fine for
#     -nostdlib bare-asm binaries like hello.S)

CROSS_GCC := $(shell command -v aarch64-linux-musl-gcc 2>/dev/null \
              || command -v aarch64-linux-gnu-gcc 2>/dev/null)

ifeq ($(CROSS_GCC),)
$(error No aarch64 cross toolchain found. Install aarch64-linux-musl-gcc or aarch64-linux-gnu-gcc.)
endif

BINARIES := hello hellopie

.PHONY: all clean busybox

all: $(BINARIES)

hello: hello.S
	$(CROSS_GCC) -nostdlib -static -no-pie -Wl,--build-id=none -o $@ $<
	@printf "Built %s (%s bytes)\n" "$@" "$$(stat -c%s $@)"

# Static-PIE (ET_DYN, no PT_INTERP): the loader places it at an ASLR base and
# the libc startup self-relocates. Exercises the PIE / load-bias path.
hellopie: hellopie.c
	$(CROSS_GCC) -static-pie -Wl,--build-id=none -o $@ $<
	@printf "Built %s (%s bytes)\n" "$@" "$$(stat -c%s $@)"

# busybox is fetched + cross-compiled (static, non-PIE) by a helper script
# rather than built from a local source tree. It is committed like hello so
# the initrd needs no network fetch at flash time.
busybox:
	./build-busybox.sh

clean:
	rm -f $(BINARIES)
