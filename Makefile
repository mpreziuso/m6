.PHONY: clean check clippy clippy-fork run debug fmt fmt-check sysroot system user image test \
        busybox fat32-image flash flash-full

all: boot kernel initrd-full

boot:
	cargo build --package m6-boot --target aarch64-unknown-uefi --release

kernel:
	cargo build --package m6-kernel --target aarch64-unknown-none --release

# Build system components (init, device-mgr, drivers, services)
system:
	cargo build --package m6-system --target aarch64-unknown-none --release

# Build sysroot for aarch64-unknown-m6 target
sysroot:
	./scripts/build-sysroot.sh

# Build user applications (shell, utilities) with custom std
user: sysroot
	RUSTFLAGS="--sysroot=$(CURDIR)/target/sysroot" cargo +nightly build \
		-Zjson-target-spec \
		--package m6-user \
		--target targets/aarch64-unknown-m6.json \
		--release

# Create initrd from system binaries (core system only)
initrd: system
	@mkdir -p target/initrd
	cd target/aarch64-unknown-none/release && \
		tar --format=ustar -cf ../../../target/initrd/INITRD init device-mgr drv-uart-pl011 drv-uart-dw drv-smmu drv-virtio-blk drv-nvme drv-usb-xhci drv-usb-dwc3 drv-usb-hid svc-fat32
	@echo "Created initrd TAR archive ($$(stat -c%s target/initrd/INITRD) bytes)"
	@echo "Contents:"
	@tar -tvf target/initrd/INITRD

# Create initrd with user applications included
initrd-full: system user
	@mkdir -p target/initrd
	@# Copy system binaries
	@cp target/aarch64-unknown-none/release/init target/initrd/
	@cp target/aarch64-unknown-none/release/device-mgr target/initrd/
	@cp target/aarch64-unknown-none/release/drv-uart-pl011 target/initrd/
	@cp target/aarch64-unknown-none/release/drv-uart-dw target/initrd/
	@cp target/aarch64-unknown-none/release/drv-smmu target/initrd/
	@cp target/aarch64-unknown-none/release/drv-virtio-blk target/initrd/
	@cp target/aarch64-unknown-none/release/drv-nvme target/initrd/
	@cp target/aarch64-unknown-none/release/drv-usb-xhci target/initrd/
	@cp target/aarch64-unknown-none/release/drv-usb-dwc3 target/initrd/
	@cp target/aarch64-unknown-none/release/drv-usb-hid target/initrd/
	@cp target/aarch64-unknown-none/release/svc-fat32 target/initrd/
	@# Copy user binaries
	@cp target/aarch64-unknown-m6/release/shell target/initrd/
	@cp target/aarch64-unknown-m6/release/ls target/initrd/
	@cp target/aarch64-unknown-m6/release/cat target/initrd/
	@cp target/aarch64-unknown-m6/release/cp target/initrd/
	@cp target/aarch64-unknown-m6/release/echo target/initrd/
	@cp target/aarch64-unknown-m6/release/mkdir target/initrd/
	@cp target/aarch64-unknown-m6/release/mkfs-fat32 target/initrd/
	@cp target/aarch64-unknown-m6/release/svc-starnix target/initrd/
	@# Bundle the Linux test binaries so svc-starnix can load them from the
	@# initrd (the boot SD is not runtime-readable; see scripts/build-sysroot.sh).
	@# Lay the musl dynamic linker under rootfs/ so dynamic binaries resolve
	@# their PT_INTERP (/lib/ld-musl-aarch64.so.1). svc-starnix seeds every
	@# rootfs/* entry into the Starnix tmpfs at the stripped path before exec.
	@if [ -f linux/ld-musl-aarch64.so.1 ]; then \
	    mkdir -p target/initrd/rootfs/lib; \
	    cp linux/ld-musl-aarch64.so.1 target/initrd/rootfs/lib/ld-musl-aarch64.so.1; \
	    echo "Bundled musl dynamic linker into initrd rootfs/lib"; \
	else \
	    echo "Note: linux/ld-musl-aarch64.so.1 missing; 'linux busybox' will fail to resolve its interpreter"; \
	fi
	@# busybox is dynamically linked (PT_INTERP=/lib/ld-musl-aarch64.so.1); it
	@# resolves its interpreter via the rootfs/lib ld-musl seeded above.
	@# NOTE: init maps the WHOLE initrd into the shell's VSpace as one 4KB frame
	@# cap per page, all held in init's 4096-slot root CNode (see process.rs
	@# map_data_to_child). That budget fits ONE large Linux binary alongside the
	@# system binaries + ld-musl. To ship more, huge-page the initrd mapping
	@# (2 MiB frames -> ~4 caps instead of ~1740).
	@if [ -f linux/busybox ]; then \
	    cp linux/busybox target/initrd/busybox; \
	    echo "Bundled linux/busybox into initrd"; \
	else \
	    echo "Note: linux/busybox not built (run 'make busybox'); 'linux busybox ls' will be unavailable"; \
	fi
	@# Create TAR archive
	cd target/initrd && \
		tar --format=ustar -cf INITRD \
		init device-mgr drv-uart-pl011 drv-uart-dw drv-smmu drv-virtio-blk drv-nvme drv-usb-xhci drv-usb-dwc3 drv-usb-hid svc-fat32 \
		shell ls cat cp echo mkdir mkfs-fat32 svc-starnix \
		$$([ -f busybox ] && echo busybox) \
		$$([ -d rootfs ] && echo rootfs)
	@echo "Created full initrd TAR archive ($$(stat -c%s target/initrd/INITRD) bytes)"
	@echo "Contents:"
	@tar -tvf target/initrd/INITRD

clean:
	cargo clean
	rm -rf target/esp target/esp.img

check:
	cargo check --workspace --exclude m6-user
	@# m6-user needs the custom sysroot
	RUSTFLAGS="--sysroot=$(CURDIR)/target/sysroot" cargo +nightly check \
		-Zjson-target-spec \
		--package m6-user \
		--target targets/aarch64-unknown-m6.json

# M6-authored crates held to the strict clippy bar (-D warnings). The vendored
# Starnix fork (m6-starnix*, m6-linux-uapi, fuchsia/zircon shims) is NOT gated
# here: it tracks upstream Fuchsia (BSD-2-Clause) and must not be churned to
# satisfy our lints. Use `make clippy-fork` to see its warnings informationally.
M6_CRATES := m6-alloc m6-arch m6-boot m6-cap m6-common m6-kernel m6-mmio \
	m6-paging m6-pal m6-std m6-syscall m6-system m6-testlib m6-zx-shim

clippy:
	cargo clippy $(addprefix -p ,$(M6_CRATES)) -- -D warnings
	@# m6-user needs the custom sysroot
	RUSTFLAGS="--sysroot=$(CURDIR)/target/sysroot" cargo +nightly clippy \
		-Zjson-target-spec \
		--package m6-user \
		--target targets/aarch64-unknown-m6.json \
		-- -D warnings

# Informational clippy over the vendored Starnix fork — NOT gated on warnings.
clippy-fork:
	cargo clippy -p m6-starnix

run: #all
	./scripts/run-qemu.sh -device VGA

# Run with user applications included
run-full: boot kernel initrd-full
	./scripts/run-qemu.sh

# Create image without running QEMU
image: all
	./scripts/run-qemu.sh --prepare-only

# SD card / flash device. Override on the command line: make flash DEV=/dev/sdX
DEV ?= /dev/mmcblk0

# Fast incremental flash: mount the bare FAT32 filesystem and copy only the
# changed payload (~3MB) instead of dd'ing the whole 64MB image. Use this for
# day-to-day iteration after a first-time `make flash-full`.
flash: image
	@test -b "$(DEV)" || { echo "Error: $(DEV) is not a block device (set DEV=...)"; exit 1; }
	@MNT=$$(mktemp -d) && \
	  echo "Mounting $(DEV) at $$MNT" && \
	  sudo mount "$(DEV)" "$$MNT" && \
	  trap 'sudo umount "$$MNT"; rmdir "$$MNT"' EXIT && \
	  sudo mkdir -p "$$MNT/EFI/BOOT" "$$MNT/EFI/M6" && \
	  sudo cp target/esp/EFI/BOOT/BOOTAA64.EFI "$$MNT/EFI/BOOT/BOOTAA64.EFI" && \
	  sudo cp target/esp/EFI/M6/KERNEL        "$$MNT/EFI/M6/KERNEL" && \
	  sudo cp target/esp/EFI/M6/INITRD        "$$MNT/EFI/M6/INITRD" && \
	  sync && \
	  echo "Flashed bootloader + kernel + initrd to $(DEV)"

# Full flash: write the entire FAT32 image to the device. Needed the first time
# or whenever the on-disk layout changes. conv=fsync flushes before returning,
# so no separate `sync` is required.
flash-full: image
	@test -b "$(DEV)" || { echo "Error: $(DEV) is not a block device (set DEV=...)"; exit 1; }
	sudo dd if=target/esp.img of="$(DEV)" bs=4M status=progress conv=fsync
	@echo "Flashed full image to $(DEV)"

debug: all
	./scripts/run-qemu.sh -s -S

debug-full: boot kernel initrd-full
	./scripts/run-qemu.sh -s -S

TESTABLE_CRATES = m6-common m6-paging m6-syscall m6-cap m6-alloc

test:
	CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUNNER="$(CURDIR)/scripts/qemu-test.sh" \
	RUSTFLAGS="-C link-arg=--gc-sections -C link-arg=-T$(CURDIR)/m6-testlib/test.ld" \
	cargo test --target aarch64-unknown-none \
	  $(addprefix -p ,$(TESTABLE_CRATES))

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

# -- busybox (dynamically linked aarch64) for `linux busybox ls` under svc-starnix
#
# Fetches + cross-compiles a dynamically-linked PIE busybox into linux/busybox,
# which initrd-full then bundles. Downloads the busybox source on first run.
busybox:
	$(MAKE) -C linux busybox

# -- FAT32 virtio-blk disk image, pre-populated with a Linux binary
#
# Wipes target/disk.img and rebuilds it as a FAT32 volume. If linux/busybox
# exists, it is copied to the root. Run `make busybox` first to make a Linux
# test binary available to svc-starnix at runtime.
#
# Requires: mkfs.vfat, mtools (mcopy).
fat32-image:
	@mkdir -p target
	dd if=/dev/zero of=target/disk.img bs=1M count=64 status=none
	mkfs.vfat -F 32 target/disk.img >/dev/null 2>&1
	@if [ -f linux/busybox ]; then \
	    mcopy -i target/disk.img linux/busybox ::busybox && \
	    printf "FAT32 disk.img populated with linux/busybox (%s bytes)\n" \
	      "$$(stat -c%s linux/busybox)"; \
	else \
	    echo "FAT32 disk.img created empty (run 'make busybox' first)"; \
	fi
