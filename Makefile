.PHONY: clean check clippy run debug fmt fmt-check sysroot system user

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
		--package m6-user \
		--target targets/aarch64-unknown-m6.json \
		--release

# Create initrd from system binaries (core system only)
initrd: system
	@mkdir -p target/initrd
	cd target/aarch64-unknown-none/release && \
		tar --format=ustar -cf ../../../target/initrd/INITRD init device-mgr drv-uart-pl011 drv-uart-dw drv-smmu drv-virtio-blk svc-fat32
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
	@cp target/aarch64-unknown-none/release/svc-fat32 target/initrd/
	@# Copy user binaries
	@cp target/aarch64-unknown-m6/release/shell target/initrd/
	@cp target/aarch64-unknown-m6/release/ls target/initrd/
	@cp target/aarch64-unknown-m6/release/cat target/initrd/
	@cp target/aarch64-unknown-m6/release/cp target/initrd/
	@cp target/aarch64-unknown-m6/release/echo target/initrd/
	@cp target/aarch64-unknown-m6/release/mkdir target/initrd/
	@# Create TAR archive
	cd target/initrd && \
		tar --format=ustar -cf INITRD \
		init device-mgr drv-uart-pl011 drv-uart-dw drv-smmu drv-virtio-blk svc-fat32 \
		shell ls cat cp echo mkdir
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
		--package m6-user \
		--target targets/aarch64-unknown-m6.json

clippy:
	cargo clippy --workspace --exclude m6-user -- -D warnings
	@# m6-user needs the custom sysroot
	RUSTFLAGS="--sysroot=$(CURDIR)/target/sysroot" cargo +nightly clippy \
		--package m6-user \
		--target targets/aarch64-unknown-m6.json \
		-- -D warnings

run: all
	./scripts/run-qemu.sh

# Run with user applications included
run-full: boot kernel initrd-full
	./scripts/run-qemu.sh

debug: all
	./scripts/run-qemu.sh -s -S

debug-full: boot kernel initrd-full
	./scripts/run-qemu.sh -s -S

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check
