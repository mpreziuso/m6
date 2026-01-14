.PHONY: clean check clippy run debug fmt fmt-check

all: boot kernel initrd

boot:
	cargo build --package m6-boot --target aarch64-unknown-uefi --release

kernel:
	cargo build --package m6-kernel --target aarch64-unknown-none --release

# Build system components (init, device-mgr, drivers, services)
system:
	cargo build --package m6-system --target aarch64-unknown-none --release

# Build user applications (shell, utilities)
user:
	cargo build --package m6-user --target aarch64-unknown-none --release

# Create initrd from system binaries (core system only)
initrd: system
	@mkdir -p target/initrd
	cd target/aarch64-unknown-none/release && \
		tar --format=ustar -cf ../../../target/initrd/INITRD init device-mgr drv-uart-pl011 drv-smmu drv-virtio-blk svc-fat32
	@echo "Created initrd TAR archive ($$(stat -c%s target/initrd/INITRD) bytes)"
	@echo "Contents:"
	@tar -tvf target/initrd/INITRD

# Create initrd with user applications included
initrd-full: system user
	@mkdir -p target/initrd
	cd target/aarch64-unknown-none/release && \
		tar --format=ustar -cf ../../../target/initrd/INITRD \
		init device-mgr drv-uart-pl011 drv-smmu drv-virtio-blk svc-fat32 \
		shell ls cat cp echo mkdir
	@echo "Created full initrd TAR archive ($$(stat -c%s target/initrd/INITRD) bytes)"
	@echo "Contents:"
	@tar -tvf target/initrd/INITRD

clean:
	cargo clean
	rm -rf target/esp target/esp.img

check:
	cargo check --workspace

clippy:
	cargo clippy --workspace -- -D warnings

run: all
	./scripts/run-qemu.sh

debug: all
	./scripts/run-qemu.sh -s -S

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check
