.PHONY: clean check clippy run debug fmt fmt-check

all: boot kernel initrd

boot:
	cargo build --package m6-boot --target aarch64-unknown-uefi --release

kernel:
	cargo build --package m6-kernel --target aarch64-unknown-none --release

user:
	cargo build --package m6-user --target aarch64-unknown-none --release

initrd: user
	@mkdir -p target/initrd
	cd target/aarch64-unknown-none/release && \
		tar --format=ustar -cf ../../../target/initrd/INITRD init device-mgr drv-uart-pl011
	@echo "Created initrd TAR archive ($$(stat -c%s target/initrd/INITRD) bytes)"
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
