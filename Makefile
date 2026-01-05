.PHONY: clean check clippy run debug fmt fmt-check

all: boot kernel

boot:
	cargo build --package m6-boot --target aarch64-unknown-uefi

kernel:
	cargo build --package m6-kernel --target aarch64-unknown-none

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