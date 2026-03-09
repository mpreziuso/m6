#!/bin/sh
# Minimal QEMU runner for bare-metal test ELFs (aarch64-unknown-none).
# Invoked by cargo as CARGO_TARGET_AARCH64_UNKNOWN_NONE_RUNNER.
set -e
exec qemu-system-aarch64 \
    -machine virt \
    -cpu cortex-a72 \
    -m 64M \
    -nographic \
    -semihosting-config enable=on,target=native \
    -kernel "$1"
