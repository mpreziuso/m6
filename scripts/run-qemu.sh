#!/bin/bash
# Run m6 in QEMU (ARM64)
#
# Requires:
# - qemu-system-aarch64
# - OVMF/EDK2 firmware for ARM64
# - mtools

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/target"

# QEMU settings
QEMU=qemu-system-aarch64
MEMORY=1G
CPUS=4

# EDK2 firmware paths (try common locations)
FIRMWARE_PATHS=(
    "/usr/share/AAVMF/AAVMF_CODE.fd"
    "/usr/share/edk2/aarch64/QEMU_CODE.fd"
    "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd"
    "/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
)

# Find firmware
FIRMWARE=""
for path in "${FIRMWARE_PATHS[@]}"; do
    if [ -f "$path" ]; then
        FIRMWARE="$path"
        break
    fi
done

if [ -z "$FIRMWARE" ]; then
    echo "Error: Could not find EDK2/OVMF firmware for ARM64"
    echo "Please install qemu-efi-aarch64 or edk2-aarch64"
    echo "Tried paths: ${FIRMWARE_PATHS[*]}"
    exit 1
fi

# Create ESP directory structure
ESP_DIR="$BUILD_DIR/esp"
mkdir -p "$ESP_DIR/EFI/BOOT"
mkdir -p "$ESP_DIR/EFI/M6"

# Copy bootloader and kernel (prefer release, fall back to debug)
BOOTLOADER="$BUILD_DIR/aarch64-unknown-uefi/release/m6-boot.efi"
if [ ! -f "$BOOTLOADER" ]; then
    BOOTLOADER="$BUILD_DIR/aarch64-unknown-uefi/debug/m6-boot.efi"
fi
cp "$BOOTLOADER" "$ESP_DIR/EFI/BOOT/BOOTAA64.EFI"
echo "Copied bootloader to ESP"

KERNEL="$BUILD_DIR/aarch64-unknown-none/release/m6-kernel"
if [ ! -f "$KERNEL" ]; then
    KERNEL="$BUILD_DIR/aarch64-unknown-none/debug/m6-kernel"
fi
cp "$KERNEL" "$ESP_DIR/EFI/M6/KERNEL"
echo "Copied kernel to ESP"

# Copy initrd if available
INITRD="$BUILD_DIR/initrd/INITRD"
if [ -f "$INITRD" ]; then
    cp "$INITRD" "$ESP_DIR/EFI/M6/INITRD"
    echo "Copied initrd to ESP"
fi

# Create FAT filesystem image
ESP_IMG="$BUILD_DIR/esp.img"
dd if=/dev/zero of="$ESP_IMG" bs=1M count=64 2>/dev/null
mkfs.vfat -F 32 "$ESP_IMG" >/dev/null 2>&1 || true

# Copy files to FAT image using mtools
mcopy -i "$ESP_IMG" -s "$ESP_DIR/EFI" ::/ 2>/dev/null || true

echo "Starting QEMU..."
echo "  Firmware: $FIRMWARE"
echo "  Memory: $MEMORY"
echo "  CPUs: $CPUS"
echo ""
echo "Press Ctrl+A, X to exit QEMU"
echo ""

# Create a test disk image if it doesn't exist
DISK_IMG="$BUILD_DIR/disk.img"
if [ ! -f "$DISK_IMG" ]; then
    echo "Creating test disk image..."
    dd if=/dev/zero of="$DISK_IMG" bs=1M count=64 2>/dev/null
    echo "Created $DISK_IMG (64MB)"
fi

# Run QEMU
exec $QEMU \
    -machine virt,gic-version=3,acpi=off,iommu=smmuv3 \
    -cpu cortex-a72 \
    -smp $CPUS \
    -m $MEMORY \
    -drive if=pflash,format=raw,readonly=on,file="$FIRMWARE" \
    -drive format=raw,file="$ESP_IMG" \
    -drive file="$DISK_IMG",if=none,format=raw,id=hd0 \
    -device virtio-blk-device,drive=hd0 \
    -device virtio-gpu-pci \
    -device virtio-keyboard-pci \
    -device virtio-mouse-pci \
    -device virtio-net-pci,netdev=net0 \
    -netdev user,id=net0 \
    -serial stdio \
    -monitor none \
    -nographic \
    "$@"
