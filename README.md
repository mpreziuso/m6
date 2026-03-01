# m6 Operating System

A capability-based microkernel OS for ARM64, written entirely in Rust.

## What is this?

m6 explores what an operating system looks like when built from scratch for modern ARM64 hardware, without decades of legacy constraints. Inspired by [seL4](https://sel4.systems/)'s security model, m6 implements a minimal kernel that provides only the essentials—memory isolation, capability-based security, IPC, and scheduling—whilst everything else runs in isolated userspace processes.

You can read more about how this project came to be [here](https://medium.com/@mpreziuso/m6-building-an-operating-system-20-years-later-f99022ebcbf3).

## Design philosophy

**Capabilities all the way down.** Every resource access requires an explicit, unforgeable capability. No ambient authority means no confused deputy attacks. If you don't hold the capability, you can't access the resource.

**Trust less, audit less.** The kernel handles exactly four concerns: memory, scheduling, messaging, and capabilities. Drivers, filesystems, and network stacks live in userspace. Smaller kernel surface means fewer attack vectors and a realistic path to formal verification.

**Memory safety without overhead.** Rust's ownership system and type guarantees eliminate entire classes of vulnerabilities at compile time. No garbage collection pauses, no use-after-free, no data races.

**Modern hardware only.** ARM64 with mandatory SMMU for DMA isolation. No x86 baggage, no BIOS, no legacy device support. UEFI-only boot on hardware that matters today.

**Linux compatibility without being Linux.** Run existing ARM64 Linux binaries through a compatibility layer (similar to Fuchsia's [Starnix](https://fuchsia.dev/fuchsia-src/concepts/starnix))—get the application ecosystem with capability security underneath.

## Architecture

m6 uses a microkernel architecture where the kernel provides only mechanisms, never policy. Device drivers, filesystems, and system services run as isolated userspace processes communicating via IPC. The capability system ensures explicit authority grants—there is no ambient authority.

## Platforms

- **QEMU virt** (cortex-a72, GICv3) for development
- **Radxa Rock 5B+** (RK3588 SoC) for real hardware
- Possibly other similar platforms

## Building

```bash
make all    # Build bootloader, kernel, and userspace
make run    # Launch in QEMU
```

## Status

m6 is an experimental research project under active development. The system boots on QEMU and RK3588 hardware with working drivers for UART, NVMe, USB (xHCI/DWC3), and SMMU v3.

## Licence

[MIT](LICENCE)
