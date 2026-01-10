//! PL011 UART Driver
//!
//! Userspace driver for ARM PL011 UART (as emulated by QEMU virt platform).
//! Provides TX and RX via IPC to client applications.
//!
//! Capabilities received from device-mgr:
//! - Slot 10: DeviceFrame for MMIO access
//! - Slot 12: Service endpoint for client requests

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

mod ipc;
mod pl011;

// Re-use io module from parent crate (for early debug output)
#[path = "../io.rs"]
mod io;

use core::panic::PanicInfo;
use m6_syscall::invoke::{map_frame, recv, sched_yield, send};

use pl011::Pl011;

// -- Well-known capability slots (mirroring device_mgr::slots::driver)
// The driver's CSpace has radix 10 (1024 slots).
// CPtrs are formatted as: slot << (64 - radix) = slot << 54

const CNODE_RADIX: u8 = 10;

/// Convert slot number to CPtr.
#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

/// Root VSpace capability (slot 2)
const ROOT_VSPACE: u64 = cptr(2);
/// DeviceFrame for MMIO access (slot 10)
const DEVICE_FRAME: u64 = cptr(10);
/// Service endpoint for clients (slot 12)
const SERVICE_EP: u64 = cptr(12);

/// Virtual address where we map the UART MMIO region.
/// Must not conflict with other mappings (stack, IPC buffer, etc.)
const UART_MMIO_VADDR: u64 = 0x0000_8000_0000;

/// Entry point for PL011 UART driver.
///
/// # Safety
///
/// Must be called only once as the entry point. Device-mgr must have provided
/// the required capabilities in well-known slots.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    io::puts("\n\x1b[35m[drv-uart] Starting PL011 UART driver\x1b[0m\n");

    // Map the DeviceFrame to our address space
    // Rights: RW (0b011), no executable
    match map_frame(ROOT_VSPACE, DEVICE_FRAME, UART_MMIO_VADDR, 0b011, 0) {
        Ok(_) => {
            io::puts("[drv-uart] Mapped MMIO at ");
            io::put_hex(UART_MMIO_VADDR);
            io::newline();
        }
        Err(e) => {
            io::puts("[drv-uart] ERROR: Failed to map MMIO: ");
            io::put_u64(e as u64);
            io::newline();
            loop {
                sched_yield();
            }
        }
    }

    // Create PL011 driver instance
    // SAFETY: We just mapped the device frame to this address
    let uart = unsafe { Pl011::new(UART_MMIO_VADDR as usize) };
    uart.init();

    io::puts("[drv-uart] PL011 initialised, entering service loop\n");

    // Enter the service loop
    service_loop(&uart);
}

/// Main service loop - handles client IPC requests.
fn service_loop(uart: &Pl011) -> ! {
    loop {
        match recv(SERVICE_EP) {
            Ok(ipc_result) => {
                let badge = ipc_result.badge;
                let label = ipc_result.label;

                let response = handle_request(uart, badge, label);

                // Reply to the caller via send on the same endpoint
                if send(SERVICE_EP, response, 0, 0, 0).is_err() {
                    io::puts("[drv-uart] send() failed\n");
                }
            }
            Err(err) => {
                io::puts("[drv-uart] recv() error: ");
                io::put_u64(err as u64);
                io::newline();
                sched_yield();
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(uart: &Pl011, _badge: u64, label: u64) -> u64 {
    match label & 0xFFFF {
        ipc::request::WRITE_INLINE => handle_write_inline(uart, label),
        ipc::request::READ => handle_read(uart),
        ipc::request::GET_STATUS => handle_get_status(uart),
        _ => ipc::response::ERR_INVALID_REQUEST,
    }
}

/// Handle WRITE_INLINE request.
///
/// Data is packed in x1-x5 (up to 40 bytes). Length is in x0[32:47].
fn handle_write_inline(uart: &Pl011, x0: u64) -> u64 {
    let len = ipc::write_inline_len(x0);
    if len == 0 || len > 40 {
        return ipc::response::ERR_INVALID_REQUEST;
    }

    // In a real implementation, we'd read x1-x5 from the IPC message registers
    // For now, this is a placeholder that just acknowledges the write
    // The actual data extraction would look like:
    //
    // let mut data = [0u8; 40];
    // for (i, reg) in [x1, x2, x3, x4, x5].iter().enumerate() {
    //     for j in 0..8 {
    //         let byte_idx = i * 8 + j;
    //         if byte_idx >= len { break; }
    //         data[byte_idx] = ((*reg >> (j * 8)) & 0xFF) as u8;
    //     }
    // }
    // uart.write(&data[..len]);

    ipc::response::OK
}

/// Handle READ request.
///
/// Returns available data inline in x1-x5.
fn handle_read(uart: &Pl011) -> u64 {
    // Try to read available data
    let mut buf = [0u8; 40];
    let count = uart.read(&mut buf);

    if count == 0 {
        return ipc::response::ERR_NO_DATA;
    }

    // In a real implementation, we'd pack the data into x1-x5 response registers
    // and return count in x1
    // For now, just return OK
    ipc::response::OK
}

/// Handle GET_STATUS request.
///
/// Returns UART status flags in x1.
fn handle_get_status(uart: &Pl011) -> u64 {
    let mut flags = 0u64;
    if uart.tx_ready() {
        flags |= ipc::status::TX_READY;
    }
    if uart.rx_ready() {
        flags |= ipc::status::RX_READY;
    }

    // In real implementation, x1 would contain the flags
    // For now, just return OK (flags would be in reply registers)
    ipc::response::OK
}

/// Panic handler.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    io::puts("\n\x1b[31m*** DRV-UART PANIC ***\x1b[0m\n");
    if let Some(location) = info.location() {
        io::puts("  at ");
        io::puts(location.file());
        io::puts(":");
        io::put_u64(location.line() as u64);
        io::newline();
    }
    if let Some(msg) = info.message().as_str() {
        io::puts("  ");
        io::puts(msg);
        io::newline();
    }
    loop {
        sched_yield();
    }
}
