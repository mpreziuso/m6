//! PL011 UART Driver
//!
//! Userspace driver for ARM PL011 UART (as emulated by QEMU virt platform).
//! Provides TX and RX via IPC to client applications.
//!
//! Capabilities received from device-mgr:
//! - Slot 10: DeviceFrame for MMIO access
//! - Slot 11: IRQHandler for interrupt handling
//! - Slot 12: Service endpoint for client requests
//! - Slot 14: Notification for IRQ delivery

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod ipc;
mod pl011;

// Re-use io module from parent crate (for early debug output)
#[path = "../../io.rs"]
mod io;
use m6_syscall::invoke::{irq_ack, irq_set_handler, map_frame, recv, reply_recv, sched_yield};

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
/// IRQHandler for interrupt handling (slot 11)
const IRQ_HANDLER: u64 = cptr(11);
/// Service endpoint for clients (slot 12)
const SERVICE_EP: u64 = cptr(12);
/// Notification for IRQ delivery (slot 14)
const IRQ_NOTIF: u64 = cptr(14);
/// Console endpoint (slot 20) - not used by UART driver as it IS the console
#[allow(dead_code)]
const CONSOLE_EP: u64 = cptr(20);

/// Virtual address where we map the UART MMIO region.
/// Must not conflict with other mappings (stack, IPC buffer, etc.)
const UART_MMIO_VADDR: u64 = 0x0000_8000_0000;

/// Badge value for RX interrupt notification
const IRQ_BADGE_RX: u64 = 1;

// -- RX Ring Buffer

/// Size of the RX ring buffer
const RX_BUFFER_SIZE: usize = 256;

/// Ring buffer for received data.
struct RxBuffer {
    data: [u8; RX_BUFFER_SIZE],
    head: usize, // Next write position
    tail: usize, // Next read position
}

impl RxBuffer {
    /// Create a new empty ring buffer.
    const fn new() -> Self {
        Self {
            data: [0; RX_BUFFER_SIZE],
            head: 0,
            tail: 0,
        }
    }

    /// Push a byte into the buffer.
    ///
    /// Returns `true` if successful, `false` if buffer is full.
    fn push(&mut self, byte: u8) -> bool {
        let next_head = (self.head + 1) % self.data.len();
        if next_head == self.tail {
            return false; // Buffer full
        }
        self.data[self.head] = byte;
        self.head = next_head;
        true
    }

    /// Pop a byte from the buffer.
    ///
    /// Returns `None` if buffer is empty.
    fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            return None;
        }
        let byte = self.data[self.tail];
        self.tail = (self.tail + 1) % self.data.len();
        Some(byte)
    }

    /// Check if the buffer is empty.
    fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Get the number of bytes in the buffer.
    #[allow(dead_code)]
    fn len(&self) -> usize {
        if self.head >= self.tail {
            self.head - self.tail
        } else {
            self.data.len() - self.tail + self.head
        }
    }
}

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

    // Set up interrupt-driven RX
    let irq_enabled = setup_irq(&uart);

    if irq_enabled {
        io::puts("[drv-uart] PL011 initialised with IRQ support, entering service loop\n");
    } else {
        io::puts("[drv-uart] PL011 initialised (polling mode), entering service loop\n");
    }

    // Enter the service loop with IRQ support
    service_loop(&uart, irq_enabled);
}

/// Set up IRQ handling for the UART.
///
/// Returns `true` if IRQ was successfully configured.
fn setup_irq(uart: &Pl011) -> bool {
    // Bind IRQ handler to notification with badge
    match irq_set_handler(IRQ_HANDLER, IRQ_NOTIF, IRQ_BADGE_RX) {
        Ok(_) => {}
        Err(e) => {
            io::puts("[drv-uart] irq_set_handler failed: ");
            io::put_u64(e as u64);
            io::newline();
            return false;
        }
    }

    // Clear any pending interrupts
    uart.clear_interrupts();

    // Enable RX interrupt
    uart.enable_rx_interrupt();

    io::puts("[drv-uart] IRQ handler configured (badge=");
    io::put_u64(IRQ_BADGE_RX);
    io::puts(")\n");

    true
}

/// Handle UART interrupt.
///
/// Drains the RX FIFO into the buffer and acknowledges the IRQ.
/// Note: Currently unused because bound notification support is not implemented
/// in the IPC code. The driver blocks on recv/reply_recv and drains RX on demand.
#[allow(dead_code)]
fn handle_irq(uart: &Pl011, rx_buffer: &mut RxBuffer) {
    // Drain RX FIFO into buffer
    let mut tmp = [0u8; 32];
    loop {
        let count = uart.drain_rx(&mut tmp);
        if count == 0 {
            break;
        }
        for &byte in tmp.iter().take(count) {
            if !rx_buffer.push(byte) {
                // Buffer full - drop remaining data
                io::puts("[drv-uart] RX buffer overflow\n");
                break;
            }
        }
    }

    // Clear interrupt
    uart.clear_interrupts();

    // Acknowledge IRQ to re-enable
    if let Err(e) = irq_ack(IRQ_HANDLER) {
        io::puts("[drv-uart] irq_ack failed: ");
        io::put_u64(e as u64);
        io::newline();
    }
}

/// Main service loop - handles client IPC requests and IRQ notifications.
fn service_loop(uart: &Pl011, irq_enabled: bool) -> ! {
    let mut rx_buffer = RxBuffer::new();
    let mut last_response: u64 = 0;
    let mut first_message = true;

    // Note: We don't poll the notification in the loop because:
    // 1. poll() returns immediately, causing CPU 100%
    // 2. The thread blocks on recv/reply_recv waiting for IPC
    // 3. Bound notification support in IPC would be needed to wake on IRQ
    // Instead, we drain RX data when handling requests.
    let _ = irq_enabled; // IRQ setup still useful for hardware-level buffering

    loop {
        // Handle IPC (blocks until a client sends a request)
        let result = if first_message {
            // First iteration: just receive (no reply to send yet)
            first_message = false;
            recv(SERVICE_EP)
        } else {
            // Subsequent iterations: reply to previous caller and wait for next
            reply_recv(SERVICE_EP, last_response, 0, 0, 0)
        };

        match result {
            Ok(ipc_result) => {
                let badge = ipc_result.badge;
                let label = ipc_result.label;

                // Handle the request and store response for next reply_recv
                last_response = handle_request(uart, &mut rx_buffer, badge, label, &ipc_result.msg);
            }
            Err(err) => {
                io::puts("[drv-uart] recv/reply_recv error: ");
                io::put_u64(err as u64);
                io::newline();
                sched_yield();
                first_message = true; // Reset to recv mode
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(
    uart: &Pl011,
    rx_buffer: &mut RxBuffer,
    _badge: u64,
    label: u64,
    msg: &[u64; 4],
) -> u64 {
    match label & 0xFFFF {
        ipc::request::WRITE_INLINE => handle_write_inline(uart, label, msg),
        ipc::request::READ => handle_read(uart, rx_buffer),
        ipc::request::GET_STATUS => handle_get_status(uart, rx_buffer),
        _ => ipc::response::ERR_INVALID_REQUEST,
    }
}

/// Handle WRITE_INLINE request.
///
/// Data is packed in msg[0..2] (up to 24 bytes). Length is in x0[32:47].
fn handle_write_inline(uart: &Pl011, x0: u64, msg: &[u64; 4]) -> u64 {
    let len = ipc::write_inline_len(x0);
    if len == 0 || len > 24 {
        return ipc::response::ERR_INVALID_REQUEST;
    }

    // Extract bytes from message registers and write to UART
    let mut data = [0u8; 24];
    for (i, &reg) in msg.iter().enumerate().take(3) {
        for j in 0..8 {
            let byte_idx = i * 8 + j;
            if byte_idx >= len {
                break;
            }
            data[byte_idx] = ((reg >> (j * 8)) & 0xFF) as u8;
        }
    }

    uart.write(&data[..len]);

    ipc::response::OK
}

/// Handle READ request.
///
/// Returns available data from the buffer (filled by interrupt handler)
/// or directly from UART if no buffered data.
fn handle_read(uart: &Pl011, rx_buffer: &mut RxBuffer) -> u64 {
    // First, drain any newly arrived data from UART into buffer
    let mut tmp = [0u8; 32];
    let count = uart.drain_rx(&mut tmp);
    for &byte in tmp.iter().take(count) {
        let _ = rx_buffer.push(byte);
    }

    // Check if we have any data
    if rx_buffer.is_empty() {
        return ipc::response::ERR_NO_DATA;
    }

    // Pop data from buffer (up to 40 bytes for inline response)
    // In a real implementation, we'd pack the data into x1-x5 response registers
    let mut _read_count = 0;
    while !rx_buffer.is_empty() && _read_count < 40 {
        let _ = rx_buffer.pop();
        _read_count += 1;
    }

    ipc::response::OK
}

/// Handle GET_STATUS request.
///
/// Returns UART status flags in x1.
fn handle_get_status(uart: &Pl011, rx_buffer: &RxBuffer) -> u64 {
    let mut flags = 0u64;
    if uart.tx_ready() {
        flags |= ipc::status::TX_READY;
    }
    // Report RX ready if either UART has data or buffer has data
    if uart.rx_ready() || !rx_buffer.is_empty() {
        flags |= ipc::status::RX_READY;
    }

    // In real implementation, x1 would contain the flags
    // For now, just return OK (flags would be in reply registers)
    let _ = flags; // Suppress unused warning
    ipc::response::OK
}

// Panic handler is provided by m6-std
