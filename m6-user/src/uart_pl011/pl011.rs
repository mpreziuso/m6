//! PL011 UART register definitions and MMIO operations.
//!
//! This module provides low-level access to the PL011 UART hardware.

use core::ptr::{read_volatile, write_volatile};

// -- PL011 register offsets

/// Data register (read/write)
pub const DR: usize = 0x00;
/// Receive status/error clear register
pub const RSRECR: usize = 0x04;
/// Flag register (read-only)
pub const FR: usize = 0x18;
/// Integer baud rate register
pub const IBRD: usize = 0x24;
/// Fractional baud rate register
pub const FBRD: usize = 0x28;
/// Line control register
pub const LCR_H: usize = 0x2C;
/// Control register
pub const CR: usize = 0x30;
/// Interrupt FIFO level select register
pub const IFLS: usize = 0x34;
/// Interrupt mask set/clear register
pub const IMSC: usize = 0x38;
/// Raw interrupt status register
pub const RIS: usize = 0x3C;
/// Masked interrupt status register
pub const MIS: usize = 0x40;
/// Interrupt clear register
pub const ICR: usize = 0x44;

// -- Flag register bits

/// TX FIFO full
pub const FR_TXFF: u32 = 1 << 5;
/// RX FIFO empty
pub const FR_RXFE: u32 = 1 << 4;
/// UART busy
pub const FR_BUSY: u32 = 1 << 3;

// -- Control register bits

/// UART enable
pub const CR_UARTEN: u32 = 1 << 0;
/// Transmit enable
pub const CR_TXE: u32 = 1 << 8;
/// Receive enable
pub const CR_RXE: u32 = 1 << 9;

// -- Line control register bits

/// Enable FIFOs
pub const LCR_H_FEN: u32 = 1 << 4;
/// Word length 8 bits
pub const LCR_H_WLEN_8: u32 = 3 << 5;

// -- Interrupt mask register bits (IMSC)

/// Receive interrupt mask
pub const IMSC_RXIM: u32 = 1 << 4;
/// Transmit interrupt mask
pub const IMSC_TXIM: u32 = 1 << 5;
/// Receive timeout interrupt mask
pub const IMSC_RTIM: u32 = 1 << 6;

// -- Interrupt clear register bits (ICR)

/// Clear all interrupts
pub const ICR_ALL: u32 = 0x7FF;

/// PL011 UART driver state.
pub struct Pl011 {
    base: usize,
}

impl Pl011 {
    /// Create a new PL011 driver for the given MMIO base address.
    ///
    /// # Safety
    ///
    /// The base address must point to a valid mapped PL011 register region.
    #[inline]
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Initialise the UART.
    ///
    /// QEMU's PL011 is already configured by the firmware, but we
    /// ensure TX and RX are enabled.
    pub fn init(&self) {
        // Read current control register
        let cr = self.read_reg(CR);

        // Ensure UART, TX, and RX are enabled
        if (cr & (CR_UARTEN | CR_TXE | CR_RXE)) != (CR_UARTEN | CR_TXE | CR_RXE) {
            self.write_reg(CR, cr | CR_UARTEN | CR_TXE | CR_RXE);
        }
    }

    /// Check if TX FIFO has space available.
    #[inline]
    pub fn tx_ready(&self) -> bool {
        (self.read_reg(FR) & FR_TXFF) == 0
    }

    /// Check if RX FIFO has data available.
    #[inline]
    pub fn rx_ready(&self) -> bool {
        (self.read_reg(FR) & FR_RXFE) == 0
    }

    /// Transmit a single byte, blocking until space is available.
    pub fn putc(&self, byte: u8) {
        // Wait for TX FIFO space
        while !self.tx_ready() {
            core::hint::spin_loop();
        }

        // Handle CRLF conversion for newlines
        if byte == b'\n' {
            self.write_reg(DR, b'\r' as u32);
            // Wait again for the carriage return to be sent
            while !self.tx_ready() {
                core::hint::spin_loop();
            }
        }

        self.write_reg(DR, byte as u32);
    }

    /// Transmit a string.
    pub fn puts(&self, s: &str) {
        for byte in s.bytes() {
            self.putc(byte);
        }
    }

    /// Try to receive a byte (non-blocking).
    ///
    /// Returns `None` if the RX FIFO is empty.
    pub fn getc(&self) -> Option<u8> {
        if self.rx_ready() {
            Some((self.read_reg(DR) & 0xFF) as u8)
        } else {
            None
        }
    }

    /// Read multiple bytes into a buffer.
    ///
    /// Returns the number of bytes actually read.
    pub fn read(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        for slot in buf.iter_mut() {
            match self.getc() {
                Some(byte) => {
                    *slot = byte;
                    count += 1;
                }
                None => break,
            }
        }
        count
    }

    /// Write multiple bytes from a buffer.
    pub fn write(&self, buf: &[u8]) {
        for &byte in buf {
            self.putc(byte);
        }
    }

    // -- Interrupt control

    /// Enable RX interrupt (and receive timeout).
    ///
    /// When enabled, an interrupt is generated when the RX FIFO reaches
    /// its trigger level or a receive timeout occurs.
    pub fn enable_rx_interrupt(&self) {
        let imsc = self.read_reg(IMSC);
        self.write_reg(IMSC, imsc | IMSC_RXIM | IMSC_RTIM);
    }

    /// Disable RX interrupt.
    pub fn disable_rx_interrupt(&self) {
        let imsc = self.read_reg(IMSC);
        self.write_reg(IMSC, imsc & !(IMSC_RXIM | IMSC_RTIM));
    }

    /// Clear all pending interrupts.
    pub fn clear_interrupts(&self) {
        self.write_reg(ICR, ICR_ALL);
    }

    /// Read masked interrupt status.
    ///
    /// Returns the MIS register value, which indicates which interrupts
    /// are currently active (masked by IMSC).
    #[allow(dead_code)]
    pub fn read_interrupt_status(&self) -> u32 {
        self.read_reg(MIS)
    }

    /// Drain all available RX data into buffer.
    ///
    /// Returns number of bytes read. This is useful for interrupt handlers
    /// to drain the FIFO after receiving an RX interrupt.
    pub fn drain_rx(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        while self.rx_ready() && count < buf.len() {
            buf[count] = (self.read_reg(DR) & 0xFF) as u8;
            count += 1;
        }
        count
    }

    // -- Private helpers

    #[inline]
    fn read_reg(&self, offset: usize) -> u32 {
        // SAFETY: Caller ensures base is valid mapped MMIO
        unsafe { read_volatile((self.base + offset) as *const u32) }
    }

    #[inline]
    fn write_reg(&self, offset: usize, value: u32) {
        // SAFETY: Caller ensures base is valid mapped MMIO
        unsafe { write_volatile((self.base + offset) as *mut u32, value) }
    }
}
