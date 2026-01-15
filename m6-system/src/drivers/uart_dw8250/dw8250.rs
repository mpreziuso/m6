//! DesignWare 8250 UART register definitions and MMIO operations.
//!
//! This module provides low-level access to the Synopsys DesignWare 8250 UART
//! hardware, commonly found on Rockchip RK3588 and similar SoCs.

use core::ptr::{read_volatile, write_volatile};

// -- Standard 8250 register offsets (4-byte stride)

/// Receive Buffer Register / Transmit Holding Register (read/write)
pub const RBR_THR: usize = 0x00;
/// Interrupt Enable Register
pub const IER: usize = 0x04;
/// Interrupt Identity Register / FIFO Control Register
pub const IIR_FCR: usize = 0x08;
/// Line Control Register
pub const LCR: usize = 0x0c;
/// Modem Control Register
#[expect(dead_code)]
pub const MCR: usize = 0x10;
/// Line Status Register (read-only)
pub const LSR: usize = 0x14;
/// Modem Status Register
#[expect(dead_code)]
pub const MSR: usize = 0x18;
/// Scratch Register
#[expect(dead_code)]
pub const SCR: usize = 0x1c;
/// UART Status Register (DesignWare-specific)
pub const USR: usize = 0x7c;

// -- Line Status Register bits

/// Data Ready - RX data available
pub const LSR_DR: u32 = 1 << 0;
/// Overrun Error
#[expect(dead_code)]
pub const LSR_OE: u32 = 1 << 1;
/// Parity Error
#[expect(dead_code)]
pub const LSR_PE: u32 = 1 << 2;
/// Framing Error
#[expect(dead_code)]
pub const LSR_FE: u32 = 1 << 3;
/// Break Interrupt
#[expect(dead_code)]
pub const LSR_BI: u32 = 1 << 4;
/// Transmit Holding Register Empty
pub const LSR_THRE: u32 = 1 << 5;
/// Transmitter Empty
#[expect(dead_code)]
pub const LSR_TEMT: u32 = 1 << 6;
/// RX FIFO Error
#[expect(dead_code)]
pub const LSR_FIFO_ERR: u32 = 1 << 7;

// -- Interrupt Enable Register bits

/// Enable Received Data Available Interrupt
pub const IER_ERBFI: u32 = 1 << 0;
/// Enable Transmitter Holding Register Empty Interrupt
#[expect(dead_code)]
pub const IER_ETBEI: u32 = 1 << 1;
/// Enable Receiver Line Status Interrupt
pub const IER_ELSI: u32 = 1 << 2;
/// Enable Modem Status Interrupt
#[expect(dead_code)]
pub const IER_EDSSI: u32 = 1 << 3;

// -- FIFO Control Register bits

/// Enable FIFOs
pub const FCR_FIFOE: u32 = 1 << 0;
/// Reset RX FIFO
pub const FCR_RFIFOR: u32 = 1 << 1;
/// Reset TX FIFO
pub const FCR_XFIFOR: u32 = 1 << 2;
/// RX Trigger Level: 1 byte
pub const FCR_RT_1: u32 = 0 << 6;

// -- Line Control Register bits

/// Word Length Select: 8 bits
pub const LCR_WLS_8: u32 = 0b11;
/// Stop Bits: 1 stop bit
#[expect(dead_code)]
pub const LCR_STB_1: u32 = 0 << 2;

// -- UART Status Register bits (DW-specific)

/// UART Busy
pub const USR_BUSY: u32 = 1 << 0;

/// DesignWare 8250 UART driver state.
pub struct Dw8250 {
    base: usize,
}

#[expect(dead_code)]
impl Dw8250 {
    /// Create a new DW8250 driver for the given MMIO base address.
    ///
    /// # Safety
    ///
    /// The base address must point to a valid mapped DW8250 register region.
    #[inline]
    pub const unsafe fn new(base: usize) -> Self {
        Self { base }
    }

    /// Initialise the UART.
    ///
    /// Assumes bootloader/firmware has already configured baud rate.
    /// We enable FIFOs and ensure 8N1 mode.
    pub fn init(&self) {
        // Wait for UART to be idle before configuration
        self.wait_idle();

        // Enable FIFOs, clear them, set RX trigger to 1 byte
        self.write_reg(IIR_FCR, FCR_FIFOE | FCR_RFIFOR | FCR_XFIFOR | FCR_RT_1);

        // Ensure 8N1 configuration (8 data bits, no parity, 1 stop bit)
        // Don't touch DLAB as we're not changing baud rate
        let lcr = self.read_reg(LCR);
        if (lcr & 0x3f) != LCR_WLS_8 {
            self.wait_idle();
            self.write_reg(LCR, LCR_WLS_8);
        }
    }

    /// Check if TX FIFO has space available.
    #[inline]
    pub fn tx_ready(&self) -> bool {
        (self.read_reg(LSR) & LSR_THRE) != 0
    }

    /// Check if RX FIFO has data available.
    #[inline]
    pub fn rx_ready(&self) -> bool {
        (self.read_reg(LSR) & LSR_DR) != 0
    }

    /// Transmit a single byte, blocking until space is available.
    pub fn putc(&self, byte: u8) {
        // Wait for TX FIFO space
        while !self.tx_ready() {
            core::hint::spin_loop();
        }

        // Handle CRLF conversion for newlines
        if byte == b'\n' {
            self.write_reg(RBR_THR, b'\r' as u32);
            // Wait again for the carriage return to be sent
            while !self.tx_ready() {
                core::hint::spin_loop();
            }
        }

        self.write_reg(RBR_THR, byte as u32);
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
            Some((self.read_reg(RBR_THR) & 0xff) as u8)
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

    /// Enable RX interrupt (and receiver line status interrupt).
    pub fn enable_rx_interrupt(&self) {
        let ier = self.read_reg(IER);
        self.write_reg(IER, ier | IER_ERBFI | IER_ELSI);
    }

    /// Disable RX interrupt.
    pub fn disable_rx_interrupt(&self) {
        let ier = self.read_reg(IER);
        self.write_reg(IER, ier & !(IER_ERBFI | IER_ELSI));
    }

    /// Clear pending interrupts by reading IIR.
    ///
    /// For the 8250, reading IIR clears the TX interrupt. RX interrupts
    /// are cleared by reading the RX data (done via drain_rx).
    pub fn clear_interrupts(&self) {
        // Reading IIR clears TX interrupt
        let _ = self.read_reg(IIR_FCR);
    }

    /// Drain all available RX data into buffer.
    ///
    /// Returns number of bytes read. This is useful for interrupt handlers
    /// to drain the FIFO after receiving an RX interrupt.
    pub fn drain_rx(&self, buf: &mut [u8]) -> usize {
        let mut count = 0;
        while self.rx_ready() && count < buf.len() {
            buf[count] = (self.read_reg(RBR_THR) & 0xff) as u8;
            count += 1;
        }
        count
    }

    /// Check if UART is busy (DW-specific).
    ///
    /// The busy flag indicates the UART is processing a character.
    /// Some operations (like LCR writes) must wait for !busy.
    #[inline]
    pub fn is_busy(&self) -> bool {
        (self.read_reg(USR) & USR_BUSY) != 0
    }

    /// Wait for UART to become idle.
    pub fn wait_idle(&self) {
        while self.is_busy() {
            core::hint::spin_loop();
        }
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
