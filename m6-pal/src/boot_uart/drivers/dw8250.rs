//! DesignWare 8250 UART register definitions (polled mode for boot console)
//!
//! This module provides register offsets and flag definitions for the
//! Synopsys DesignWare 8250 UART, commonly found on Rockchip RK3588 and
//! similar SoCs.

// -- Standard 8250 register offsets (4-byte stride)

/// Receive Buffer Register / Transmit Holding Register (read/write)
pub const THR: usize = 0x00;

/// Line Status Register (read-only)
pub const LSR: usize = 0x14;

// -- Line Status Register bits

/// Data Ready - RX data available
pub const LSR_DR: u32 = 1 << 0;

/// Transmit Holding Register Empty - TX ready for new data
pub const LSR_THRE: u32 = 1 << 5;

/// Transmitter Empty - TX shift register empty
pub const LSR_TEMT: u32 = 1 << 6;

// -- DesignWare-specific registers

/// UART Status Register (DW-specific)
pub const USR: usize = 0x7c;

/// USR bit: UART Busy
pub const USR_BUSY: u32 = 1 << 0;
