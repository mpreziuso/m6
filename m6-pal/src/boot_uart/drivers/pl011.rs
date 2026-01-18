/// PL011 UART registers
///
/// Data register offset
pub const DR: usize = 0x00;
/// Flag register offset
pub(crate) const FR: usize = 0x18;
/// Flag: Transmit FIFO full
pub const FR_TXFF: u32 = 1 << 5;
/// Flag: Receive FIFO empty
pub const FR_RXFE: u32 = 1 << 4;
