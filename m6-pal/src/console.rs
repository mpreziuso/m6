//! Console implementation
//!
//! Provides basic output functionality via a memory-mapped UART
//! for early boot logging. Supports both ARM PL011 and DesignWare 8250 UARTs.

use core::fmt::{self, Write};

use spin::mutex::SpinMutex;

use crate::boot_uart::drivers::{dw8250, pl011};
use crate::current_platform;
use crate::dtb_platform::UartType;

struct Console {
    base: u64,
    uart_type: UartType,
    initialised: bool,
}

impl Console {
    const fn new() -> Self {
        Self {
            base: 0,
            uart_type: UartType::Unknown,
            initialised: false,
        }
    }

    fn init(&mut self, base: u64, uart_type: UartType) {
        self.base = base;
        self.uart_type = uart_type;
        self.initialised = true;
    }

    fn putc(&self, c: u8) {
        if !self.initialised || self.base == 0 {
            return;
        }

        match self.uart_type {
            UartType::Pl011 => {
                // SAFETY: We're reading/writing from a known MMIO address
                unsafe {
                    let fr_ptr = (self.base + pl011::FR as u64) as *const u32;
                    while core::ptr::read_volatile(fr_ptr) & pl011::FR_TXFF != 0 {
                        core::hint::spin_loop();
                    }
                    let dr_ptr = (self.base + pl011::DR as u64) as *mut u32;
                    core::ptr::write_volatile(dr_ptr, c as u32);
                }
            }
            UartType::Dw8250 => {
                // SAFETY: We're reading/writing from a known MMIO address
                unsafe {
                    let lsr_ptr = (self.base + dw8250::LSR as u64) as *const u32;
                    while core::ptr::read_volatile(lsr_ptr) & dw8250::LSR_THRE == 0 {
                        core::hint::spin_loop();
                    }
                    let thr_ptr = (self.base + dw8250::THR as u64) as *mut u32;
                    core::ptr::write_volatile(thr_ptr, c as u32);
                }
            }
            UartType::Unknown => {
                // Cannot output without knowing UART type
            }
        }
    }

    fn puts(&self, s: &str) {
        for c in s.bytes() {
            if c == b'\n' {
                self.putc(b'\r');
            }
            self.putc(c);
        }
    }
}

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.puts(s);
        Ok(())
    }
}

/// Global console instance
static CONSOLE: SpinMutex<Console> = SpinMutex::new(Console::new());

/// Initialise the early console
pub fn init() {
    if let Some(plat) = current_platform() {
        let mut console = CONSOLE.lock();
        console.init(plat.uart_base(), plat.uart_type());
    }
}

/// Initialise the console with a specific base address and UART type
pub fn init_with_base(base: u64, uart_type: UartType) {
    let mut console = CONSOLE.lock();
    console.init(base, uart_type);
}

/// Print a string to the console
pub fn puts(s: &str) {
    let console = CONSOLE.lock();
    console.puts(s);
}

/// Print a character to the console
pub fn putc(c: u8) {
    let console = CONSOLE.lock();
    console.putc(c);
}

/// Console writer for fmt::Write
pub struct ConsoleWriter;

impl Write for ConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        puts(s);
        Ok(())
    }
}

/// Print formatted output to the console
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::console::ConsoleWriter, $($arg)*);
    }};
}

/// Print formatted output with newline to the console
#[macro_export]
macro_rules! println {
    () => {
        $crate::console::puts("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::console::ConsoleWriter, $($arg)*);
        $crate::console::puts("\n");
    }};
}
