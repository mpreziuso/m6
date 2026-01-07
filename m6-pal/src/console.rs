/// Console implementation
/// Provides basic output functionality via a memory-mapped UART
/// for early boot logging.
use core::fmt::{self, Write};

use spin::mutex::SpinMutex;

use crate::{boot_uart::drivers::pl011, current_platform};



struct Console {
    base: u64,
    initialized: bool,
}

impl Console {
    const fn new() -> Self {
        Self {
            base: 0,
            initialized: false,
        }
    }

    fn init(&mut self, base: u64) {
        self.base = base;
        self.initialized = true;
    }

    fn putc(&self, c: u8) {
        if !self.initialized || self.base == 0 {
            return;
        }

        // Wait for TX FIFO to have space
        // SAFETY: We're reading from a known MMIO address
        unsafe {
            let fr_ptr = (self.base + pl011::FR as u64) as *const u32;
            while core::ptr::read_volatile(fr_ptr) & pl011::FR_TXFF != 0 {
                core::hint::spin_loop();
            }

            // Write the character
            let dr_ptr = (self.base + pl011::DR as u64) as *mut u32;
            core::ptr::write_volatile(dr_ptr, c as u32);
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

/// Initialize the early console
pub fn init() {
    if let Some(plat) = current_platform() {
        let mut console = CONSOLE.lock();
        console.init(plat.uart_base());
    }
}

/// Initialize the console with a specific base address
pub fn init_with_base(base: u64) {
    let mut console = CONSOLE.lock();
    console.init(base);
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
