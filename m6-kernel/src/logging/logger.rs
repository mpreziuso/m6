//! Kernel Logging
//!
//! Provides logging infrastructure using the `log` crate.
//!
//! # Log Output
//!
//! Log messages are written to:
//! 1. A lock-free ring buffer (for userspace draining via syscall)
//! 2. Direct console output (during early boot, before UART driver takes over)
//!
//! The panic handler bypasses the ring buffer and writes directly to UART.

use core::fmt::Write;
use log::{Level, LevelFilter, Log, Metadata, Record};
use m6_pal::console;

use crate::logging::buffer::{self, LogEntry};

/// Stack buffer for formatting log messages before pushing to the lock-free queue
struct MessageBuffer {
    data: [u8; buffer::LOG_ENTRY_CONTENT_SIZE],
    len: usize,
}

impl MessageBuffer {
    const fn new() -> Self {
        Self {
            data: [0u8; buffer::LOG_ENTRY_CONTENT_SIZE],
            len: 0,
        }
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.data[..self.len]).unwrap_or("<invalid>")
    }
}

impl Write for MessageBuffer {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let bytes = s.as_bytes();
        let remaining = buffer::LOG_ENTRY_CONTENT_SIZE - self.len;
        let to_copy = bytes.len().min(remaining);
        self.data[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

/// Kernel logger implementation
struct KernelLogger;

impl Log for KernelLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Get timestamp
            let time_ms = m6_pal::timer::now_ms();

            // Format message into stack buffer (no locks!)
            let mut msg_buf = MessageBuffer::new();
            let _ = write!(msg_buf, "{}", record.args());

            // Create log entry
            let entry = LogEntry::new(
                time_ms,
                record.level(),
                record.target(),
                msg_buf.as_str(),
            );

            // Push to lock-free buffer
            buffer::push(entry);

            // Write to console during early boot
            if buffer::early_console_enabled() {
                let level_str = match record.level() {
                    Level::Error => "\x1b[31mERROR\x1b[0m",
                    Level::Warn => "\x1b[33m WARN\x1b[0m",
                    Level::Info => "\x1b[32m INFO\x1b[0m",
                    Level::Debug => "\x1b[34mDEBUG\x1b[0m",
                    Level::Trace => "\x1b[35mTRACE\x1b[0m",
                };

                // Format and write to console
                let mut console_buf = MessageBuffer::new();
                let _ = writeln!(
                    console_buf,
                    "[{:>8}.{:03}] {} {}: {}",
                    time_ms / 1000,
                    time_ms % 1000,
                    level_str,
                    record.target(),
                    msg_buf.as_str()
                );
                console::puts(console_buf.as_str());
            }
        }
    }

    fn flush(&self) {}
}

/// Global logger instance
static LOGGER: KernelLogger = KernelLogger;

/// Initialise the logging system
pub fn init() {
    // Enable the log buffer
    buffer::enable();

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .ok();
}

/// Disable early console output
///
/// Call this when the userspace UART driver has taken over console output.
/// After this, log messages only go to the ring buffer.
pub fn disable_early_console() {
    buffer::disable_early_console();
}

/// Transition from early console to userspace console
///
/// Call this after kernel initialization is complete, right before init runs.
/// This disables early console output and resets the log buffer read position
/// so that init's log drain loop doesn't re-print logs that were already
/// displayed during early boot.
pub fn transition_to_userspace_console() {
    buffer::disable_early_console();
    buffer::reset_read_position();
}

/// Log a message at the specified level (bypasses log crate if not initialised)
pub fn log_raw(level: Level, message: &str) {
    let level_str = match level {
        Level::Error => "[ERROR]",
        Level::Warn => "[WARN ]",
        Level::Info => "[INFO ]",
        Level::Debug => "[DEBUG]",
        Level::Trace => "[TRACE]",
    };

    console::puts(level_str);
    console::puts(" ");
    console::puts(message);
    console::puts("\n");
}

/// Early print before logging is initialised
#[macro_export]
macro_rules! early_print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!(m6_pal::console::ConsoleWriter, $($arg)*);
    }};
}

/// Early println before logging is initialised
#[macro_export]
macro_rules! early_println {
    () => {
        m6_pal::console::puts("\n")
    };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!(m6_pal::console::ConsoleWriter, $($arg)*);
        m6_pal::console::puts("\n");
    }};
}
