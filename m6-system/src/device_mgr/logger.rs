//! Simple logger for userspace services
//!
//! Provides logging using the `log` crate, with output going through
//! the console I/O module.

use core::fmt::Write;
use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::io;

/// Simple userspace logger
struct SimpleLogger;

impl Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let level_color = match record.level() {
                Level::Error => "\x1b[31m",
                Level::Warn => "\x1b[33m",
                Level::Info => "\x1b[34m",
                Level::Debug => "\x1b[36m",
                Level::Trace => "\x1b[35m",
            };

            let level_str = match record.level() {
                Level::Error => "ERROR",
                Level::Warn => "WARN ",
                Level::Info => "INFO ",
                Level::Debug => "DEBUG",
                Level::Trace => "TRACE",
            };

            // Write log prefix with color
            io::puts(level_color);
            io::puts("[device-mgr] ");
            io::puts(level_str);
            io::puts("\x1b[0m ");

            // Write message
            let mut buffer = MessageBuffer::new();
            let _ = write!(buffer, "{}", record.args());
            io::puts(buffer.as_str());
            io::newline();
        }
    }

    fn flush(&self) {}
}

/// Buffer for formatting log messages
struct MessageBuffer {
    data: [u8; 512],
    len: usize,
}

impl MessageBuffer {
    fn new() -> Self {
        Self {
            data: [0u8; 512],
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
        let remaining = 512 - self.len;
        let to_copy = bytes.len().min(remaining);
        self.data[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

static LOGGER: SimpleLogger = SimpleLogger;

/// Initialize the logger
pub fn init() {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .ok();
}
