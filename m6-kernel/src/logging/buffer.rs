//! Kernel Log Ring Buffer
//!
//! Stores kernel log messages in a lock-free ring buffer for userspace draining.
//! The panic handler bypasses this and writes directly to UART.
//!
//! # Design
//!
//! - Lock-free MPMC queue using thingbuf
//! - 256 fixed-size log entry slots (256 bytes each = 64KB total)
//! - Interrupt-safe: no locks, safe to call from any context
//! - Overflow drops new messages (returns Full)

use core::sync::atomic::{AtomicBool, Ordering};

use thingbuf::StaticThingBuf;

/// Maximum size of a single log entry's content (target + message)
pub const LOG_ENTRY_CONTENT_SIZE: usize = 240;

/// Number of log entry slots in the buffer
pub const LOG_BUFFER_SLOTS: usize = 256;

/// A single log entry with fixed-size storage
#[derive(Clone)]
pub struct LogEntry {
    /// Timestamp in milliseconds since boot
    pub timestamp_ms: u64,
    /// Log level (0=Error, 1=Warn, 2=Info, 3=Debug, 4=Trace)
    pub level: u8,
    /// Length of the target string
    pub target_len: u8,
    /// Length of the message
    pub message_len: u16,
    /// Combined target + message content
    /// Layout: [target bytes][message bytes]
    pub content: [u8; LOG_ENTRY_CONTENT_SIZE],
}

impl Default for LogEntry {
    fn default() -> Self {
        Self {
            timestamp_ms: 0,
            level: 0,
            target_len: 0,
            message_len: 0,
            content: [0u8; LOG_ENTRY_CONTENT_SIZE],
        }
    }
}

impl LogEntry {
    /// Create a new log entry
    pub fn new(timestamp_ms: u64, level: log::Level, target: &str, message: &str) -> Self {
        let mut entry = Self {
            timestamp_ms,
            level: level_to_u8(level),
            target_len: 0,
            message_len: 0,
            content: [0u8; LOG_ENTRY_CONTENT_SIZE],
        };

        // Copy target (truncate if needed)
        let target_bytes = target.as_bytes();
        let target_len = target_bytes.len().min(255); // Max u8
        entry.content[..target_len].copy_from_slice(&target_bytes[..target_len]);
        entry.target_len = target_len as u8;

        // Copy message (truncate if needed)
        let message_bytes = message.as_bytes();
        let remaining = LOG_ENTRY_CONTENT_SIZE - target_len;
        let message_len = message_bytes.len().min(remaining);
        entry.content[target_len..target_len + message_len]
            .copy_from_slice(&message_bytes[..message_len]);
        entry.message_len = message_len as u16;

        entry
    }

    /// Get the target string
    pub fn target(&self) -> &str {
        let len = self.target_len as usize;
        core::str::from_utf8(&self.content[..len]).unwrap_or("<invalid>")
    }

    /// Get the message string
    pub fn message(&self) -> &str {
        let target_len = self.target_len as usize;
        let message_len = self.message_len as usize;
        core::str::from_utf8(&self.content[target_len..target_len + message_len])
            .unwrap_or("<invalid>")
    }
}

fn level_to_u8(level: log::Level) -> u8 {
    match level {
        log::Level::Error => 0,
        log::Level::Warn => 1,
        log::Level::Info => 2,
        log::Level::Debug => 3,
        log::Level::Trace => 4,
    }
}

/// Convert u8 back to log level
pub fn u8_to_level(val: u8) -> log::Level {
    match val {
        0 => log::Level::Error,
        1 => log::Level::Warn,
        2 => log::Level::Info,
        3 => log::Level::Debug,
        _ => log::Level::Trace,
    }
}

/// Lock-free log buffer using thingbuf
static LOG_BUFFER: StaticThingBuf<LogEntry, LOG_BUFFER_SLOTS> = StaticThingBuf::new();

static EARLY_CONSOLE_ENABLED: AtomicBool = AtomicBool::new(true);
static BUFFER_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enable the log buffer
pub fn enable() {
    BUFFER_ENABLED.store(true, Ordering::Release);
}

/// Disable early console output
pub fn disable_early_console() {
    EARLY_CONSOLE_ENABLED.store(false, Ordering::Release);
}

/// Check if early console is enabled
pub fn early_console_enabled() -> bool {
    EARLY_CONSOLE_ENABLED.load(Ordering::Acquire)
}

/// Push a log entry to the buffer
///
/// This is lock-free and interrupt-safe.
/// Returns true if the entry was queued, false if the buffer is full.
pub fn push(entry: LogEntry) -> bool {
    if !BUFFER_ENABLED.load(Ordering::Acquire) {
        return false;
    }

    LOG_BUFFER.push(entry).is_ok()
}

/// Pop a log entry from the buffer
///
/// This is lock-free and interrupt-safe.
/// Returns None if the buffer is empty.
pub fn pop() -> Option<LogEntry> {
    if !BUFFER_ENABLED.load(Ordering::Acquire) {
        return None;
    }

    LOG_BUFFER.pop()
}

/// Get the number of entries available for draining
pub fn available() -> usize {
    if !BUFFER_ENABLED.load(Ordering::Acquire) {
        return 0;
    }

    LOG_BUFFER.len()
}

/// Check if the buffer is empty
pub fn is_empty() -> bool {
    LOG_BUFFER.is_empty()
}

/// Get the buffer capacity
pub fn capacity() -> usize {
    LOG_BUFFER.capacity()
}

/// Drain entries into a byte buffer (for syscall compatibility)
///
/// Formats each log entry and writes it to the output buffer.
/// Returns the number of bytes written.
pub fn drain(out: &mut [u8]) -> usize {
    if !BUFFER_ENABLED.load(Ordering::Acquire) {
        return 0;
    }

    let mut written = 0;

    while let Some(entry) = LOG_BUFFER.pop() {
        // Format: "[LEVEL] target: message\n"
        let level_str = match entry.level {
            0 => "[ERROR]",
            1 => "[WARN ]",
            2 => "[INFO ]",
            3 => "[DEBUG]",
            _ => "[TRACE]",
        };

        let target = entry.target();
        let message = entry.message();

        // Calculate required space
        let needed = level_str.len() + 1 + target.len() + 2 + message.len() + 1;

        if written + needed > out.len() {
            // Can't fit this entry, stop draining
            // Note: entry is lost since we already popped it
            // TODO: Consider a peek-then-pop pattern
            break;
        }

        // Write formatted entry
        let start = written;
        out[start..start + level_str.len()].copy_from_slice(level_str.as_bytes());
        written += level_str.len();

        out[written] = b' ';
        written += 1;

        out[written..written + target.len()].copy_from_slice(target.as_bytes());
        written += target.len();

        out[written..written + 2].copy_from_slice(b": ");
        written += 2;

        out[written..written + message.len()].copy_from_slice(message.as_bytes());
        written += message.len();

        out[written] = b'\n';
        written += 1;
    }

    written
}

/// Clear all entries from the buffer
///
/// Call this after early console is disabled to prevent re-draining
/// logs that were already printed during early boot.
pub fn reset_read_position() {
    if !BUFFER_ENABLED.load(Ordering::Acquire) {
        return;
    }

    // Drain all entries without processing them
    while LOG_BUFFER.pop().is_some() {}
}

/// Statistics about the log buffer
#[derive(Debug, Clone, Copy)]
pub struct LogBufferStats {
    /// Number of entries currently in the buffer
    pub entries: usize,
    /// Total capacity
    pub capacity: usize,
}

/// Get log buffer statistics
pub fn stats() -> LogBufferStats {
    LogBufferStats {
        entries: LOG_BUFFER.len(),
        capacity: LOG_BUFFER.capacity(),
    }
}
