//! Shared userspace logger for M6 system services.
//!
//! Produces log output matching the kernel format:
//! `[{secs}.{ms}] {LEVEL} {service}: {message}`
//!
//! Timestamps are read directly from the ARM generic timer (CNTVCT_EL0),
//! which the kernel exposes to EL0 via CNTKCTL_EL1.

use core::fmt::Write;
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::io;

// -- Service name storage (set once at init)

static NAME_PTR: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static NAME_LEN: AtomicUsize = AtomicUsize::new(0);

fn service_name() -> &'static str {
    let ptr = NAME_PTR.load(Ordering::Relaxed);
    let len = NAME_LEN.load(Ordering::Relaxed);
    if ptr.is_null() || len == 0 {
        "unknown"
    } else {
        // SAFETY: ptr points into a &'static str literal stored by init().
        unsafe { core::str::from_utf8_unchecked(core::slice::from_raw_parts(ptr, len)) }
    }
}

// -- Timestamp

fn uptime_ms() -> u64 {
    let count: u64;
    let freq: u64;
    // SAFETY: CNTVCT_EL0 and CNTFRQ_EL0 are accessible from EL0 — the kernel
    // enables this by setting CNTKCTL_EL1.{EL0PCTEN, EL0VCTEN}.
    unsafe {
        core::arch::asm!("mrs {}, cntvct_el0", out(reg) count, options(nostack, nomem, preserves_flags));
        core::arch::asm!("mrs {}, cntfrq_el0", out(reg) freq, options(nostack, nomem, preserves_flags));
    }
    if freq == 0 {
        return 0;
    }
    let secs = count / freq;
    let frac = count % freq;
    secs * 1000 + (frac * 1000) / freq
}

// -- Logger implementation

struct ServiceLogger;

impl Log for ServiceLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let time_ms = uptime_ms();
        let level_str = match record.level() {
            Level::Error => "\x1b[31mERROR\x1b[0m",
            Level::Warn => "\x1b[33m WARN\x1b[0m",
            Level::Info => "\x1b[32m INFO\x1b[0m",
            Level::Debug => "\x1b[34mDEBUG\x1b[0m",
            Level::Trace => "\x1b[35mTRACE\x1b[0m",
        };

        let mut buf = MessageBuffer::new();
        let _ = writeln!(
            buf,
            "[{:>8}.{:03}] {} {}: {}",
            time_ms / 1000,
            time_ms % 1000,
            level_str,
            service_name(),
            record.args()
        );
        io::puts(buf.as_str());
    }

    fn flush(&self) {}
}

// -- Format buffer

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
        let remaining = self.data.len() - self.len;
        let to_copy = bytes.len().min(remaining);
        self.data[self.len..self.len + to_copy].copy_from_slice(&bytes[..to_copy]);
        self.len += to_copy;
        Ok(())
    }
}

static LOGGER: ServiceLogger = ServiceLogger;

/// Initialise the userspace logger.
///
/// `name` must be a `&'static str` (string literal). It is stored by pointer
/// and used as the service identifier in every log line.
pub fn init(name: &'static str) {
    NAME_PTR.store(name.as_ptr() as *mut u8, Ordering::Relaxed);
    NAME_LEN.store(name.len(), Ordering::Relaxed);

    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Debug))
        .ok();
}
