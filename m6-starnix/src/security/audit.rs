// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Audit logging framework.
//!
//! The full audit framework is coupled to the netlink audit socket
//! (`crate::vfs::socket::AuditNetlinkClient`), which is only compiled under the
//! `fuchsia` feature. The non-gated surface exposes just enough for kernel
//! components (e.g. seccomp) to emit audit records to the log; the netlink sink,
//! backlog management and `AUDIT_*` netlink request handling are gated.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use linux_uapi::AUDIT_FAIL_PRINTK;
use starnix_logging::log_warn;
use starnix_sync::Mutex;
use m6_starnix_std::collections::VecDeque;
use m6_starnix_std::fmt::Display;
use m6_starnix_std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use crate::task::{ArgNameAndValue, Kernel};

const DEFAULT_BACKLOG_LIMIT: u32 = 128;

/// Possible modes of the audit framework.
#[derive(PartialEq)]
enum AuditMode {
    Disabled,
    Unspecified,
    Enabled,
}

/// Audit status structure defining the behaviour of the logger.
struct AuditConfig {
    /// The audit mode set by kernel command line.
    audit_mode: AuditMode,
    /// The maximum number of audit messages that can be stored by the logger.
    backlog_limit: AtomicU32,
    /// Action to take in case of audit failure.
    fail_action: AtomicU8,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            audit_mode: AuditMode::Unspecified,
            backlog_limit: AtomicU32::new(DEFAULT_BACKLOG_LIMIT),
            fail_action: AtomicU8::new(AUDIT_FAIL_PRINTK as u8),
        }
    }
}

impl AuditConfig {
    pub fn new<'a>(cmdline_iter: impl Iterator<Item = ArgNameAndValue<'a>>) -> Self {
        let mut config = Self::default();
        // The logger may be disabled by the kernel command line.
        config.apply_kernel_cmdline(cmdline_iter);
        config
    }

    /// Function to apply the optional kernel command line arguments.
    fn apply_kernel_cmdline<'a>(
        &mut self,
        cmdline_iter: impl Iterator<Item = ArgNameAndValue<'a>>,
    ) {
        for arg in cmdline_iter {
            match arg {
                ArgNameAndValue { name: "audit", value: Some(value) } => match value {
                    "0" | "off" => self.audit_mode = AuditMode::Disabled,
                    // If the audit option is "1"/"on"/anything else, fully enable auditing.
                    _ => self.audit_mode = AuditMode::Enabled,
                },
                ArgNameAndValue { name: "audit_backlog_limit", value: Some(value) } => self
                    .backlog_limit
                    .store(value.parse().unwrap_or(DEFAULT_BACKLOG_LIMIT), Ordering::Release),
                _ => (),
            }
        }
    }
}

/// Audit logging structure.
pub struct AuditLogger {
    /// Audit status structure.
    configuration: AuditConfig,
    /// The number of audit messages lost due to writing errors.
    lost_audit_messages: AtomicU32,
    /// Audit message deque containing recorded messages up to `backlog_limit`.
    audit_queue: Mutex<VecDeque<AuditMessage>>,
}

impl AuditLogger {
    pub fn new(kernel: &Kernel) -> Self {
        Self {
            configuration: AuditConfig::new(kernel.cmdline_args_iter()),
            lost_audit_messages: Default::default(),
            audit_queue: Default::default(),
        }
    }

    pub fn is_disabled(&self) -> bool {
        self.configuration.audit_mode == AuditMode::Disabled
    }

    /// Audit logging function that records an audit message.
    ///
    /// The `audit_formatter` function is called only if auditing is enabled. With no audit sink
    /// attached the record is written to the kernel log and pushed to the backlog.
    pub fn audit_log<M: Display, T: FnOnce() -> M>(&self, audit_type: u16, audit_formatter: T) {
        if self.configuration.audit_mode == AuditMode::Disabled {
            return;
        }
        let message = format!("{}", audit_formatter());
        log_warn!("audit: type={audit_type} msg={message}");
        if self.configuration.audit_mode == AuditMode::Enabled {
            self.push_back_audit(audit_type, message);
        }
    }

    /// Push the audit message in the backlog after checking its limit.
    fn push_back_audit(&self, audit_type: u16, audit_message: String) {
        let mut queue = self.audit_queue.lock();
        if self.check_backlog(queue.len() as u32) {
            return;
        }
        queue.push_back(AuditMessage { audit_type, message: audit_message.into() });
    }

    /// Function to check the backlog size against the backlog limit.
    /// If the limit is set to 0, ignore the check.
    ///
    /// Return true if the limit is reached, false otherwise.
    fn check_backlog(&self, backlog_size: u32) -> bool {
        let limit = self.configuration.backlog_limit.load(Ordering::Acquire);
        if limit != 0 && backlog_size >= limit {
            let lost = self.lost_audit_messages.fetch_add(1, Ordering::Release) + 1;
            log_warn!("audit_lost={lost} backlog_limit={limit}");
            return true;
        }
        false
    }
}

/// Audit message structure.
pub struct AuditMessage {
    /// The type of the audit message (e.g., AUDIT_AVC).
    pub audit_type: u16,
    /// The message to be audit-logged.
    pub message: Vec<u8>,
}

// -- Netlink audit sink (gated)
//
// The remaining functionality drives the netlink audit socket, which lives in
// the `fuchsia`-gated `crate::vfs::socket` module. Its only callers are there.

/// Supported requests that manipulate the `AuditLogger`.
#[cfg(feature = "fuchsia")]
pub enum AuditRequest {
    AuditGet,
    AuditSet,
    AuditUser,
}

#[cfg(feature = "fuchsia")]
impl TryFrom<u32> for AuditRequest {
    type Error = starnix_uapi::errors::Errno;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        use linux_uapi::{
            AUDIT_FIRST_USER_MSG, AUDIT_FIRST_USER_MSG2, AUDIT_GET, AUDIT_LAST_USER_MSG,
            AUDIT_LAST_USER_MSG2, AUDIT_SET, AUDIT_USER,
        };
        use starnix_uapi::error;
        match value {
            AUDIT_GET => Ok(Self::AuditGet),
            AUDIT_SET => Ok(Self::AuditSet),
            AUDIT_USER
            | AUDIT_FIRST_USER_MSG..=AUDIT_LAST_USER_MSG
            | AUDIT_FIRST_USER_MSG2..=AUDIT_LAST_USER_MSG2 => Ok(Self::AuditUser),
            _ => error!(ENOTSUP),
        }
    }
}

#[cfg(feature = "fuchsia")]
impl AuditLogger {
    /// Called by the `NetlinkAuditClient` to pull the next audit log from the backlog.
    pub fn read_audit_log(
        &self,
        _client: &m6_starnix_std::sync::Arc<crate::vfs::socket::AuditNetlinkClient>,
    ) -> Option<AuditMessage> {
        self.audit_queue.lock().pop_front()
    }

    /// Detach the `AuditNetlinkClient` from the `AuditLogger`.
    pub fn detach_client(
        &self,
        _client: &m6_starnix_std::sync::Arc<crate::vfs::socket::AuditNetlinkClient>,
    ) {
    }

    /// Applies the specified changes to the audit logger settings.
    pub fn set_status(
        &self,
        _current_task: &crate::task::CurrentTask,
        status: starnix_uapi::audit_status,
        _client: &m6_starnix_std::sync::Arc<crate::vfs::socket::AuditNetlinkClient>,
    ) -> Result<(), starnix_uapi::errors::Errno> {
        use linux_uapi::AUDIT_STATUS_BACKLOG_LIMIT;
        if status.mask & AUDIT_STATUS_BACKLOG_LIMIT != 0 {
            self.configuration.backlog_limit.store(status.backlog_limit, Ordering::Release);
        }
        Ok(())
    }

    /// Retrieve the `AuditConfig` as `audit_status` struct.
    pub fn get_status(&self) -> starnix_uapi::audit_status {
        starnix_uapi::audit_status {
            mask: Default::default(),
            enabled: Default::default(),
            failure: self.configuration.fail_action.load(Ordering::Acquire) as u32,
            pid: 0,
            rate_limit: u32::MAX,
            backlog_limit: self.configuration.backlog_limit.load(Ordering::Acquire),
            lost: self.lost_audit_messages.load(Ordering::Acquire),
            backlog: self.audit_queue.lock().len() as u32,
            __bindgen_anon_1: Default::default(),
            backlog_wait_time: Default::default(),
            backlog_wait_time_actual: Default::default(),
        }
    }

    /// Retrieve the number of audit messages in the backlog.
    pub fn get_backlog_count(
        &self,
        _client: &m6_starnix_std::sync::Arc<crate::vfs::socket::AuditNetlinkClient>,
    ) -> usize {
        self.audit_queue.lock().len()
    }
}
