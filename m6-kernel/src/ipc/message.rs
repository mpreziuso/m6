//! IPC message handling.
//!
//! Messages are transferred via registers x0-x5, providing 48 bytes of
//! payload without any memory copies. This is the fast path for small
//! messages; larger data should use Frame capabilities.

use m6_arch::exceptions::ExceptionContext;

/// IPC message stored in registers x0-x5.
///
/// This struct represents the 48-byte message payload that can be
/// transferred between threads during IPC operations.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcMessage {
    /// Message registers (x0-x5).
    pub regs: [u64; 6],
}

impl IpcMessage {
    /// Create an empty message.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { regs: [0; 6] }
    }

    /// Create a message from raw register values.
    #[inline]
    #[must_use]
    pub const fn from_regs(regs: [u64; 6]) -> Self {
        Self { regs }
    }

    /// Extract message from exception context (caller's registers).
    #[inline]
    #[must_use]
    pub fn from_context(ctx: &ExceptionContext) -> Self {
        Self {
            regs: [
                ctx.gpr[0],
                ctx.gpr[1],
                ctx.gpr[2],
                ctx.gpr[3],
                ctx.gpr[4],
                ctx.gpr[5],
            ],
        }
    }

    /// Write message to exception context (receiver's registers).
    #[inline]
    pub fn to_context(&self, ctx: &mut ExceptionContext) {
        ctx.gpr[0] = self.regs[0];
        ctx.gpr[1] = self.regs[1];
        ctx.gpr[2] = self.regs[2];
        ctx.gpr[3] = self.regs[3];
        ctx.gpr[4] = self.regs[4];
        ctx.gpr[5] = self.regs[5];
    }

    /// Get the message label (first word, x0).
    ///
    /// By convention, x0 contains a message label/type identifier.
    #[inline]
    #[must_use]
    pub const fn label(&self) -> u64 {
        self.regs[0]
    }

    /// Set the message label (first word, x0).
    #[inline]
    pub fn set_label(&mut self, label: u64) {
        self.regs[0] = label;
    }

    /// Get a message word by index (0-5).
    #[inline]
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<u64> {
        if index < 6 {
            Some(self.regs[index])
        } else {
            None
        }
    }

    /// Set a message word by index (0-5).
    #[inline]
    pub fn set(&mut self, index: usize, value: u64) -> bool {
        if index < 6 {
            self.regs[index] = value;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_new() {
        let msg = IpcMessage::new();
        assert_eq!(msg.regs, [0; 6]);
    }

    #[test]
    fn test_message_label() {
        let mut msg = IpcMessage::new();
        msg.set_label(0x1234);
        assert_eq!(msg.label(), 0x1234);
    }

    #[test]
    fn test_message_get_set() {
        let mut msg = IpcMessage::new();
        assert!(msg.set(3, 42));
        assert_eq!(msg.get(3), Some(42));
        assert_eq!(msg.get(6), None);
        assert!(!msg.set(6, 99));
    }
}
