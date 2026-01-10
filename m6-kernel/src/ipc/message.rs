//! IPC message handling.
//!
//! Messages are transferred via registers. On send/call, the message payload
//! is in x1-x5 (x0 contains the endpoint cptr). On receive, the message is
//! delivered to x0-x4, with the badge in x6. This provides 40 bytes of
//! payload without any memory copies.

use m6_arch::exceptions::ExceptionContext;

/// IPC message stored in 5 registers.
///
/// On send/call: extracted from x1-x5 (x0 = endpoint cptr)
/// On receive: delivered to x0-x4 (x6 = badge)
///
/// This struct represents the 40-byte message payload that can be
/// transferred between threads during IPC operations.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IpcMessage {
    /// Message registers (5 words = 40 bytes).
    pub regs: [u64; 5],
}

impl IpcMessage {
    /// Create an empty message.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self { regs: [0; 5] }
    }

    /// Create a message from raw register values.
    #[inline]
    #[must_use]
    pub const fn from_regs(regs: [u64; 5]) -> Self {
        Self { regs }
    }

    /// Extract message from exception context (caller's registers).
    ///
    /// Reads x1-x5 as message words 0-4. x0 contains the endpoint cptr
    /// and is not part of the message payload.
    #[inline]
    #[must_use]
    pub fn from_context(ctx: &ExceptionContext) -> Self {
        Self {
            regs: [
                ctx.gpr[1], // x1 -> msg[0] (label)
                ctx.gpr[2], // x2 -> msg[1]
                ctx.gpr[3], // x3 -> msg[2]
                ctx.gpr[4], // x4 -> msg[3]
                ctx.gpr[5], // x5 -> msg[4]
            ],
        }
    }

    /// Write message to exception context (receiver's registers).
    ///
    /// Writes message words 0-4 to x0-x4. The badge is written to x6
    /// separately by the caller.
    #[inline]
    pub fn to_context(&self, ctx: &mut ExceptionContext) {
        ctx.gpr[0] = self.regs[0]; // msg[0] (label) -> x0
        ctx.gpr[1] = self.regs[1]; // msg[1] -> x1
        ctx.gpr[2] = self.regs[2]; // msg[2] -> x2
        ctx.gpr[3] = self.regs[3]; // msg[3] -> x3
        ctx.gpr[4] = self.regs[4]; // msg[4] -> x4
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

    /// Get a message word by index (0-4).
    #[inline]
    #[must_use]
    pub const fn get(&self, index: usize) -> Option<u64> {
        if index < 5 {
            Some(self.regs[index])
        } else {
            None
        }
    }

    /// Set a message word by index (0-4).
    #[inline]
    pub fn set(&mut self, index: usize, value: u64) -> bool {
        if index < 5 {
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
        assert_eq!(msg.regs, [0; 5]);
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
        assert_eq!(msg.get(5), None);
        assert!(!msg.set(5, 99));
    }
}
