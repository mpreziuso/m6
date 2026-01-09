//! IRQ management capabilities
//!
//! The IRQ system has two capability types:
//!
//! - **IRQControl**: Singleton capability to create IRQ handlers
//! - **IRQHandler**: Binds a hardware interrupt to a notification
//!
//! # Interrupt Flow
//!
//! 1. Hardware interrupt fires
//! 2. Kernel acknowledges and masks the interrupt
//! 3. Kernel signals the bound notification with the configured badge
//! 4. Userspace driver receives the notification
//! 5. Driver processes the interrupt
//! 6. Driver acknowledges via IRQHandler capability (unmasks)

use crate::Badge;
use crate::slot::ObjectRef;

/// IRQ number type.
pub type IrqNumber = u32;

/// Maximum IRQ number (GICv3 supports up to 1020 SPIs).
pub const MAX_IRQ: IrqNumber = 1019;

/// IRQ state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum IrqState {
    /// IRQ is not configured.
    #[default]
    Inactive = 0,
    /// IRQ is bound to a notification.
    Active = 1,
    /// IRQ is masked (waiting for acknowledgement).
    Masked = 2,
}

/// IRQ handler object metadata.
///
/// Stored in the kernel's object table.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct IrqHandlerObject {
    /// Hardware IRQ number.
    pub irq: IrqNumber,
    /// Current state.
    pub state: IrqState,
    /// Bound notification object.
    pub notification: ObjectRef,
    /// Badge to use when signalling.
    pub badge: Badge,
}

impl IrqHandlerObject {
    /// Create a new IRQ handler object.
    #[inline]
    #[must_use]
    pub const fn new(irq: IrqNumber) -> Self {
        Self {
            irq,
            state: IrqState::Inactive,
            notification: ObjectRef::NULL,
            badge: Badge::NONE,
        }
    }

    /// Check if the handler is bound to a notification.
    #[inline]
    #[must_use]
    pub const fn is_bound(&self) -> bool {
        self.notification.is_valid()
    }

    /// Check if the IRQ is currently masked.
    #[inline]
    #[must_use]
    pub const fn is_masked(&self) -> bool {
        matches!(self.state, IrqState::Masked)
    }

    /// Bind to a notification.
    #[inline]
    pub fn bind(&mut self, notification: ObjectRef, badge: Badge) {
        self.notification = notification;
        self.badge = badge;
        self.state = IrqState::Active;
    }

    /// Unbind from the notification.
    #[inline]
    pub fn unbind(&mut self) {
        self.notification = ObjectRef::NULL;
        self.badge = Badge::NONE;
        self.state = IrqState::Inactive;
    }

    /// Mark the IRQ as masked (pending acknowledgement).
    #[inline]
    pub fn mask(&mut self) {
        if self.is_bound() {
            self.state = IrqState::Masked;
        }
    }

    /// Acknowledge the IRQ (unmask).
    #[inline]
    pub fn acknowledge(&mut self) {
        if self.is_masked() {
            self.state = IrqState::Active;
        }
    }
}

/// IRQ control object metadata.
///
/// There is exactly one IRQControl capability in the system,
/// given to the root task at boot.
#[derive(Clone, Debug, Default)]
#[repr(C)]
pub struct IrqControlObject {
    /// Bitmap of claimed IRQs (1 = claimed, 0 = available).
    /// Supports up to 1024 IRQs (128 bytes = 16 u64s).
    pub claimed_bitmap: [u64; 16],
    /// Number of claimed IRQs.
    pub claimed_count: u16,
}

impl IrqControlObject {
    /// Create a new IRQ control object.
    #[inline]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            claimed_bitmap: [0; 16],
            claimed_count: 0,
        }
    }

    /// Check if an IRQ is available.
    #[inline]
    #[must_use]
    pub fn is_available(&self, irq: IrqNumber) -> bool {
        if irq > MAX_IRQ {
            return false;
        }
        let word_idx = (irq / 64) as usize;
        let bit_idx = (irq % 64) as usize;
        self.claimed_bitmap[word_idx] & (1u64 << bit_idx) == 0
    }

    /// Claim an IRQ.
    ///
    /// # Returns
    ///
    /// `true` if the IRQ was successfully claimed, `false` if already claimed.
    pub fn claim(&mut self, irq: IrqNumber) -> bool {
        if !self.is_available(irq) {
            return false;
        }
        let word_idx = (irq / 64) as usize;
        let bit_idx = (irq % 64) as usize;
        self.claimed_bitmap[word_idx] |= 1u64 << bit_idx;
        self.claimed_count += 1;
        true
    }

    /// Release an IRQ.
    pub fn release(&mut self, irq: IrqNumber) {
        if irq > MAX_IRQ {
            return;
        }
        let word_idx = (irq / 64) as usize;
        let bit_idx = (irq % 64) as usize;
        if self.claimed_bitmap[word_idx] & (1u64 << bit_idx) != 0 {
            self.claimed_bitmap[word_idx] &= !(1u64 << bit_idx);
            self.claimed_count = self.claimed_count.saturating_sub(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_irq_handler() {
        let mut handler = IrqHandlerObject::new(33);
        assert!(!handler.is_bound());

        handler.bind(ObjectRef::from_index(1), Badge::new(0x01));
        assert!(handler.is_bound());
        assert!(!handler.is_masked());

        handler.mask();
        assert!(handler.is_masked());

        handler.acknowledge();
        assert!(!handler.is_masked());
    }

    #[test]
    fn test_irq_control() {
        let mut ctrl = IrqControlObject::new();
        assert!(ctrl.is_available(33));

        assert!(ctrl.claim(33));
        assert!(!ctrl.is_available(33));
        assert!(!ctrl.claim(33)); // Already claimed

        ctrl.release(33);
        assert!(ctrl.is_available(33));
    }
}
