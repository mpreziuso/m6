//! Userspace IRQ delivery
//!
//! This module implements the userspace IRQ dispatch mechanism.
//! When a hardware interrupt fires that has an IRQHandler bound to
//! a notification, the kernel signals that notification with the
//! configured badge.
//!
//! # Interrupt Flow
//!
//! 1. Hardware interrupt fires
//! 2. GIC acknowledges and masks the interrupt
//! 3. Kernel looks up IRQHandler by INTID
//! 4. If handler is Active, signals bound notification with badge
//! 5. Handler transitions to Masked state
//! 6. Userspace driver receives notification, processes interrupt
//! 7. Driver calls IrqAck to unmask and re-enable

use m6_cap::objects::IrqState;
use m6_cap::ObjectRef;

use crate::cap::object_table::{self, KernelObjectType, MAX_OBJECTS};
use crate::ipc::notification::do_signal;

/// Dispatch a hardware IRQ to userspace.
///
/// Called from the GIC dispatch function when an interrupt fires
/// that doesn't have a kernel-registered handler.
///
/// # Arguments
///
/// * `intid` - GIC interrupt ID
///
/// # Returns
///
/// `true` if the IRQ was handled by a userspace handler, `false` otherwise.
pub fn dispatch_userspace_irq(intid: u32) -> bool {
    log::trace!("dispatch_userspace_irq: INTID {}", intid);

    // Find IRQHandler object for this INTID
    let handler_ref = match find_irq_handler(intid) {
        Some(r) => r,
        None => {
            log::warn!("dispatch_userspace_irq: no handler for INTID {}", intid);
            return false;
        }
    };

    // Extract notification info from handler, mask it, and disable IRQ.
    // We must release the object table lock before calling do_signal
    // to avoid deadlock (do_signal also needs the object table).
    let signal_info = object_table::with_irq_handler_mut(handler_ref, |handler| {
        // Only process if handler is Active (bound and ready)
        if handler.state != IrqState::Active {
            log::warn!(
                "dispatch_userspace_irq: handler for IRQ {} is {:?}, not Active",
                intid,
                handler.state
            );
            return None;
        }

        // Get bound notification and badge
        let notif_ref = handler.notification;
        let badge = handler.badge.value();

        if !notif_ref.is_valid() {
            log::warn!(
                "dispatch_userspace_irq: notification ref invalid for IRQ {}",
                intid
            );
            return None;
        }

        // Transition to Masked state (awaiting acknowledgement)
        handler.mask();

        // Disable the IRQ in GIC until userspace acknowledges.
        // This is critical for level-triggered interrupts like UART RX,
        // which will keep firing until the source is cleared.
        m6_pal::gic::disable_irq(intid);

        Some((notif_ref, badge))
    });

    // Now signal the notification outside the object table lock
    let Some((notif_ref, badge)) = signal_info.flatten() else {
        return false;
    };

    log::trace!(
        "dispatch_userspace_irq: IRQ {} -> notif {:?} badge {}",
        intid,
        notif_ref,
        badge
    );

    if do_signal(notif_ref, badge).is_err() {
        log::warn!(
            "dispatch_userspace_irq: failed to signal notification for IRQ {}",
            intid
        );
        return false;
    }

    log::trace!("dispatch_userspace_irq: signalled IRQ {}", intid);
    true
}

/// Find IRQHandler object for a given INTID.
///
/// This iterates through the object table looking for an IRQHandler
/// with matching IRQ number.
///
/// # Performance Note
///
/// This is O(n) where n is the number of allocated objects. For better
/// performance, consider maintaining a lookup table indexed by INTID.
fn find_irq_handler(intid: u32) -> Option<ObjectRef> {
    object_table::with_table(|table| {
        for i in 1..MAX_OBJECTS {
            let obj_ref = ObjectRef::from_index(i as u32);
            if let Some(obj) = table.get(obj_ref)
                && obj.obj_type == KernelObjectType::IrqHandler
                && !obj.is_free()
            {
                // SAFETY: Verified type is IrqHandler
                let handler = unsafe { &obj.data.irq_handler };
                if handler.irq == intid {
                    return Some(obj_ref);
                }
            }
        }
        None
    })
}
