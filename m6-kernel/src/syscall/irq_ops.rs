//! IRQ syscall handlers
//!
//! This module implements syscalls for interrupt management:
//! - IrqAck: Acknowledge an IRQ (unmask it)
//! - IrqSetHandler: Bind an IRQ to a notification
//! - IrqClearHandler: Unbind an IRQ from its notification

use m6_cap::{Badge, CapRights, ObjectType};
use m6_cap::objects::IrqState;

use crate::cap::object_table;
use crate::ipc;

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};

/// Handle IrqAck syscall.
///
/// Acknowledges an IRQ to unmask it for future delivery.
///
/// # ABI
///
/// - x0: IRQ handler capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_irq_ack(args: &SyscallArgs) -> SyscallResult {
    let irq_handler_cptr = args.arg0;

    // Look up IRQ handler capability with WRITE right
    let cap = ipc::lookup_cap(irq_handler_cptr, ObjectType::IRQHandler, CapRights::WRITE)?;

    // Access the IRQ handler and acknowledge
    let result = object_table::with_irq_handler_mut(cap.obj_ref, |handler| {
        // Must be in Masked state to acknowledge
        if !handler.is_masked() {
            return Err(SyscallError::InvalidState);
        }

        // Acknowledge the IRQ (transitions from Masked to Active)
        handler.acknowledge();

        // Enable the IRQ in hardware
        m6_pal::gic::enable_irq(handler.irq);

        Ok(())
    });

    match result {
        Some(Ok(())) => Ok(0),
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}

/// Handle IrqSetHandler syscall.
///
/// Binds an IRQ handler to a notification object.
///
/// # ABI
///
/// - x0: IRQ handler capability pointer
/// - x1: Notification capability pointer
/// - x2: Badge value to OR into notification on interrupt
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_irq_set_handler(args: &SyscallArgs) -> SyscallResult {
    let irq_handler_cptr = args.arg0;
    let notification_cptr = args.arg1;
    let badge = args.arg2;

    // Look up IRQ handler capability with WRITE right
    let handler_cap = ipc::lookup_cap(irq_handler_cptr, ObjectType::IRQHandler, CapRights::WRITE)?;

    // Look up notification capability with WRITE right
    let notif_cap = ipc::lookup_cap(notification_cptr, ObjectType::Notification, CapRights::WRITE)?;

    // Bind the handler to the notification
    let result = object_table::with_irq_handler_mut(handler_cap.obj_ref, |handler| {
        // Must be in Inactive state to bind
        if handler.state != IrqState::Inactive {
            return Err(SyscallError::InvalidState);
        }

        // Bind to the notification
        handler.bind(notif_cap.obj_ref, Badge::new(badge));

        // Enable the IRQ in hardware
        m6_pal::gic::enable_irq(handler.irq);

        Ok(())
    });

    match result {
        Some(Ok(())) => Ok(0),
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}

/// Handle IrqClearHandler syscall.
///
/// Unbinds an IRQ handler from its notification.
///
/// # ABI
///
/// - x0: IRQ handler capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_irq_clear_handler(args: &SyscallArgs) -> SyscallResult {
    let irq_handler_cptr = args.arg0;

    // Look up IRQ handler capability with WRITE right
    let cap = ipc::lookup_cap(irq_handler_cptr, ObjectType::IRQHandler, CapRights::WRITE)?;

    // Unbind the handler
    let result = object_table::with_irq_handler_mut(cap.obj_ref, |handler| {
        // Must be bound (Active or Masked) to unbind
        if handler.state == IrqState::Inactive {
            return Err(SyscallError::InvalidState);
        }

        // Disable the IRQ in hardware first
        m6_pal::gic::disable_irq(handler.irq);

        // Unbind from the notification
        handler.unbind();

        Ok(())
    });

    match result {
        Some(Ok(())) => Ok(0),
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}
