//! IRQ syscall handlers
//!
//! This module implements syscalls for interrupt management:
//! - IrqAck: Acknowledge an IRQ (unmask it)
//! - IrqSetHandler: Bind an IRQ to a notification
//! - IrqClearHandler: Unbind an IRQ from its notification
//! - IrqControlGet: Claim an IRQ from IRQControl and create IRQHandler
//! - MsiAllocate: Allocate MSI vectors for a device

use m6_arch::exceptions::ExceptionContext;
use m6_cap::objects::{IrqHandlerObject, IrqState, MAX_IRQ};
use m6_cap::{Badge, CapRights, CapSlot, ObjectType, SlotFlags};

use crate::cap::object_table::KernelObjectType;
use crate::cap::{cspace, object_table};
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
    let notif_cap = ipc::lookup_cap(
        notification_cptr,
        ObjectType::Notification,
        CapRights::WRITE,
    )?;

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

/// Handle IrqControlGet syscall.
///
/// Claims an IRQ from IRQControl and creates an IRQHandler capability.
///
/// # ABI
///
/// - x0: IRQControl capability pointer
/// - x1: IRQ number to claim
/// - x2: Destination CNode capability pointer
/// - x3: Destination slot index
/// - x4: Depth (0 = auto)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_irq_control_get(args: &SyscallArgs) -> SyscallResult {
    let irq_control_cptr = args.arg0;
    let irq = args.arg1 as u32;
    let dest_cnode_cptr = args.arg2;
    let dest_index = args.arg3 as usize;
    let dest_depth = args.arg4 as u8;

    log::trace!(
        "irq_control_get: control={:#x} irq={} dest_cnode={:#x} dest_index={}",
        irq_control_cptr,
        irq,
        dest_cnode_cptr,
        dest_index
    );

    // Validate IRQ number
    if irq > MAX_IRQ {
        return Err(SyscallError::InvalidArg);
    }

    // Look up IRQControl capability with ALL rights
    let control_cap = ipc::lookup_cap(irq_control_cptr, ObjectType::IRQControl, CapRights::ALL)?;

    log::trace!(
        "irq_control_get: lookup succeeded, obj_ref={:?}",
        control_cap.obj_ref
    );

    // Resolve destination CNode slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    log::trace!(
        "irq_control_get: dest resolved to cnode={:?} slot={}",
        dest_loc.cnode_ref,
        dest_loc.slot_index
    );

    // Check destination slot is empty
    let slot_empty = cspace::with_slot(&dest_loc, |slot| Ok(slot.is_empty()))?;
    if !slot_empty {
        log::warn!(
            "irq_control_get: destination slot {} is occupied",
            dest_index
        );
        return Err(SyscallError::SlotOccupied);
    }

    log::trace!(
        "irq_control_get: dest slot {} is empty, claiming IRQ {}",
        dest_index,
        irq
    );

    // Try to claim the IRQ from IRQControl
    let claimed =
        object_table::with_irq_control_mut(control_cap.obj_ref, |control| control.claim(irq));

    if claimed.is_none() {
        // Debug why with_irq_control_mut failed
        let obj_info =
            object_table::with_object(control_cap.obj_ref, |obj| (obj.obj_type, obj.is_free()));
        log::warn!(
            "irq_control_get: with_irq_control_mut returned None for obj_ref={:?}, obj_info={:?}",
            control_cap.obj_ref,
            obj_info
        );
        return Err(SyscallError::InvalidCap);
    }

    let claimed = claimed.unwrap();

    if !claimed {
        return Err(SyscallError::ObjectInUse);
    }

    // Allocate IRQHandler object
    let handler_ref = object_table::alloc(KernelObjectType::IrqHandler).ok_or_else(|| {
        // Release the IRQ if allocation fails
        let _ = object_table::with_irq_control_mut(control_cap.obj_ref, |control| {
            control.release(irq);
        });
        SyscallError::NoMemory
    })?;

    // Initialise the IRQHandler object
    object_table::with_table(|table| {
        if let Some(obj) = table.get_mut(handler_ref) {
            obj.data.irq_handler = core::mem::ManuallyDrop::new(IrqHandlerObject::new(irq));
        }
    });

    // Install capability in destination slot
    let cap_result = cspace::with_slot_mut(&dest_loc, |slot| {
        *slot = CapSlot::new(
            handler_ref,
            ObjectType::IRQHandler,
            CapRights::ALL,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL,
        );
        Ok(())
    });

    if let Err(e) = cap_result {
        // Cleanup on failure
        let _ = object_table::with_irq_control_mut(control_cap.obj_ref, |control| {
            control.release(irq);
        });
        // SAFETY: Object was just created and not yet referenced.
        unsafe { object_table::free(handler_ref) };
        return Err(e);
    }

    // Increment reference count
    object_table::with_table(|table| table.inc_ref(handler_ref));

    log::trace!(
        "irq_control_get: created IRQHandler for IRQ {} at slot {}",
        irq,
        dest_index
    );
    Ok(0)
}

/// Handle MsiAllocate syscall.
///
/// Allocates MSI vectors for a device and returns MSI configuration.
///
/// # ABI
///
/// - x0: IRQControl capability pointer
/// - x1: Number of vectors requested
///
/// # Returns
///
/// - x0: 0 on success, negative error code on failure
/// - x1: MSI target address (physical address to write for MSI)
/// - x2: Base SPI number (message data for first vector)
/// - x3: Actual number of vectors allocated
pub fn handle_msi_allocate(args: &SyscallArgs, ctx: &ExceptionContext) -> SyscallResult {
    let irq_control_cptr = args.arg0;
    let requested_count = args.arg1 as u32;

    log::trace!(
        "msi_allocate: control={:#x} count={}",
        irq_control_cptr,
        requested_count
    );

    // Validate request
    if requested_count == 0 || requested_count > 64 {
        return Err(SyscallError::InvalidArg);
    }

    // Look up IRQControl capability with ALL rights
    let _control_cap = ipc::lookup_cap(irq_control_cptr, ObjectType::IRQControl, CapRights::ALL)?;

    // Allocate MSI vectors
    let msi_config =
        m6_pal::gic::allocate_msi_vectors(requested_count).ok_or(SyscallError::NoMemory)?;

    // Configure each allocated SPI for MSI use
    for i in 0..msi_config.vector_count {
        let spi = msi_config.data_base + i;
        m6_pal::gic::configure_msi_spi(spi);
    }

    // Return MSI configuration via registers
    // x1 = target address, x2 = base SPI, x3 = count
    // We need to write to x1-x3 in the exception context
    // SAFETY: We're modifying return values in the exception context
    unsafe {
        let ctx_ptr = ctx as *const ExceptionContext as *mut ExceptionContext;
        (*ctx_ptr).gpr[1] = msi_config.target_addr;
        (*ctx_ptr).gpr[2] = msi_config.data_base as u64;
        (*ctx_ptr).gpr[3] = msi_config.vector_count as u64;
    }

    log::trace!(
        "msi_allocate: allocated {} vectors, target={:#x}, base_spi={}",
        msi_config.vector_count,
        msi_config.target_addr,
        msi_config.data_base
    );

    Ok(0)
}
