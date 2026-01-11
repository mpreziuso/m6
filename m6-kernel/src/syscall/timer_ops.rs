//! Timer syscall handlers
//!
//! This module implements syscalls for timer management:
//! - TimerControlGet: Create a timer from TimerControl
//! - TimerBind: Bind a timer to a notification
//! - TimerArm: Arm a timer (one-shot or periodic)
//! - TimerCancel: Cancel an armed timer
//! - TimerClear: Unbind a timer from its notification

use m6_cap::{Badge, CapRights, CapSlot, ObjectType, SlotFlags};
use m6_cap::objects::{TimerObject, TimerState};

use crate::cap::{cspace, object_table};
use crate::cap::object_table::KernelObjectType;
use crate::ipc;
use crate::sched::timer_queue;

use super::SyscallArgs;
use super::error::{SyscallError, SyscallResult};

/// Handle TimerControlGet syscall.
///
/// Creates a new timer from TimerControl.
///
/// # ABI
///
/// - x0: TimerControl capability pointer
/// - x1: Destination CNode capability pointer
/// - x2: Destination slot index
/// - x3: Depth (0 = auto)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_timer_control_get(args: &SyscallArgs) -> SyscallResult {
    let timer_control_cptr = args.arg0;
    let dest_cnode_cptr = args.arg1;
    let dest_index = args.arg2 as usize;
    let dest_depth = args.arg3 as u8;

    log::trace!(
        "timer_control_get: control={:#x} dest_cnode={:#x} dest_index={}",
        timer_control_cptr, dest_cnode_cptr, dest_index
    );

    // Look up TimerControl capability with ALL rights
    let _control_cap = ipc::lookup_cap(timer_control_cptr, ObjectType::TimerControl, CapRights::ALL)?;

    // Resolve destination CNode slot
    let dest_loc = cspace::resolve_cnode_slot(dest_cnode_cptr, dest_depth, dest_index)?;

    // Check destination slot is empty
    let slot_empty = cspace::with_slot(&dest_loc, |slot| Ok(slot.is_empty()))?;
    if !slot_empty {
        log::warn!("timer_control_get: destination slot {} is occupied", dest_index);
        return Err(SyscallError::SlotOccupied);
    }

    // Allocate Timer object
    let timer_ref = object_table::alloc(KernelObjectType::Timer)
        .ok_or(SyscallError::NoMemory)?;

    // Initialise the Timer object
    object_table::with_table(|table| {
        if let Some(obj) = table.get_mut(timer_ref) {
            obj.data.timer = core::mem::ManuallyDrop::new(TimerObject::new());
        }
    });

    // Install capability in destination slot
    let cap_result = cspace::with_slot_mut(&dest_loc, |slot| {
        *slot = CapSlot::new(
            timer_ref,
            ObjectType::Timer,
            CapRights::ALL,
            Badge::NONE,
            SlotFlags::IS_ORIGINAL,
        );
        Ok(())
    });

    if let Err(e) = cap_result {
        // Cleanup on failure
        // SAFETY: Object was just created and not yet referenced.
        unsafe { object_table::free(timer_ref) };
        return Err(e);
    }

    // Increment reference count
    object_table::with_table(|table| table.inc_ref(timer_ref));

    log::trace!("timer_control_get: created Timer at slot {}", dest_index);
    Ok(0)
}

/// Handle TimerBind syscall.
///
/// Binds a timer to a notification object.
///
/// # ABI
///
/// - x0: Timer capability pointer
/// - x1: Notification capability pointer
/// - x2: Badge value to OR into notification on expiry
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_timer_bind(args: &SyscallArgs) -> SyscallResult {
    let timer_cptr = args.arg0;
    let notification_cptr = args.arg1;
    let badge = args.arg2;

    // Look up Timer capability with WRITE right
    let timer_cap = ipc::lookup_cap(timer_cptr, ObjectType::Timer, CapRights::WRITE)?;

    // Look up notification capability with WRITE right
    let notif_cap = ipc::lookup_cap(notification_cptr, ObjectType::Notification, CapRights::WRITE)?;

    // Bind the timer to the notification
    let result = object_table::with_timer_mut(timer_cap.obj_ref, |timer| {
        // Must be in Inactive state to bind
        if timer.state != TimerState::Inactive {
            return Err(SyscallError::InvalidState);
        }

        // Bind to the notification
        timer.bind(notif_cap.obj_ref, Badge::new(badge));

        Ok(())
    });

    match result {
        Some(Ok(())) => Ok(0),
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}

/// Handle TimerArm syscall.
///
/// Arms a timer to fire after a specified duration or at an absolute time.
///
/// # ABI
///
/// - x0: Timer capability pointer
/// - x1: Duration in nanoseconds (for relative mode) or absolute tick count
/// - x2: Flags (bit 0: 0=relative, 1=absolute; bit 1: 0=one-shot, 1=periodic)
/// - x3: Period in nanoseconds (for periodic timers, 0 for one-shot)
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_timer_arm(args: &SyscallArgs) -> SyscallResult {
    let timer_cptr = args.arg0;
    let time_value = args.arg1;
    let flags = args.arg2;
    let period_ns = args.arg3;

    let is_absolute = (flags & 1) != 0;
    let is_periodic = (flags & 2) != 0;

    // Look up Timer capability with WRITE right
    let timer_cap = ipc::lookup_cap(timer_cptr, ObjectType::Timer, CapRights::WRITE)?;

    // Arm the timer
    let result = object_table::with_timer_mut(timer_cap.obj_ref, |timer| {
        // Must be bound to a notification
        if !timer.is_bound() {
            return Err(SyscallError::InvalidState);
        }

        // Calculate expiry time in ticks
        let expiry_ticks = if is_absolute {
            // Absolute mode: time_value is the absolute tick count
            time_value
        } else {
            // Relative mode: time_value is duration in nanoseconds
            let freq = m6_pal::timer::frequency();
            if freq == 0 {
                return Err(SyscallError::InvalidState);
            }
            let now_ticks = m6_pal::timer::read_counter();
            let duration_ticks = (time_value.saturating_mul(freq)) / 1_000_000_000;
            now_ticks.saturating_add(duration_ticks)
        };

        // Arm the timer object
        timer.arm(is_periodic, period_ns);

        Ok((timer_cap.obj_ref, expiry_ticks))
    });

    match result {
        Some(Ok((timer_ref, expiry_ticks))) => {
            // Register timer in timer queue
            timer_queue::register_timer_ticks(timer_ref, expiry_ticks);
            Ok(0)
        }
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}

/// Handle TimerCancel syscall.
///
/// Cancels an armed timer.
///
/// # ABI
///
/// - x0: Timer capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_timer_cancel(args: &SyscallArgs) -> SyscallResult {
    let timer_cptr = args.arg0;

    // Look up Timer capability with WRITE right
    let timer_cap = ipc::lookup_cap(timer_cptr, ObjectType::Timer, CapRights::WRITE)?;

    // Cancel the timer
    let result = object_table::with_timer_mut(timer_cap.obj_ref, |timer| {
        // Must be in Armed state to cancel
        if !timer.is_armed() {
            return Err(SyscallError::InvalidState);
        }

        // Disarm the timer
        timer.disarm();

        Ok(timer_cap.obj_ref)
    });

    match result {
        Some(Ok(timer_ref)) => {
            // Unregister from timer queue
            timer_queue::unregister_timer(timer_ref);
            Ok(0)
        }
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}

/// Handle TimerClear syscall.
///
/// Unbinds a timer from its notification.
///
/// # ABI
///
/// - x0: Timer capability pointer
///
/// # Returns
///
/// - 0 on success
/// - Negative error code on failure
pub fn handle_timer_clear(args: &SyscallArgs) -> SyscallResult {
    let timer_cptr = args.arg0;

    // Look up Timer capability with WRITE right
    let timer_cap = ipc::lookup_cap(timer_cptr, ObjectType::Timer, CapRights::WRITE)?;

    // Clear the timer
    let result = object_table::with_timer_mut(timer_cap.obj_ref, |timer| {
        // If armed, cancel first
        let was_armed = timer.is_armed();
        let timer_ref = if was_armed {
            Some(timer_cap.obj_ref)
        } else {
            None
        };

        // Unbind from the notification
        timer.unbind();

        Ok(timer_ref)
    });

    match result {
        Some(Ok(Some(timer_ref))) => {
            // Was armed, unregister from timer queue
            timer_queue::unregister_timer(timer_ref);
            Ok(0)
        }
        Some(Ok(None)) => {
            // Was not armed, just cleared binding
            Ok(0)
        }
        Some(Err(e)) => Err(e),
        None => Err(SyscallError::InvalidCap),
    }
}
