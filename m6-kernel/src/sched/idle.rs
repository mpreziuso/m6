//! Idle Task
//!
//! Creates and manages the per-CPU idle task that runs when no other
//! tasks are runnable.

use m6_arch::wait_for_interrupt;
use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;

use crate::cap::object_table::{self, KernelObjectType};
use crate::cap::tcb_storage;

/// Create an idle task for a CPU.
///
/// The idle task runs at the lowest priority and executes a WFI loop
/// when no other tasks are runnable.
pub fn create_idle_task(cpu_id: usize) -> Option<ObjectRef> {
    // 1. Allocate object table slot
    let obj_ref = object_table::alloc(KernelObjectType::Tcb)?;

    // 2. Allocate TCB storage
    let tcb_ptr = tcb_storage::create_tcb().ok()?;

    // 3. Configure as idle task
    // SAFETY: We just allocated this TCB and have exclusive access.
    unsafe {
        (*tcb_ptr).tcb.state = ThreadState::Running;
        (*tcb_ptr).tcb.priority = 0; // Lowest priority

        // Set name based on CPU ID
        let name = if cpu_id < 10 {
            [
                b'i',
                b'd',
                b'l',
                b'e',
                b'0' + cpu_id as u8,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
            ]
        } else {
            [
                b'i', b'd', b'l', b'e', b'?', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]
        };
        (*tcb_ptr).tcb.name = name;

        // No VSpace - idle runs in kernel space (TTBR1)
        (*tcb_ptr).tcb.vspace = ObjectRef::NULL;
        (*tcb_ptr).tcb.cspace_root = ObjectRef::NULL;

        // Context: idle loop entry point
        // Note: The idle task doesn't actually use this context because
        // it's set as current_thread but never context-switched TO via
        // the normal path. It's just a placeholder that indicates
        // "no real work to do".
        (*tcb_ptr).context.elr = idle_loop as *const () as usize as u64;
        // EL1h (handler mode), IRQs unmasked (I=0), FIQ/SError/Debug masked
        // DAIF: D=1 A=1 I=0 F=1 = 0b1101 in bits [9:6] = 0x340
        // M[4:0] = 0b00101 (EL1h) = 0x5
        (*tcb_ptr).context.spsr = 0x345;
    }

    // 4. Store in object table
    object_table::with_object_mut(obj_ref, |obj| {
        obj.data.tcb_ptr = tcb_ptr;
    });

    log::debug!(
        "Created idle task for CPU {} with ref {:?}",
        cpu_id,
        obj_ref
    );

    Some(obj_ref)
}

/// Idle loop - runs when no other tasks are runnable.
///
/// This function uses WFI (Wait For Interrupt) to put the CPU into
/// a low-power state until an interrupt occurs.
#[inline(never)]
pub extern "C" fn idle_loop() -> ! {
    loop {
        wait_for_interrupt();
    }
}
