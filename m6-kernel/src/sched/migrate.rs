//! Task Migration
//!
//! Provides functionality for migrating tasks between CPUs.
//! Uses ordered locking (lower CPU ID first) to prevent deadlocks.

use m6_cap::ObjectRef;

use super::{MAX_CPUS, current_cpu_id, eevdf, get_sched_state, request_reschedule_on};

/// Find which CPU a task is currently on.
///
/// Returns `None` if the task is not found in any run queue or as
/// the current task on any CPU.
pub fn find_task_cpu(tcb_ref: ObjectRef) -> Option<usize> {
    let sched_state = get_sched_state();

    for (cpu, _) in sched_state.iter().enumerate().take(MAX_CPUS) {
        let sched = sched_state[cpu].lock();
        if sched.current() == Some(tcb_ref) || sched.run_queue().contains(tcb_ref) {
            return Some(cpu);
        }
    }

    None
}

/// Migrate a task to a different CPU.
///
/// Returns `true` if migration was successful, `false` if the task
/// couldn't be found or migration failed.
///
/// # Locking Strategy
///
/// To prevent deadlocks when migrating between CPUs, we always lock
/// CPUs in ascending order (lower CPU ID first). This ensures a
/// consistent lock ordering across all migration operations.
///
/// # Notes
///
/// - Cannot migrate the currently running task on another CPU
/// - If migrating the current task on this CPU, a reschedule will be triggered
/// - Tasks with CPU affinity set will have their affinity updated
pub fn migrate_task(tcb_ref: ObjectRef, target_cpu: usize) -> bool {
    if target_cpu >= MAX_CPUS {
        log::error!("Invalid target CPU {} for migration", target_cpu);
        return false;
    }

    // First, find which CPU the task is on
    let source_cpu = match find_task_cpu(tcb_ref) {
        Some(cpu) => cpu,
        None => {
            log::debug!("Task {:?} not found for migration", tcb_ref);
            return false;
        }
    };

    // Already on target CPU
    if source_cpu == target_cpu {
        log::trace!("Task {:?} already on CPU {}", tcb_ref, target_cpu);
        return true;
    }

    // Perform migration with ordered locking
    migrate_between_cpus(tcb_ref, source_cpu, target_cpu)
}

/// Internal function to migrate a task between two specific CPUs.
///
/// Acquires locks in ascending CPU order to prevent deadlocks.
fn migrate_between_cpus(tcb_ref: ObjectRef, source_cpu: usize, target_cpu: usize) -> bool {
    let sched_state = get_sched_state();
    let current = current_cpu_id();

    // Lock in ascending order to prevent deadlock
    let (first_cpu, second_cpu) = if source_cpu < target_cpu {
        (source_cpu, target_cpu)
    } else {
        (target_cpu, source_cpu)
    };

    let mut first_lock = sched_state[first_cpu].lock();
    let mut second_lock = sched_state[second_cpu].lock();

    // Get mutable references to source and target schedulers
    let (source_sched, target_sched) = if source_cpu < target_cpu {
        (&mut *first_lock, &mut *second_lock)
    } else {
        (&mut *second_lock, &mut *first_lock)
    };

    // Check if task is the current task on source CPU
    let is_current = source_sched.current() == Some(tcb_ref);

    // If it's the current task on a different CPU, we can't migrate it directly
    // (it's actively running). We'd need an IPI to request it yield first.
    if is_current && source_cpu != current {
        log::debug!(
            "Cannot migrate running task {:?} from CPU {} (not current CPU)",
            tcb_ref,
            source_cpu
        );
        return false;
    }

    // Remove from source run queue
    if !source_sched.run_queue().contains(tcb_ref) && !is_current {
        log::debug!(
            "Task {:?} not in source CPU {} run queue",
            tcb_ref,
            source_cpu
        );
        return false;
    }

    // Remove from source
    eevdf::remove_from_run_queue(source_sched, tcb_ref);

    // Add to target
    eevdf::add_to_run_queue(target_sched, tcb_ref);

    log::debug!(
        "Migrated task {:?} from CPU {} to CPU {}",
        tcb_ref,
        source_cpu,
        target_cpu
    );

    // Drop locks before sending IPI
    drop(first_lock);
    drop(second_lock);

    // If we migrated from current CPU (and it was the running task), request reschedule
    if is_current && source_cpu == current {
        request_reschedule_on(current);
    }

    // Wake target CPU if different from current
    if target_cpu != current {
        request_reschedule_on(target_cpu);
        m6_pal::gic::send_ipi(target_cpu, m6_pal::gic::IpiType::Reschedule);
    }

    true
}

/// Attempt to migrate a task, updating its affinity if successful.
///
/// This sets the task's CPU affinity to the target CPU after migration,
/// ensuring it stays on that CPU.
pub fn migrate_and_pin(tcb_ref: ObjectRef, target_cpu: usize) -> bool {
    if !migrate_task(tcb_ref, target_cpu) {
        return false;
    }

    // Update affinity to pin to target CPU
    super::run_queue::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.affinity = target_cpu as i8;
    });

    true
}

/// Check if a task can be migrated.
///
/// A task can be migrated if:
/// - It exists in some CPU's run queue or is the current task
/// - It doesn't have a fixed CPU affinity (affinity >= 0 means pinned)
/// - It's not currently running on a different CPU
pub fn can_migrate(tcb_ref: ObjectRef) -> bool {
    // Check affinity - if pinned, cannot migrate
    let affinity = super::run_queue::with_tcb(tcb_ref, |tcb| tcb.tcb.affinity);

    match affinity {
        Some(aff) if aff >= 0 => {
            // Task is pinned to a specific CPU
            false
        }
        Some(_) => {
            // Task has no affinity, can migrate
            find_task_cpu(tcb_ref).is_some()
        }
        None => {
            // Task doesn't exist
            false
        }
    }
}
