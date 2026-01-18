//! Load Balancing
//!
//! Implements periodic load balancing and work-stealing for SMP systems.
//! Called from the timer interrupt on CPU 0 to redistribute tasks across CPUs.

use m6_cap::ObjectRef;

use super::{MAX_CPUS, get_sched_state, migrate, run_queue};

/// Load balancing interval in timer ticks.
/// At 100Hz tick rate, 100 ticks = 1 second.
pub const BALANCE_INTERVAL_TICKS: u64 = 100;

/// Minimum load difference ratio to trigger migration.
/// Migrate if busiest CPU has > 2x the load of the idlest.
const LOAD_IMBALANCE_THRESHOLD: u32 = 2;

/// Minimum tasks on busiest CPU before considering migration.
const MIN_TASKS_TO_MIGRATE: u32 = 2;

/// Counter for balance interval tracking.
static BALANCE_TICK_COUNTER: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Per-CPU load information.
#[derive(Debug, Clone, Copy, Default)]
struct CpuLoad {
    /// Number of runnable tasks (in run queue + current).
    task_count: u32,
    /// Total weight of runnable tasks (reserved for future weighted balancing).
    #[expect(dead_code)]
    total_weight: u64,
}

/// Collect load information from all CPUs.
fn collect_load() -> [CpuLoad; MAX_CPUS] {
    let sched_state = get_sched_state();
    let mut loads = [CpuLoad::default(); MAX_CPUS];

    for cpu in 0..MAX_CPUS {
        let sched = sched_state[cpu].lock();
        let queue_len = sched.run_queue().len();
        let has_current = sched.current().is_some();

        loads[cpu] = CpuLoad {
            task_count: queue_len + if has_current { 1 } else { 0 },
            total_weight: sched.total_weight(),
        };
    }

    loads
}

/// Find the busiest and idlest CPUs.
fn find_busiest_and_idlest(loads: &[CpuLoad; MAX_CPUS], cpu_count: usize) -> (usize, usize) {
    let mut busiest = 0;
    let mut idlest = 0;

    for cpu in 0..cpu_count {
        if loads[cpu].task_count > loads[busiest].task_count {
            busiest = cpu;
        }
        if loads[cpu].task_count < loads[idlest].task_count {
            idlest = cpu;
        }
    }

    (busiest, idlest)
}

/// Periodic load balancing.
///
/// Should be called from the timer interrupt on CPU 0.
/// Checks if load is imbalanced and migrates tasks if necessary.
pub fn periodic_balance(cpu_count: usize) {
    use core::sync::atomic::Ordering;

    // Increment tick counter
    let ticks = BALANCE_TICK_COUNTER.fetch_add(1, Ordering::Relaxed) + 1;

    // Only balance every BALANCE_INTERVAL_TICKS
    if !ticks.is_multiple_of(BALANCE_INTERVAL_TICKS) {
        return;
    }

    // Single CPU systems don't need balancing
    if cpu_count <= 1 {
        return;
    }

    let loads = collect_load();
    let (busiest, idlest) = find_busiest_and_idlest(&loads, cpu_count);

    // Check if imbalance is significant enough
    let busiest_load = loads[busiest].task_count;
    let idlest_load = loads[idlest].task_count;

    if busiest_load < MIN_TASKS_TO_MIGRATE {
        // Busiest CPU doesn't have enough tasks to share
        return;
    }

    if idlest_load > 0 && busiest_load / idlest_load.max(1) < LOAD_IMBALANCE_THRESHOLD {
        // Imbalance isn't significant enough
        return;
    }

    // Try to migrate a task from busiest to idlest
    if let Some(task) = find_migratable_task(busiest)
        && migrate::migrate_task(task, idlest)
    {
        log::debug!(
            "Load balance: migrated task {:?} from CPU {} ({} tasks) to CPU {} ({} tasks)",
            task,
            busiest,
            busiest_load,
            idlest,
            idlest_load
        );
    }
}

/// Find a task suitable for migration from a CPU.
///
/// Returns a task that:
/// - Is not the currently running task
/// - Does not have CPU affinity set (affinity < 0)
fn find_migratable_task(cpu: usize) -> Option<ObjectRef> {
    let sched_state = get_sched_state();
    let sched = sched_state[cpu].lock();

    // Walk the run queue to find a migratable task
    let mut current = sched.run_queue().head();

    while current.is_valid() {
        // Check if this task can be migrated
        let can_migrate = run_queue::with_tcb(current, |tcb| {
            // Only migrate tasks without affinity
            tcb.tcb.affinity < 0
        })
        .unwrap_or(false);

        if can_migrate {
            return Some(current);
        }

        // Move to next task
        current = run_queue::with_tcb(current, |tcb| tcb.sched_next).unwrap_or(ObjectRef::NULL);
    }

    None
}

/// Work-stealing for idle CPUs.
///
/// Called when a CPU has no runnable tasks. Attempts to steal work from
/// another CPU to keep the system balanced.
///
/// Returns the stolen task's ObjectRef if successful.
pub fn try_steal_work(idle_cpu: usize, cpu_count: usize) -> Option<ObjectRef> {
    if cpu_count <= 1 {
        return None;
    }

    let loads = collect_load();

    // Find a CPU with excess work
    for (cpu, _) in loads.iter().enumerate().take(cpu_count) {
        if cpu == idle_cpu {
            continue;
        }

        // Only steal from CPUs with at least 2 tasks
        if loads[cpu].task_count < MIN_TASKS_TO_MIGRATE {
            continue;
        }

        // Try to find and migrate a task
        if let Some(task) = find_migratable_task(cpu)
            && migrate::migrate_task(task, idle_cpu)
        {
            log::trace!(
                "Work steal: CPU {} stole task {:?} from CPU {}",
                idle_cpu,
                task,
                cpu
            );
            return Some(task);
        }
    }

    None
}

/// Reset the balance tick counter.
///
/// Called during initialisation.
pub fn reset_balance_counter() {
    use core::sync::atomic::Ordering;
    BALANCE_TICK_COUNTER.store(0, Ordering::Relaxed);
}

/// Get the current balance tick count (for debugging).
pub fn balance_tick_count() -> u64 {
    use core::sync::atomic::Ordering;
    BALANCE_TICK_COUNTER.load(Ordering::Relaxed)
}
