//! EEVDF Scheduler
//!
//! Implements the Earliest Eligible Virtual Deadline First (EEVDF) scheduling
//! algorithm with SMP support and capability-based CPU time management.
//!
//! # Key Concepts
//!
//! - **Virtual Clock (vclock)**: Advances proportionally to real time, scaled
//!   by the total weight of all runnable tasks.
//! - **Virtual Eligible Time (v_eligible)**: When a task becomes eligible to run.
//! - **Virtual Deadline (v_deadline)**: Used to pick which eligible task runs next.
//! - **Weight**: Priority-based weight that determines how much CPU time a task gets.
//! - **SchedContext**: Capability-based CPU time budget management.

extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

use m6_arch::IrqSpinMutex;
use m6_arch::cpu::cpu_id;
use m6_cap::ObjectRef;
use spin::Once;

use crate::cap::object_table::{self, KernelObjectType};
use crate::cap::tcb_storage::TcbFull;
use crate::task::TaskId;

pub mod dispatch;
pub mod eevdf;
pub mod idle;
pub mod run_queue;
pub mod sleep;
pub mod timer_queue;
mod context;

pub use context::{timer_context_switch, enter_userspace};
pub use dispatch::dispatch_task;
pub use run_queue::RunQueue;

// -- Constants

/// Maximum number of CPUs supported.
pub const MAX_CPUS: usize = 8;

/// Fixed-point configuration for virtual-time accounting.
/// We use a 65.63 format (65 integer bits, 63 fractional bits) as recommended
/// by the EEVDF paper to minimise rounding error accumulation.
pub const VT_FIXED_SHIFT: u32 = 63;
pub const VT_ONE: u128 = 1u128 << VT_FIXED_SHIFT;

/// Tolerance used when comparing virtual-time values.
/// Two virtual-time instants whose integer parts differ by no more than this
/// constant are considered equal.
pub const VCLOCK_EPSILON: u128 = VT_ONE;

// -- Reschedule Flag

/// Flag indicating a reschedule is needed (set by timer interrupt).
static NEEDS_RESCHEDULE: AtomicBool = AtomicBool::new(false);

/// Request a reschedule on next opportunity (called from timer interrupt).
#[inline]
pub fn request_reschedule() {
    NEEDS_RESCHEDULE.store(true, AtomicOrdering::Release);
}

/// Check and clear the reschedule flag (called from IRQ handler).
#[inline]
pub fn should_reschedule() -> bool {
    NEEDS_RESCHEDULE.swap(false, AtomicOrdering::AcqRel)
}

/// Check if a reschedule is pending without clearing.
#[inline]
pub fn reschedule_pending() -> bool {
    NEEDS_RESCHEDULE.load(AtomicOrdering::Acquire)
}

// -- Per-CPU Scheduler State

/// Per-CPU scheduler state.
pub struct PerCpuSched {
    /// Task currently running on this CPU.
    current_thread: Option<ObjectRef>,
    /// Run queue for this CPU.
    run_queue: RunQueue,
    /// Idle task for this CPU.
    idle_thread: ObjectRef,
    /// Per-CPU virtual clock (fixed-point 65.63 stored in u128).
    vclock: u128,
    /// Tick count when vclock was last updated.
    last_update_ticks: u64,
    /// Cached sum of weights of all tasks in the run queue.
    total_weight: u64,
    /// CPU ID.
    cpu_id: usize,
}

impl PerCpuSched {
    /// Create new per-CPU scheduler state.
    pub const fn new(cpu_id: usize) -> Self {
        Self {
            current_thread: None,
            run_queue: RunQueue::new(),
            idle_thread: ObjectRef::NULL,
            vclock: 0,
            last_update_ticks: 0,
            total_weight: 0,
            cpu_id,
        }
    }

    /// Set the idle thread for this CPU.
    pub fn set_idle_thread(&mut self, idle_ref: ObjectRef) {
        self.idle_thread = idle_ref;
    }

    /// Get the currently running task.
    #[inline]
    pub fn current(&self) -> Option<ObjectRef> {
        self.current_thread
    }

    /// Get the run queue.
    #[inline]
    pub fn run_queue(&self) -> &RunQueue {
        &self.run_queue
    }

    /// Get mutable access to the run queue.
    #[inline]
    pub fn run_queue_mut(&mut self) -> &mut RunQueue {
        &mut self.run_queue
    }

    /// Get the virtual clock value.
    #[inline]
    pub fn vclock(&self) -> u128 {
        self.vclock
    }

    /// Get the total weight.
    #[inline]
    pub fn total_weight(&self) -> u64 {
        self.total_weight
    }
}

// SAFETY: PerCpuSched is only accessed with proper synchronisation.
unsafe impl Send for PerCpuSched {}

// -- Global Scheduler State

/// Per-CPU scheduler state array.
///
/// Each CPU has its own scheduler state protected by an IrqSpinMutex.
/// Initialised lazily on first access.
static SCHED_STATE: Once<[IrqSpinMutex<PerCpuSched>; MAX_CPUS]> = Once::new();

/// Get the per-CPU scheduler state array, initialising if necessary.
pub fn get_sched_state() -> &'static [IrqSpinMutex<PerCpuSched>; MAX_CPUS] {
    SCHED_STATE.call_once(|| {
        core::array::from_fn(|i| IrqSpinMutex::new(PerCpuSched::new(i)))
    })
}

/// Get the current CPU ID.
#[inline]
fn current_cpu_id() -> usize {
    cpu_id()
}

// -- Public API

/// Initialise the scheduler.
///
/// This should be called once during kernel initialisation.
pub fn init() {
    let _ = get_sched_state();
    log::debug!("Scheduler initialised with {} CPUs", MAX_CPUS);
}

/// Initialise the scheduler for a CPU with its idle task.
pub fn init_cpu(cpu_id: usize, idle_tcb_ref: ObjectRef) {
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();
    sched.set_idle_thread(idle_tcb_ref);
    sched.current_thread = Some(idle_tcb_ref);
    log::debug!("CPU {} scheduler initialised with idle task", cpu_id);
}

/// Get the current task on this CPU.
pub fn current_task() -> Option<ObjectRef> {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    sched_state[cpu_id].lock().current()
}

/// Insert a task into the run queue.
pub fn insert_task(tcb_ref: ObjectRef) {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    // Add to run queue using EEVDF algorithm
    eevdf::add_to_run_queue(&mut sched, tcb_ref);
}

/// Remove a task from the run queue.
pub fn remove_task(tcb_ref: ObjectRef) {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    eevdf::remove_from_run_queue(&mut sched, tcb_ref);
}

/// Yield the current task's remaining time slice.
///
/// The current task remains runnable and the scheduler picks the next
/// task to run. Note: The syscall handler checks if we're the only task
/// and waits for an interrupt if so, to avoid busy-looping.
pub fn yield_current() {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    // Update the current task's EEVDF times so other tasks become eligible
    if let Some(current_ref) = sched.current_thread {
        eevdf::yield_task(&mut sched, current_ref);
    }

    request_reschedule();
}

/// The main scheduling function.
///
/// Picks the next task to run and switches to it.
pub fn schedule() {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    // Get previous task's VSpace for comparison
    let prev_vspace = sched.current_thread
        .and_then(|tcb_ref| run_queue::with_tcb(tcb_ref, |tcb| tcb.tcb.vspace));

    // Mark current task as runnable (if it was running)
    if let Some(current_ref) = sched.current_thread {
        object_table::with_object_mut(current_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We know this is a TCB.
                let _tcb = unsafe { &mut *obj.data.tcb_ptr };
                // Only change Running to Runnable, leave other states alone
                // Note: We use TaskState from task module, not ThreadState from m6-cap
            }
        });
    }

    // Find next task (or use idle task)
    let next = eevdf::find_next_runnable(&sched)
        .unwrap_or(sched.idle_thread);

    if !next.is_valid() {
        log::error!("No runnable task and no idle task!");
        return;
    }

    // Get next task's VSpace
    let next_vspace = run_queue::with_tcb(next, |tcb| tcb.tcb.vspace);

    // Switch VSpace (TTBR0) if address spaces differ
    if prev_vspace != next_vspace {
        context::switch_vspace(next_vspace);
    }

    eevdf::switch_to(&mut sched, next);
}

/// Wake a task by its TaskId.
///
/// This is called from the waker implementation.
pub fn wake_task_by_id(task_id: TaskId) {
    // TaskId uses ObjectRef index as the ID
    let tcb_ref = ObjectRef::from_index(task_id.value() as u32);

    object_table::with_object_mut(tcb_ref, |obj| {
        if obj.obj_type == KernelObjectType::Tcb {
            // SAFETY: We verified the type.
            let tcb = unsafe { &mut *obj.data.tcb_ptr };
            // Wake the task - this will be handled by the task state machine
            // The actual state transition depends on current state
            wake_tcb(tcb);
        }
    });
}

/// Wake a task by ObjectRef.
pub fn wake_task(tcb_ref: ObjectRef) {
    object_table::with_object_mut(tcb_ref, |obj| {
        if obj.obj_type == KernelObjectType::Tcb {
            // SAFETY: We verified the type.
            let tcb = unsafe { &mut *obj.data.tcb_ptr };
            wake_tcb(tcb);
        }
    });
}

/// Internal function to wake a TCB.
fn wake_tcb(tcb: &mut TcbFull) {
    use m6_cap::objects::ThreadState;

    match tcb.tcb.state {
        // Task is sleeping (blocked) - make it runnable
        ThreadState::BlockedOnSend
        | ThreadState::BlockedOnRecv
        | ThreadState::BlockedOnNotification
        | ThreadState::BlockedOnReply => {
            tcb.tcb.state = ThreadState::Running;
        }
        // Task is currently running - it will be woken when it finishes
        ThreadState::Running => {
            // This is the race condition case - the task is being polled
            // and the waker fired. The dispatch loop handles this.
        }
        // Other states - do nothing
        _ => {}
    }
}

/// Charge the current thread for CPU time consumed.
///
/// Called from timer interrupt.
pub fn charge_current_thread() {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let mut sched = sched_state[cpu_id].lock();

    if let Some(current_ref) = sched.current_thread {
        eevdf::charge_time(&mut sched, current_ref);
    }
}

/// Check if preemption should occur.
///
/// Called from timer interrupt.
pub fn should_preempt() -> bool {
    let cpu_id = current_cpu_id();
    let sched_state = get_sched_state();
    let sched = sched_state[cpu_id].lock();

    eevdf::should_preempt(&sched)
}

// -- Async Work Spawning

/// Spawn kernel work on the current task.
///
/// The work will be polled during the dispatch loop before returning
/// to userspace.
pub fn spawn_kernel_work<F>(fut: F)
where
    F: core::future::Future<Output = ()> + 'static + Send,
{
    if let Some(tcb_ref) = current_task() {
        run_queue::with_tcb_mut(tcb_ref, |tcb| {
            tcb.task_ctx.put_kernel_work(alloc::boxed::Box::pin(fut));
        });
    }
}

/// Spawn signal work on a specific task.
///
/// Signal work returns a new user context on success, or an error
/// that will cause the task to be terminated.
pub fn spawn_signal_work<F>(tcb_ref: ObjectRef, fut: F)
where
    F: core::future::Future<Output = Result<crate::task::UserCtx, ()>> + 'static + Send,
{
    run_queue::with_tcb_mut(tcb_ref, |tcb| {
        tcb.task_ctx.put_signal_work(alloc::boxed::Box::pin(fut));
    });
}
