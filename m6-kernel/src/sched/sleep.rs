//! Sleep Queue for Timer-Based Task Wakeups
//!
//! Maintains a priority queue of sleeping tasks ordered by wakeup time.
//! The timer interrupt handler calls `process_wakeups()` to wake tasks.

extern crate alloc;

use alloc::collections::BinaryHeap;
use core::cmp::Ordering;

use m6_arch::IrqSpinMutex;
use m6_cap::ObjectRef;
use m6_cap::objects::ThreadState;
use m6_pal::timer;
use spin::Once;

use super::run_queue::with_tcb_mut;

/// Entry in the sleep queue.
struct SleepEntry {
    /// When to wake up (in timer ticks).
    wakeup_ticks: u64,
    /// Task to wake.
    tcb_ref: ObjectRef,
}

impl PartialEq for SleepEntry {
    fn eq(&self, other: &Self) -> bool {
        self.wakeup_ticks == other.wakeup_ticks && self.tcb_ref == other.tcb_ref
    }
}

impl Eq for SleepEntry {}

impl PartialOrd for SleepEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SleepEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap: earliest wakeup first
        // BinaryHeap is a max-heap, so we reverse the comparison
        other
            .wakeup_ticks
            .cmp(&self.wakeup_ticks)
            .then_with(|| other.tcb_ref.index().cmp(&self.tcb_ref.index()))
    }
}

/// Global sleep queue.
static SLEEP_QUEUE: Once<IrqSpinMutex<BinaryHeap<SleepEntry>>> = Once::new();

/// Get the sleep queue, initialising if necessary.
fn get_sleep_queue() -> &'static IrqSpinMutex<BinaryHeap<SleepEntry>> {
    SLEEP_QUEUE.call_once(|| IrqSpinMutex::new(BinaryHeap::new()))
}

/// Add a task to the sleep queue.
///
/// The task should already be marked as sleeping before calling this.
///
/// # Arguments
///
/// * `tcb_ref` - The task to sleep.
/// * `wakeup_ns` - Nanoseconds from now until wakeup.
pub fn sleep_for(tcb_ref: ObjectRef, wakeup_ns: u64) {
    let freq = timer::frequency();
    if freq == 0 {
        return;
    }

    let now_ticks = timer::read_counter();
    let wakeup_ticks = now_ticks + (wakeup_ns * freq) / 1_000_000_000;

    get_sleep_queue().lock().push(SleepEntry {
        wakeup_ticks,
        tcb_ref,
    });
}

/// Add a task to the sleep queue with absolute wakeup time.
///
/// # Arguments
///
/// * `tcb_ref` - The task to sleep.
/// * `wakeup_ticks` - Absolute tick count for wakeup.
pub fn sleep_until_ticks(tcb_ref: ObjectRef, wakeup_ticks: u64) {
    get_sleep_queue().lock().push(SleepEntry {
        wakeup_ticks,
        tcb_ref,
    });
}

/// Check and wake all tasks whose wakeup time has passed.
///
/// Called from the timer interrupt handler.
pub fn process_wakeups() {
    let now_ticks = timer::read_counter();

    // Collect expired entries under the sleep queue lock, then release
    // before touching the scheduler, to avoid nested lock acquisition.
    let mut to_wake: [Option<ObjectRef>; 8] = [None; 8];
    let mut count = 0;

    {
        let mut queue = get_sleep_queue().lock();
        while let Some(entry) = queue.peek() {
            if entry.wakeup_ticks <= now_ticks {
                let entry = queue.pop().unwrap();
                if count < to_wake.len() {
                    to_wake[count] = Some(entry.tcb_ref);
                    count += 1;
                } else {
                    // Overflow: wake inline (rare, >8 simultaneous wakeups)
                    wake_sleeping_task(entry.tcb_ref);
                }
            } else {
                break;
            }
        }
    }

    for slot in &to_wake[..count] {
        if let Some(tcb_ref) = slot {
            wake_sleeping_task(*tcb_ref);
        }
    }
}

/// Wake a specific sleeping task.
fn wake_sleeping_task(tcb_ref: ObjectRef) {
    let should_enqueue = with_tcb_mut(tcb_ref, |tcb| -> bool {
        // Only wake if the task is in a sleeping/blocked state
        match tcb.tcb.state {
            ThreadState::Sleeping
            | ThreadState::BlockedOnNotification
            | ThreadState::BlockedOnSend
            | ThreadState::BlockedOnRecv
            | ThreadState::BlockedOnReply => {
                tcb.tcb.state = ThreadState::Running;
                true
            }
            ThreadState::Running => {
                // Task was woken while still running (race condition)
                false
            }
            _ => {
                // Other states - don't change
                false
            }
        }
    });

    // Re-insert into the scheduler's run queue so the task actually gets scheduled.
    // This mirrors the IPC wakeup pattern (e.g. endpoint.rs reply_to_caller).
    if should_enqueue.unwrap_or(false) {
        super::insert_task(tcb_ref);
    }
}

/// Get the time until the next wakeup (for potential timer optimisation).
///
/// Returns `None` if the queue is empty or time cannot be determined.
pub fn time_until_next_wakeup() -> Option<u64> {
    let now_ticks = timer::read_counter();
    let queue = get_sleep_queue().lock();

    queue.peek().map(|entry| {
        if entry.wakeup_ticks > now_ticks {
            let freq = timer::frequency();
            if freq > 0 {
                let delta_ticks = entry.wakeup_ticks - now_ticks;
                (delta_ticks * 1_000_000_000) / freq
            } else {
                0
            }
        } else {
            0
        }
    })
}

/// Check if the sleep queue is empty.
pub fn is_empty() -> bool {
    get_sleep_queue().lock().is_empty()
}

/// Get the number of sleeping tasks.
pub fn len() -> usize {
    get_sleep_queue().lock().len()
}
