//! Timer Queue for Timer Kernel Objects
//!
//! Maintains a priority queue of armed timers ordered by expiry time.
//! The timer interrupt handler calls `process_expirations()` to
//! check for expired timers and signal their bound notifications.

extern crate alloc;

use alloc::collections::BinaryHeap;
use alloc::vec::Vec;
use core::cmp::Ordering;

use m6_arch::IrqSpinMutex;
use m6_cap::ObjectRef;
use m6_pal::timer;
use spin::Once;

use crate::cap::object_table;

/// Entry in the timer queue.
struct TimerEntry {
    /// Expiry time (in timer ticks).
    expiry_ticks: u64,
    /// Timer object reference.
    timer_ref: ObjectRef,
}

impl PartialEq for TimerEntry {
    fn eq(&self, other: &Self) -> bool {
        self.expiry_ticks == other.expiry_ticks && self.timer_ref == other.timer_ref
    }
}

impl Eq for TimerEntry {}

impl PartialOrd for TimerEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimerEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse ordering for min-heap: earliest expiry first
        // BinaryHeap is a max-heap, so we reverse the comparison
        other.expiry_ticks.cmp(&self.expiry_ticks)
            .then_with(|| other.timer_ref.index().cmp(&self.timer_ref.index()))
    }
}

/// Global timer queue.
static TIMER_QUEUE: Once<IrqSpinMutex<BinaryHeap<TimerEntry>>> = Once::new();

/// Get the timer queue, initialising if necessary.
fn get_timer_queue() -> &'static IrqSpinMutex<BinaryHeap<TimerEntry>> {
    TIMER_QUEUE.call_once(|| IrqSpinMutex::new(BinaryHeap::new()))
}

/// Register a timer in the queue.
///
/// # Arguments
///
/// * `timer_ref` - The timer object reference.
/// * `expiry_ns` - Nanoseconds from now until expiry.
pub fn register_timer(timer_ref: ObjectRef, expiry_ns: u64) {
    let freq = timer::frequency();
    if freq == 0 {
        return;
    }

    let now_ticks = timer::read_counter();
    let expiry_ticks = now_ticks + (expiry_ns * freq) / 1_000_000_000;

    get_timer_queue().lock().push(TimerEntry {
        expiry_ticks,
        timer_ref,
    });
}

/// Register a timer with absolute expiry time.
///
/// # Arguments
///
/// * `timer_ref` - The timer object reference.
/// * `expiry_ticks` - Absolute tick count for expiry.
pub fn register_timer_ticks(timer_ref: ObjectRef, expiry_ticks: u64) {
    get_timer_queue().lock().push(TimerEntry {
        expiry_ticks,
        timer_ref,
    });
}

/// Unregister a timer from the queue.
///
/// Note: This is O(n) but timers are expected to be few.
pub fn unregister_timer(timer_ref: ObjectRef) {
    let mut queue = get_timer_queue().lock();

    // Drain and filter
    let entries: Vec<_> = queue.drain()
        .filter(|e| e.timer_ref != timer_ref)
        .collect();

    // Re-insert remaining entries
    for entry in entries {
        queue.push(entry);
    }
}

/// Process expired timers.
///
/// Called from the timer interrupt handler.
/// Checks each expired timer, signals its bound notification, and handles
/// periodic timer re-arming.
pub fn process_expirations() {
    let now_ticks = timer::read_counter();
    let mut queue = get_timer_queue().lock();
    let mut to_reinsert: Vec<TimerEntry> = Vec::new();

    while let Some(entry) = queue.peek() {
        if entry.expiry_ticks > now_ticks {
            break; // Earliest timer not yet expired
        }

        let entry = queue.pop().unwrap();

        // Process the expired timer
        if let Some(new_entry) = process_timer_expiry(entry.timer_ref, now_ticks) {
            to_reinsert.push(new_entry);
        }
    }

    // Re-insert periodic timers
    for entry in to_reinsert {
        queue.push(entry);
    }
}

/// Process a single timer expiry.
///
/// Returns a new entry if the timer is periodic and should be re-armed.
fn process_timer_expiry(timer_ref: ObjectRef, now_ticks: u64) -> Option<TimerEntry> {
    use m6_cap::objects::TimerState;
    use crate::ipc::notification::do_signal;

    // Access timer under lock, get signal info
    let rearm_info = object_table::with_timer_mut(timer_ref, |timer| {
        if timer.state != TimerState::Armed {
            return None;
        }

        let notif = timer.notification;
        let badge = timer.badge.value();
        let periodic = timer.is_periodic;
        let period = timer.period_ns;

        // Disarm one-shot timers
        if !periodic {
            timer.disarm();
        }

        Some((notif, badge, periodic, period))
    });

    // Signal notification (outside lock)
    if let Some((notif, badge, periodic, period)) = rearm_info.flatten() {
        if let Err(e) = do_signal(notif, badge) {
            log::warn!("Timer expiry failed to signal {:?}: {:?}", notif, e);
        }

        // Re-arm periodic timer
        if periodic && period > 0 {
            let freq = timer::frequency();
            if freq > 0 {
                let period_ticks = (period.saturating_mul(freq)) / 1_000_000_000;
                return Some(TimerEntry {
                    expiry_ticks: now_ticks.saturating_add(period_ticks),
                    timer_ref,
                });
            }
        }
    }

    None
}

/// Check if the timer queue is empty.
pub fn is_empty() -> bool {
    get_timer_queue().lock().is_empty()
}

/// Get the number of pending timers.
pub fn len() -> usize {
    get_timer_queue().lock().len()
}

/// Get the time until the next timer expiry.
///
/// Returns `None` if the queue is empty.
pub fn time_until_next_expiry() -> Option<u64> {
    let now_ticks = timer::read_counter();
    let queue = get_timer_queue().lock();

    queue.peek().map(|entry| {
        if entry.expiry_ticks > now_ticks {
            let freq = timer::frequency();
            if freq > 0 {
                let delta_ticks = entry.expiry_ticks - now_ticks;
                (delta_ticks * 1_000_000_000) / freq
            } else {
                0
            }
        } else {
            0
        }
    })
}
