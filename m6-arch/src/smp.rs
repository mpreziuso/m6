//! SMP (Symmetric Multi-Processing) Support
//!
//! Provides secondary CPU startup and synchronisation primitives.
//! Works in conjunction with the PSCI driver to bring up secondary CPUs.

use core::sync::atomic::{AtomicU32, Ordering};

/// Maximum number of CPUs supported
pub const MAX_CPUS: usize = 8;

/// Number of CPUs that have completed initialisation
static CPUS_ONLINE: AtomicU32 = AtomicU32::new(1); // BSP (CPU 0) is online from start

/// Barrier for CPU synchronisation during startup
static CPU_BARRIER: AtomicU32 = AtomicU32::new(0);

/// Get the number of CPUs currently online.
#[inline]
pub fn cpus_online() -> u32 {
    CPUS_ONLINE.load(Ordering::Acquire)
}

/// Increment the online CPU count.
///
/// Called by secondary CPUs when they complete basic initialisation.
#[inline]
pub fn mark_cpu_online() {
    CPUS_ONLINE.fetch_add(1, Ordering::SeqCst);
}

/// Wait for the barrier to reach the expected value.
///
/// Uses WFE (Wait For Event) to avoid busy-spinning.
pub fn wait_for_barrier(expected: u32) {
    while CPU_BARRIER.load(Ordering::Acquire) < expected {
        // Use WFE to wait for an event (SEV from BSP)
        crate::cpu::wait_for_event();
    }
}

/// Release CPUs waiting on the barrier.
///
/// Called by BSP to signal secondary CPUs to proceed.
pub fn release_barrier(value: u32) {
    CPU_BARRIER.store(value, Ordering::Release);
    // Send event to wake all CPUs waiting on WFE
    crate::cpu::send_event();
}

/// Get the current barrier value.
#[inline]
pub fn barrier_value() -> u32 {
    CPU_BARRIER.load(Ordering::Acquire)
}

/// Reset SMP state (for testing or system reset).
pub fn reset_smp_state() {
    CPUS_ONLINE.store(1, Ordering::SeqCst);
    CPU_BARRIER.store(0, Ordering::SeqCst);
}
