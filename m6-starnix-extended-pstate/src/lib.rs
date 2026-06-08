// extended_pstate — Starnix-fork shim for M6 (no_std).
//
// Ported from Fuchsia `//src/starnix/lib/extended_pstate`. Per the M6 port we
// keep ONLY the aarch64 backend (the project targets ARM64). For non-aarch64
// host builds a portable, asm-free fallback `State`/`Aarch32State` is provided
// purely so the crate still type-checks; it performs no real save/restore.
#![no_std]

#[cfg(target_arch = "aarch64")]
mod aarch64;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;

// -- Fallback backend for non-aarch64 host builds (compile-only).
#[cfg(not(target_arch = "aarch64"))]
mod fallback {
    #[derive(Clone, Copy, Default)]
    pub struct State {
        pub q: [u128; 32],
        pub fpcr: u32,
        pub fpsr: u32,
    }

    impl State {
        pub(crate) fn save(&mut self) {}
        /// # Safety
        /// No-op on non-aarch64; safe placeholder.
        pub(crate) unsafe fn restore(&self) {}
        pub fn reset(&mut self) {
            *self = Default::default();
        }
    }

    #[derive(Clone, Copy, Default)]
    pub struct Aarch32State {
        pub q: [u128; 16],
        pub fpcr: u32,
        pub fpsr: u32,
    }

    impl Aarch32State {
        pub(crate) fn save(&mut self) {}
        /// # Safety
        /// No-op on non-aarch64; safe placeholder.
        pub(crate) unsafe fn restore(&self) {}
        pub fn reset(&mut self) {
            *self = Default::default();
        }
    }
}

#[cfg(not(target_arch = "aarch64"))]
use fallback as arch;

// -- Full extended pstate state

#[derive(Clone, Copy, Default)]
pub struct ExtendedPstateState {
    state: arch::State,
}

/// A version of [`ExtendedPstateState`] that only stores the processor state
/// accessible from AArch32 (e.g., registers Q0-Q15).
#[derive(Clone, Copy, Default)]
pub struct ExtendedAarch32PstateState {
    state: arch::Aarch32State,
}

impl ExtendedAarch32PstateState {
    #[inline(always)]
    pub fn save(&mut self) {
        self.state.save()
    }

    /// This restores the extended processor state saved in this object into the processor's state
    /// registers.
    ///
    /// # Safety
    ///
    /// This clobbers the current vector register, floating point register, and floating
    /// point status and control register state including callee-saved registers. This should be
    /// used in conjunction with save() to switch to an alternate extended processor state.
    #[inline(always)]
    pub unsafe fn restore(&self) {
        // SAFETY: forwarded to the backend; caller upholds the documented contract.
        unsafe { self.state.restore() }
    }

    pub fn reset(&mut self) {
        self.state.reset()
    }
}

impl ExtendedPstateState {
    /// This saves the current extended processor state to this state object.
    #[inline(always)]
    fn save(&mut self) {
        self.state.save()
    }

    /// This restores the extended processor state saved in this object into the processor's state
    /// registers.
    ///
    /// # Safety
    ///
    /// This clobbers the current vector register, floating point register, and floating
    /// point status and control register state including callee-saved registers. This should be
    /// used in conjunction with save() to switch to an alternate extended processor state.
    #[inline(always)]
    unsafe fn restore(&self) {
        // SAFETY: forwarded to the backend; caller upholds the documented contract.
        unsafe { self.state.restore() }
    }

    pub fn reset(&mut self) {
        self.state.reset()
    }

    pub fn get_arm64_qregs(&self) -> &[u128; 32] {
        &self.state.q
    }

    pub fn get_arm64_fpsr(&self) -> u32 {
        self.state.fpsr
    }

    pub fn get_arm64_fpcr(&self) -> u32 {
        self.state.fpcr
    }

    pub fn set_arm64_state(&mut self, qregs: &[u128; 32], fpsr: u32, fpcr: u32) {
        self.state.q = *qregs;
        self.state.fpsr = fpsr;
        self.state.fpcr = fpcr;
    }
}

/// Stores a pointer to the currently active extended pstate storage.
/// The caller to the C entry points is responsible for ensuring that the active union
/// member corresponds to the entry points being called.
#[repr(C)]
pub union ExtendedPstatePointer {
    pub extended_pstate: *mut ExtendedPstateState,
    pub extended_aarch32_pstate: *mut ExtendedAarch32PstateState,
}

/// Restores the current extended architectural process state.
///
/// # Safety
///    - state_addr must point to a pointer to an instance of ExtendedPstatePointer.
///    - The active member of the ExtendedPstatePointer union must be extended_pstate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn restore_extended_pstate(state_addr: usize) {
    let pointer = state_addr as *const ExtendedPstatePointer;
    // SAFETY: per the documented contract, `state_addr` points to an
    // ExtendedPstatePointer whose active member is `extended_pstate`, which in
    // turn points to a valid ExtendedPstateState.
    unsafe {
        let state = (*pointer).extended_pstate;
        (*state).restore()
    }
}

/// Save the current extended architectural process state.
///
/// # Safety
///    - state_addr must point to pointer to an exclusively owned instance of ExtendedPstateState.
///    - The active member of the ExtendedPstatePointer union must be extended_pstate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn save_extended_pstate(state_addr: usize) {
    let pointer = state_addr as *const ExtendedPstatePointer;
    // SAFETY: per the documented contract, `state_addr` points to an
    // ExtendedPstatePointer whose active member is `extended_pstate`, which in
    // turn points to an exclusively-owned, valid ExtendedPstateState.
    unsafe {
        let state = (*pointer).extended_pstate;
        (*state).save()
    }
}

/// Restores the current extended AArch32-visible architectural process state.
///
/// # Safety
///    - state_addr must point to pointer to an instance of ExtendedAarch32PstateState.
///    - The active member of the ExtendedPstatePointer union must be extended_aarch32_pstate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn restore_extended_aarch32_pstate(state_addr: usize) {
    let pointer = state_addr as *const ExtendedPstatePointer;
    // SAFETY: per the documented contract, `state_addr` points to an
    // ExtendedPstatePointer whose active member is `extended_aarch32_pstate`,
    // which in turn points to a valid ExtendedAarch32PstateState.
    unsafe {
        let state = (*pointer).extended_aarch32_pstate;
        (*state).restore()
    }
}

/// Saves the current extended AArch32-visible architectural process state.
///
/// # Safety
///    - state_addr must point to a pointer to an exclusively owned instance of
///      ExtendedAarch32PstateState.
///    - The active member of the ExtendedPstatePointer union must be extended_aarch32_pstate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn save_extended_aarch32_pstate(state_addr: usize) {
    let pointer = state_addr as *const ExtendedPstatePointer;
    // SAFETY: per the documented contract, `state_addr` points to an
    // ExtendedPstatePointer whose active member is `extended_aarch32_pstate`,
    // which in turn points to an exclusively-owned, valid ExtendedAarch32PstateState.
    unsafe {
        let state = (*pointer).extended_aarch32_pstate;
        (*state).save()
    }
}
