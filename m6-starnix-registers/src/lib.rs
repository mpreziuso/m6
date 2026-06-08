// starnix_registers — Starnix-fork shim for M6 (no_std).
//
// Forked from Fuchsia's starnix_registers, adapted for M6 (no_std, aarch64 only).
// Original: Copyright 2025 The Fuchsia Authors. BSD-style license.
//
// Provides the register-storage abstractions (`RegisterStorage`, `RegisterState<T>`,
// `RegisterStorageEnum`, `HeapRegs`) that the forked Starnix `arch/`, `task/`, `signals/`
// and `ptrace/` modules build `ThreadState<R: RegisterStorage>` around.
//
// The register frame mirrors the Zircon `zx::sys::zx_restricted_state_t` aarch64 layout
// exactly (as upstream does); M6's restricted-mode shim re-exposes that struct via the `zx`
// crate (m6-zx-shim). The native M6 register frame is `m6-starnix/src/syscall_loop.rs::
// StateFrame` (ExceptionContext). The eventual syscall_loop integration converts between
// `StateFrame` and `RegisterState`; for now matching `zx_restricted_state_t` (as upstream
// does) is the correct interim representation.
//
// Upstream's `RestrictedState` (which maps a Zircon restricted-state VMO via fuchsia_runtime)
// is intentionally omitted: it depends on std + fuchsia_runtime and is not consumed by the
// fork. The `RegisterStorageEnum::Vmo` variant is retained for API parity; populating it with
// a live mapping is a TODO for the syscall_loop integration.

#![no_std]

extern crate alloc;

#[cfg(target_arch = "aarch64")]
mod arm64;

#[cfg(target_arch = "aarch64")]
pub use arm64::*;

use alloc::boxed::Box;
use core::fmt;
use core::ops::Deref;
use core::ptr::NonNull;
use static_assertions::assert_not_impl_any;

// -- CPSR mask constants
//
// Upstream sources these from `zx::sys` (zx-types). M6's zx shim does not expose them, so they
// are defined locally here with the canonical Zircon aarch64 values.

/// Set in `cpsr` when the thread is executing in aarch32 (compat) mode.
pub const ZX_REG_CPSR_ARCH_32_MASK: u64 = 0x10;
/// Set in `cpsr` when the aarch32 thread is executing in Thumb mode.
pub const ZX_REG_CPSR_THUMB_MASK: u64 = 0x20;

// -- RegisterStorage

/// Storage backing a [`RegisterState`]: either a heap allocation or a mapped restricted-state VMO.
///
/// Derefs to the underlying [`zx::sys::zx_restricted_state_t`].
pub trait RegisterStorage:
    Deref<Target = zx::sys::zx_restricted_state_t>
    + core::ops::DerefMut
    + Eq
    + PartialEq
    + fmt::Debug
    + Clone
{
}

// -- MappedVmoRegs

/// Registers stored in a mapped restricted-state VMO.
///
/// The pointer is populated by the restricted-mode binding step in the syscall loop. It is tied
/// to the owning `CurrentTask`, hence neither `Send` nor `Sync`.
#[derive(Eq, PartialEq, Clone)]
struct MappedVmoRegs(NonNull<zx::sys::zx_restricted_state_t>);
// MappedVmoRegs should be tied to the CurrentTask, so it is not Send or Sync.
assert_not_impl_any!(MappedVmoRegs: Send, Sync);

impl fmt::Debug for MappedVmoRegs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MappedVmoRegs")
            .field(&format_args!("{:?}", self.deref()))
            .finish()
    }
}

impl Deref for MappedVmoRegs {
    type Target = zx::sys::zx_restricted_state_t;

    fn deref(&self) -> &Self::Target {
        // SAFETY: The pointer is valid and points to a valid `zx_restricted_state_t` for the
        // lifetime of the owning task's restricted-state binding.
        unsafe { self.0.as_ref() }
    }
}

impl core::ops::DerefMut for MappedVmoRegs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: The pointer is valid and points to a valid `zx_restricted_state_t` for the
        // lifetime of the owning task's restricted-state binding.
        unsafe { self.0.as_mut() }
    }
}

impl RegisterStorage for MappedVmoRegs {}

// -- HeapRegs

/// Registers stored on the heap. Used during task initialisation before a restricted-state VMO
/// is bound.
#[derive(Eq, PartialEq, Debug, Clone, Default)]
pub struct HeapRegs(Box<zx::sys::zx_restricted_state_t>);

impl Deref for HeapRegs {
    type Target = zx::sys::zx_restricted_state_t;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for HeapRegs {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl RegisterStorage for HeapRegs {}

impl From<RegisterStorageEnum> for HeapRegs {
    fn from(regs: RegisterStorageEnum) -> Self {
        match regs {
            RegisterStorageEnum::Vmo(vmo) => HeapRegs(Box::new(*vmo)),
            RegisterStorageEnum::Heap(heap) => heap,
        }
    }
}

// -- RegisterStorageEnum

/// Holds registers in either a heap allocation or a mapped VMO.
///
/// This allows `CurrentTask` to store registers on the heap during initialisation and link to the
/// VMO once the restricted-state binding is created.
#[derive(Eq, PartialEq, Debug)]
pub enum RegisterStorageEnum {
    // Keep it private to prevent using it directly.
    #[allow(private_interfaces)]
    Vmo(MappedVmoRegs),
    Heap(HeapRegs),
}
assert_not_impl_any!(RegisterStorageEnum: Send, Sync);

impl Deref for RegisterStorageEnum {
    type Target = zx::sys::zx_restricted_state_t;

    fn deref(&self) -> &Self::Target {
        match self {
            RegisterStorageEnum::Vmo(vmo) => vmo.deref(),
            RegisterStorageEnum::Heap(heap) => heap.deref(),
        }
    }
}

impl core::ops::DerefMut for RegisterStorageEnum {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            RegisterStorageEnum::Vmo(vmo) => vmo.deref_mut(),
            RegisterStorageEnum::Heap(heap) => heap.deref_mut(),
        }
    }
}

impl Clone for RegisterStorageEnum {
    fn clone(&self) -> RegisterStorageEnum {
        RegisterStorageEnum::Heap(HeapRegs(Box::new(**self)))
    }
}

impl RegisterStorage for RegisterStorageEnum {}

impl From<MappedVmoRegs> for RegisterStorageEnum {
    fn from(regs: MappedVmoRegs) -> Self {
        RegisterStorageEnum::Vmo(regs)
    }
}

impl From<HeapRegs> for RegisterStorageEnum {
    fn from(regs: HeapRegs) -> Self {
        RegisterStorageEnum::Heap(regs)
    }
}
