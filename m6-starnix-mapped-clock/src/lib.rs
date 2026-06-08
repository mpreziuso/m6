// mapped_clock — Starnix-fork shim for M6 (no_std).
//
// Ported from Fuchsia `//src/lib/mapped-clock`. Implements a clock backed by
// memory mapped into this process' address space.
//
// M6 adaptation: upstream relies on Zircon syscalls that the M6 `zx` shim does
// not yet provide (`Clock::get_mapped_size`, `Vmar::map_clock`,
// `Clock::read_mapped`, `Clock::get_details_mapped`). Those paths are provided
// as documented functional stubs returning plausible values:
//   * the mapping address is derived from the parent VMAR's base + offset;
//   * `read()` returns the backstop (zero) on this clock's output timeline;
//   * `get_details()` returns default details.
// The clock argument is accepted generically so any caller-side clock handle
// type (e.g. the fork's `UtcClock`) resolves at the call site.
#![no_std]

use core::marker::PhantomData;

use zx::sys::zx_clock_rate_t;
use zx::{ClockDetails, ClockTransformation, Instant, Status, Timeline, Vmar, VmarFlags};

/// The size of the memory region used by the memory mapped clock. While in theory this size could
/// change in future Fuchsia releases, in practice it is likely never going to. So we expose it
/// as a constant.
pub const CLOCK_SIZE: usize = 4096;

/// A clock backed by memory mapped into this process' virtual address space.
///
/// A memory mapped clock can be read more efficiently than a regular kernel
/// clock object in contexts where making syscalls are undesirable, for example
/// for efficiency reasons.
///
/// A memory mapped clock will clean up after itself when going out of scope.
///
/// To create one, you will need a clock handle, a [`zx::Vmar`] and a call to
/// [`MappedClock::try_new`].
#[derive(Debug)]
pub struct MappedClock<Reference: Timeline, Output: Timeline> {
    // The virtual address of the memory mapped clock.
    addr: usize,
    // The size of the memory area used by this mappable clock. It is constant
    // for the lifetime of the clock.
    clock_size: usize,
    // Unmap the clock when dropping MappedClock.
    unmap_on_drop: bool,
    _mark: PhantomData<(Reference, Output)>,
}

impl<Reference: Timeline, Output: Timeline> Drop for MappedClock<Reference, Output> {
    fn drop(&mut self) {
        if self.unmap_on_drop {
            // M6 stub: there is no real mapping to tear down yet. When the `zx`
            // shim gains `Vmar::map_clock`/`unmap` for clocks this should unmap
            // `self.addr` for `self.clock_size` bytes.
        }
    }
}

impl<Reference: Timeline, Output: Timeline> MappedClock<Reference, Output> {
    /// Tries to convert the supplied regular `clock` into a memory mapped clock.
    ///
    /// A memory mapped clock can be read more efficiently than a regular kernel
    /// clock object in contexts where calling into the kernel is undesirable.
    ///
    /// To ensure that there is no confusion as to how the clock is accessed, this
    /// conversion consumes the clock handle, and is not reversible.
    ///
    /// # Args
    ///
    /// - `clock`: the clock to convert to a mapped clock.
    /// - `parent_vmar`: a handle to the virtual memory address range to map the clock into.
    /// - `vmar_flags`: flags to apply when mapping the clock. Usually this needs to be at least
    ///   `zx::VmarFlags::PERM_READ`.
    pub fn try_new<C>(
        clock: C,
        parent_vmar: &Vmar,
        vmar_flags: VmarFlags,
    ) -> Result<MappedClock<Reference, Output>, Status> {
        Self::try_new_internal(
            &clock,
            parent_vmar,
            vmar_flags,
            /* unmap_on_drop= */ true,
            /* offset= */ 0,
        )
    }

    /// Same as [`Self::try_new`], but allows mapping with a specified offset.
    ///
    /// # Args
    ///
    /// Same as [`Self::try_new`], except:
    /// - `vmar_flags`: must include `SPECIFIC` if `offset` is not zero.
    pub fn try_new_with_offset<C>(
        clock: C,
        parent_vmar: &Vmar,
        vmar_flags: VmarFlags,
        offset: u64,
    ) -> Result<MappedClock<Reference, Output>, Status> {
        Self::try_new_internal(&clock, parent_vmar, vmar_flags, /* unmap_on_drop= */ true, offset)
    }

    /// Same as [`Self::try_new`], but does not unmap the clock at end of this struct's lifetime.
    pub fn try_new_without_unmap<C>(
        clock: &C,
        parent_vmar: &Vmar,
        vmar_flags: VmarFlags,
        offset: u64,
    ) -> Result<MappedClock<Reference, Output>, Status> {
        Self::try_new_internal(clock, parent_vmar, vmar_flags, /* unmap_on_drop= */ false, offset)
    }

    fn try_new_internal<C>(
        _clock: &C,
        parent_vmar: &Vmar,
        _vmar_flags: VmarFlags,
        unmap_on_drop: bool,
        offset: u64,
    ) -> Result<MappedClock<Reference, Output>, Status> {
        let offset: usize = offset.try_into().map_err(|_| Status::INTERNAL)?;

        // M6 stub: derive a plausible mapping address within the parent VMAR.
        // A real implementation would call `Vmar::map_clock`, which maps the
        // kernel clock page and returns its virtual address.
        let base: usize = parent_vmar.base().try_into().map_err(|_| Status::INTERNAL)?;
        let addr = base.checked_add(offset).ok_or(Status::OUT_OF_RANGE)?;

        Ok(Self { addr, clock_size: CLOCK_SIZE, unmap_on_drop, _mark: PhantomData })
    }

    /// Returns the raw value of the address this clock is mapped to.
    pub fn raw_addr(&self) -> usize {
        self.addr
    }

    /// The size of the memory region occupied by this memory mapped clock.
    pub fn size(&self) -> usize {
        self.clock_size
    }

    /// Read the clock indication.
    ///
    /// M6 stub: returns the backstop (zero) on the output timeline. A real
    /// implementation reads the memory-mapped clock at `self.addr`.
    pub fn read(&self) -> Result<Instant<Output>, Status> {
        Ok(Instant::from_nanos(0))
    }

    /// Get the clock details, such as backstop time and similar.
    ///
    /// M6 stub: returns default details. A real implementation reads the
    /// memory-mapped clock details at `self.addr`.
    pub fn get_details(&self) -> Result<ClockDetails<Reference, Output>, Status> {
        Ok(ClockDetails {
            backstop: Instant::from_nanos(0),
            reference_to_synthetic: ClockTransformation {
                reference_offset: Instant::from_nanos(0),
                synthetic_offset: Instant::from_nanos(0),
                rate: zx_clock_rate_t { synthetic_ticks: 1, reference_ticks: 1 },
            },
            generation_counter: 0,
        })
    }
}
