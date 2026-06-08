//! Zircon API compatibility shim backed by M6 capabilities
//!
//! Provides the Zircon (`zx::`) types that the forked Fuchsia Starnix code
//! references, so that forked code compiles. The fork renames this crate to
//! `zx`. Pure-data types (time, signals, koid, name, status) are implemented
//! faithfully; handle-backed types are minimal stubs carrying the exact method
//! signatures the fork calls — they are not yet wired to M6 syscalls.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod cprng;
mod exception;
mod flags;
mod handle;
mod identity;
mod info;
pub mod mem_context;
mod object;
mod packet;
mod process;
mod rights;
mod signals;
mod status;
pub mod sys;
mod thread;
mod time;
mod timer;
mod vmar;
mod vmo;

pub use cprng::{cprng_draw, cprng_draw_uninit};
pub use exception::{ExceptionArchData, ExceptionReport, ExceptionType, PolicyCode};
pub use flags::{
    ClockOpts, CpuFeatureFlags, JobCriticalOptions, PagerOptions, ProcessOptions,
    RaiseExceptionOptions, TransferDataOptions, VmarFlagsExtended, VmarOp, VmoInfoFlags, VmoOp,
    WaitAsyncOpts,
};
pub use handle::Handle;
pub use identity::{Koid, Name, ObjectType, ZX_MAX_NAME_LEN};
pub use info::{
    ClockDetails, ClockTransformation, MapDetails, MapInfo, MappingDetails, VmarInfo, VmoInfo,
};
pub use object::{
    AsHandleRef, BootTimer, Channel, Clock, Counter, Event, EventPair, HandleBasicInfo,
    HandleBased, HandleRef as ObjectHandleRef, NullableHandle, Pager, Port, Profile, Resource,
    Socket, Task, Unowned, WaitResult,
};
pub use packet::{Packet, PacketContents, PagerPacket, UserPacket};
pub use process::Process;
pub use rights::Rights;
pub use signals::Signals;
pub use status::Status;
pub use thread::{TaskRuntimeInfo, Thread, ThreadStats};
pub use time::{
    BootDuration, BootDurationTicks, BootInstant, BootTicks, BootTimeline, Duration, Instant,
    MonotonicDuration, MonotonicDurationTicks, MonotonicInstant, MonotonicTicks, MonotonicTimeline,
    NsUnit, SyntheticDuration, SyntheticInstant, SyntheticTimeline, Ticks, TicksUnit, Timeline,
    TimeUnit, UtcDuration, UtcInstant, UtcTimeline,
};
pub use timer::Timer;
pub use vmar::{Vmar, VmarFlags};
pub use vmo::{Vmo, VmoChildOptions, VmoOptions};

/// Page size constant (ARM64).
#[inline]
pub fn system_get_page_size() -> u32 {
    4096
}

/// Returns the number of logical CPUs. Stub: reports a single CPU.
#[inline]
pub fn system_get_num_cpus() -> u32 {
    1
}

/// Returns the amount of physical memory, in bytes. Stub: reports 1 GiB until
/// the M6 boot info is threaded through.
#[inline]
pub fn system_get_physmem() -> u64 {
    1024 * 1024 * 1024
}

/// Returns the reported CPU feature flags for the requested feature type.
///
/// Stub: reports an empty feature set.
#[inline]
pub fn system_get_feature_flags<T: bitflags::Flags<Bits = u32>>() -> Result<T, Status> {
    Ok(T::empty())
}

/// Maps a raw status code to `Ok(())` on success or `Err(Status)` otherwise.
#[inline]
pub fn ok(raw: i32) -> Result<(), Status> {
    Status::ok(raw)
}

/// Convenience alias used throughout Starnix.
pub type HandleRef<'a> = &'a Handle;
