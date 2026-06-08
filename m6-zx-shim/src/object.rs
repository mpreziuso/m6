//! Handle-backed Zircon object stubs and the handle traits
//!
//! These types satisfy the forked Starnix code's references to Zircon kernel
//! objects. They are minimal stubs: each carries an opaque [`NullableHandle`]
//! and exposes the method signatures the fork calls. Operations that would
//! require a live kernel object return plausible values or
//! [`Status::NOT_SUPPORTED`] — they are not yet wired to M6 capabilities.

use crate::identity::{Koid, Name, ObjectType};
use crate::signals::Signals;
use crate::sys::zx_handle_t;
use crate::time::MonotonicInstant;
use crate::{Rights, Status};

// -- Raw handle wrappers

/// A handle that may be invalid. The general-purpose owning handle type.
#[derive(Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct NullableHandle(zx_handle_t);

impl NullableHandle {
    /// The invalid handle.
    pub const fn invalid() -> Self {
        Self(0)
    }

    /// Builds a handle from a raw value.
    pub const fn from_raw(raw: zx_handle_t) -> Self {
        Self(raw)
    }

    /// Returns the raw handle value.
    pub const fn raw(&self) -> zx_handle_t {
        self.0
    }

    /// Returns whether this handle is invalid.
    pub const fn is_invalid(&self) -> bool {
        self.0 == 0
    }
}

/// A borrowed reference to a handle.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct HandleRef<'a> {
    raw: zx_handle_t,
    _marker: core::marker::PhantomData<&'a NullableHandle>,
}

impl HandleRef<'_> {
    /// Builds a handle reference for a raw value with an arbitrary lifetime.
    pub(crate) const fn from_raw(raw: zx_handle_t) -> Self {
        Self {
            raw,
            _marker: core::marker::PhantomData,
        }
    }

    /// Returns whether the referenced handle is invalid.
    pub const fn is_invalid(&self) -> bool {
        self.raw == 0
    }

    /// Returns the raw handle value.
    pub const fn raw_handle(&self) -> zx_handle_t {
        self.raw
    }
}

/// A borrowed wrapper around a typed handle (mirrors `zx::Unowned`).
#[derive(Debug, Copy, Clone)]
pub struct Unowned<'a, T> {
    inner: T,
    _marker: core::marker::PhantomData<&'a T>,
}

impl<'a, T> Unowned<'a, T> {
    /// Wraps a value as an unowned reference.
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<T> core::ops::Deref for Unowned<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.inner
    }
}

// -- Basic info / wait result

/// Basic information about a kernel object handle.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct HandleBasicInfo {
    pub koid: Koid,
    pub rights: Rights,
    pub object_type: ObjectType,
    pub related_koid: Koid,
}

impl Default for Rights {
    fn default() -> Self {
        Rights::empty()
    }
}

/// The outcome of a `wait_one` call.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum WaitResult {
    /// The wait succeeded and these signals were observed.
    Ok(Signals),
    /// The deadline elapsed; these signals were observed.
    TimedOut(Signals),
    /// The wait was cancelled; these signals were observed.
    Canceled(Signals),
    /// The wait failed with this status.
    Err(Status),
}

impl WaitResult {
    /// Converts this `WaitResult` into a `Result<Signals, Status>`. The signals
    /// are discarded in all cases except [`WaitResult::Ok`].
    pub const fn to_result(self) -> Result<Signals, Status> {
        match self {
            WaitResult::Ok(signals) => Ok(signals),
            WaitResult::TimedOut(_signals) => Err(Status::TIMED_OUT),
            WaitResult::Canceled(_signals) => Err(Status::CANCELED),
            WaitResult::Err(status) => Err(status),
        }
    }

    // The following definitions mirror `core::result::Result`, delegating to
    // `to_result()`, so a `WaitResult` can be treated like a `Result`.

    /// Returns `true` if the wait succeeded.
    #[must_use]
    pub const fn is_ok(&self) -> bool {
        self.to_result().is_ok()
    }

    /// Returns `true` if the wait did not succeed.
    #[must_use]
    pub const fn is_err(&self) -> bool {
        self.to_result().is_err()
    }

    /// Maps the observed signals through `op` on success.
    pub fn map<U, F: FnOnce(Signals) -> U>(self, op: F) -> Result<U, Status> {
        self.to_result().map(op)
    }

    /// Maps the failure status through `op`.
    pub fn map_err<F, O: FnOnce(Status) -> F>(self, op: O) -> Result<Signals, F> {
        self.to_result().map_err(op)
    }

    /// Returns the observed signals, panicking with `msg` on failure.
    #[track_caller]
    pub fn expect(self, msg: &str) -> Signals {
        self.to_result().expect(msg)
    }

    /// Returns the failure status, panicking with `msg` on success.
    #[track_caller]
    pub fn expect_err(self, msg: &str) -> Status {
        self.to_result().expect_err(msg)
    }

    /// Returns the observed signals, panicking on failure.
    #[track_caller]
    pub fn unwrap(self) -> Signals {
        self.to_result().unwrap()
    }
}

// -- Handle traits

/// Operations available on anything convertible to a handle reference.
pub trait AsHandleRef {
    /// Returns a borrowed reference to the underlying handle.
    fn as_handle_ref(&self) -> HandleRef<'_>;

    /// Returns the raw handle value.
    fn raw_handle(&self) -> zx_handle_t {
        self.as_handle_ref().raw_handle()
    }

    /// Returns the koid of the object.
    ///
    /// Stub: derives a koid from the raw handle value.
    fn get_koid(&self) -> Result<Koid, Status> {
        Ok(Koid::from_raw(self.raw_handle() as u64))
    }

    /// Returns the koid of the object (alias used by the fork).
    fn koid(&self) -> Result<Koid, Status> {
        self.get_koid()
    }

    /// Returns basic info about the object. Stub.
    fn basic_info(&self) -> Result<HandleBasicInfo, Status> {
        Ok(HandleBasicInfo {
            koid: Koid::from_raw(self.raw_handle() as u64),
            rights: Rights::SAME_RIGHTS,
            object_type: ObjectType::None,
            related_koid: Koid::from_raw(0),
        })
    }

    /// Returns the object's name. Stub.
    fn get_name(&self) -> Result<Name, Status> {
        Ok(Name::EMPTY)
    }

    /// Asserts/clears signals on the object. Stub.
    fn signal_handle(&self, _clear: Signals, _set: Signals) -> Result<(), Status> {
        Ok(())
    }

    /// Waits for any of `signals` until `deadline`. Stub: reports a timeout.
    fn wait_one(&self, _signals: Signals, _deadline: MonotonicInstant) -> WaitResult {
        WaitResult::TimedOut(Signals::NONE)
    }
}

/// Operations available on owning, handle-based objects.
pub trait HandleBased: AsHandleRef + Sized {
    /// Consumes the object, returning its raw handle.
    fn into_handle(self) -> NullableHandle {
        NullableHandle::from_raw(self.raw_handle())
    }

    /// Consumes the object, returning its raw handle value.
    fn into_raw(self) -> zx_handle_t {
        self.raw_handle()
    }

    /// Sets the object's name. Stub.
    fn set_name(&self, _name: &Name) -> Result<(), Status> {
        Ok(())
    }

    /// Asserts/clears signals on the object. Stub.
    fn signal(&self, _clear: Signals, _set: Signals) -> Result<(), Status> {
        Ok(())
    }

    /// Duplicates the handle with the given rights. Stub: returns `NOT_SUPPORTED`.
    fn duplicate_handle(&self, _rights: Rights) -> Result<Self, Status> {
        Err(Status::NOT_SUPPORTED)
    }

    /// Replaces the handle with one carrying the given rights. Stub.
    fn replace_handle(self, _rights: Rights) -> Result<Self, Status> {
        Ok(self)
    }
}

impl AsHandleRef for NullableHandle {
    fn as_handle_ref(&self) -> HandleRef<'_> {
        HandleRef {
            raw: self.0,
            _marker: core::marker::PhantomData,
        }
    }
}
impl HandleBased for NullableHandle {}

// -- Stub object types
//
// Each wraps a `NullableHandle` and gets the trait methods above for free. The
// `stub_object!` macro generates the boilerplate plus the `AsHandleRef`/
// `HandleBased` impls.

macro_rules! stub_object {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[repr(transparent)]
        pub struct $name(NullableHandle);

        impl AsHandleRef for $name {
            fn as_handle_ref(&self) -> HandleRef<'_> {
                self.0.as_handle_ref()
            }
        }
        impl HandleBased for $name {}
    };
}

stub_object!(
    /// A waitable event object.
    Event
);
stub_object!(
    /// A paired event object.
    EventPair
);
stub_object!(
    /// A bidirectional message channel endpoint.
    Channel
);
stub_object!(
    /// A streaming/datagram socket endpoint.
    Socket
);
stub_object!(
    /// A counting object with positive/non-positive signals.
    Counter
);
stub_object!(
    /// An asynchronous wait/notification port.
    Port
);
stub_object!(
    /// A user-defined clock object.
    Clock
);
stub_object!(
    /// A pager object backing VMOs.
    Pager
);
stub_object!(
    /// A scheduling profile object.
    Profile
);
stub_object!(
    /// A resource-authority object.
    Resource
);
/// A schedulable task (process/thread/job), mirroring `zx::Task`.
///
/// Upstream this is a trait over handle types; the methods are inert stubs here
/// (no runtime accounting / task control yet on M6).
pub trait Task: AsHandleRef {
    /// Returns accumulated runtime statistics. Stub: zeroes.
    fn get_runtime_info(&self) -> Result<crate::thread::TaskRuntimeInfo, Status> {
        Ok(crate::thread::TaskRuntimeInfo::default())
    }
    /// Kills the task. Stub.
    fn kill(&self) -> Result<(), Status> {
        Ok(())
    }
}

impl Task for crate::process::Process {}
impl Task for crate::thread::Thread {}

impl Event {
    /// Creates a new event object. Stub.
    pub fn create() -> Self {
        Self(NullableHandle::invalid())
    }
}

impl EventPair {
    /// Creates a connected pair of event objects. Stub.
    pub fn create() -> (Self, Self) {
        (Self(NullableHandle::invalid()), Self(NullableHandle::invalid()))
    }
}

impl Channel {
    /// Creates a connected pair of channel endpoints. Stub.
    pub fn create() -> (Self, Self) {
        (Self(NullableHandle::invalid()), Self(NullableHandle::invalid()))
    }

    /// Writes a message to the channel. Stub: succeeds without transfer.
    pub fn write(&self, _bytes: &[u8], _handles: &mut alloc::vec::Vec<NullableHandle>) -> Result<(), Status> {
        Ok(())
    }
}

impl Socket {
    /// Creates a connected pair of stream sockets. Stub.
    pub fn create_stream() -> (Self, Self) {
        (Self(NullableHandle::invalid()), Self(NullableHandle::invalid()))
    }
}

impl Counter {
    /// Creates a new counter object. Stub.
    pub fn create() -> Self {
        Self(NullableHandle::invalid())
    }

    /// Adds `delta` to the counter. Stub: succeeds.
    pub fn add(&self, _delta: i64) -> Result<(), Status> {
        Ok(())
    }

    /// Reads the counter's current value. Stub: returns zero.
    pub fn read(&self) -> Result<i64, Status> {
        Ok(0)
    }
}

impl core::fmt::Display for Counter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Counter({})", self.0.raw())
    }
}

impl Clone for Counter {
    fn clone(&self) -> Self {
        Self(NullableHandle::from_raw(self.0.raw()))
    }
}

impl Port {
    /// Creates a new port object. Stub.
    pub fn create() -> Self {
        Self(NullableHandle::invalid())
    }

    /// Waits for a packet on the port. Stub: returns `TIMED_OUT`.
    pub fn wait(&self, _deadline: MonotonicInstant) -> Result<crate::packet::Packet, Status> {
        Err(Status::TIMED_OUT)
    }

    /// Queues a user packet on the port. Stub: succeeds.
    pub fn queue(&self, _packet: &crate::packet::Packet) -> Result<(), Status> {
        Ok(())
    }
}

impl Pager {
    /// Creates a new pager object. Stub: returns `NOT_SUPPORTED`.
    pub fn create(_options: crate::flags::PagerOptions) -> Result<Self, Status> {
        Err(Status::NOT_SUPPORTED)
    }

    /// Creates a pager-backed VMO. Stub: returns `NOT_SUPPORTED`.
    pub fn create_vmo(
        &self,
        _options: crate::vmo::VmoOptions,
        _port: &Port,
        _key: u64,
        size: u64,
    ) -> Result<crate::vmo::Vmo, Status> {
        crate::vmo::Vmo::create(size)
    }

    /// Supplies pages to a pager-backed VMO. Stub: succeeds.
    pub fn supply_pages(
        &self,
        _vmo: &crate::vmo::Vmo,
        _range: core::ops::Range<u64>,
        _source: &crate::vmo::Vmo,
        _source_offset: u64,
    ) -> Result<(), Status> {
        Ok(())
    }
}

impl Clock {
    /// Returns details about the clock. Stub: returns `NOT_SUPPORTED`.
    pub fn create() -> Result<Self, Status> {
        Err(Status::NOT_SUPPORTED)
    }
}

stub_object!(
    /// A timer object. Generic over its timeline in upstream; here a single stub.
    BootTimer
);

impl BootTimer {
    /// Creates a new boot-timeline timer object. Stub.
    pub fn create() -> Self {
        Self(NullableHandle::invalid())
    }

    /// Arms the timer for `_deadline` with `_slack`. Stub: there is no timer
    /// reactor in the minimal core, so the timer never fires (callers that wait
    /// on TIMER_SIGNALED simply never observe it until the reactor lands).
    pub fn set(
        &self,
        _deadline: crate::time::BootInstant,
        _slack: crate::time::BootDuration,
    ) -> Result<(), Status> {
        Ok(())
    }

    /// Cancels the timer. Stub.
    pub fn cancel(&self) -> Result<(), Status> {
        Ok(())
    }
}
