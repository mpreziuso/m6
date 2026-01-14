//! IPC abstractions
//!
//! Provides high-level abstractions over M6's IPC primitives.
//!
//! M6 provides two main IPC mechanisms:
//!
//! - **Endpoints**: Synchronous message passing with rendezvous semantics.
//!   The sender blocks until a receiver is ready, and vice versa.
//!
//! - **Notifications**: Asynchronous signalling using a word-sized bitmask.
//!   Signals are ORed into the notification word and can be polled or waited on.
//!
//! # Message Format
//!
//! IPC messages in M6 consist of up to 5 machine words (u64):
//! - Word 0: Label (message type/tag)
//! - Words 1-4: Payload
//!
//! For typed message passing, use the higher-level abstractions in this module.

use core::marker::PhantomData;
use core::sync::atomic::{AtomicU64, Ordering};

use m6_cap::ObjectType;
use m6_syscall::error::SyscallError;
use m6_syscall::invoke::{retype, IpcRecvResult};

// Re-export syscall wrappers for direct IPC access
pub use m6_syscall::invoke::{
    call, nb_recv, nb_send, poll, recv, reply_recv, send, signal, wait,
};

// -- Capability slot management

/// First slot for IPC-allocated resources.
const IPC_SLOT_BASE: u64 = 512;

/// Global counter for allocating IPC resource slots.
static NEXT_IPC_SLOT: AtomicU64 = AtomicU64::new(IPC_SLOT_BASE);

/// CNode radix.
const CNODE_RADIX: u8 = 10;

/// Root CNode CPtr.
const ROOT_CNODE_CPTR: u64 = 0;

/// Untyped capability CPtr.
const UNTYPED_CPTR: u64 = 9 << 54;

// -- Endpoint wrapper

/// A wrapper around an endpoint capability.
///
/// Endpoints provide synchronous IPC with rendezvous semantics.
#[derive(Clone, Copy)]
pub struct Endpoint {
    cptr: u64,
}

impl Endpoint {
    /// Create an endpoint wrapper from a raw capability pointer.
    #[inline]
    pub const fn from_cptr(cptr: u64) -> Self {
        Self { cptr }
    }

    /// Get the raw capability pointer.
    #[inline]
    pub const fn cptr(&self) -> u64 {
        self.cptr
    }

    /// Allocate a new endpoint from untyped memory.
    ///
    /// Returns the endpoint capability pointer.
    pub fn create() -> Result<Self, SyscallError> {
        let slot = NEXT_IPC_SLOT.fetch_add(1, Ordering::Relaxed);
        let cptr = slot << (64 - CNODE_RADIX as u64);

        retype(
            UNTYPED_CPTR,
            ObjectType::Endpoint as u64,
            0, // Endpoint size is fixed
            ROOT_CNODE_CPTR,
            slot,
            1,
        )?;

        Ok(Self { cptr })
    }

    /// Send a message on this endpoint.
    ///
    /// Blocks until a receiver is ready.
    #[inline]
    pub fn send(&self, label: u64, msg: [u64; 4]) -> Result<(), SyscallError> {
        send(self.cptr, label, msg[0], msg[1], msg[2])?;
        Ok(())
    }

    /// Receive a message from this endpoint.
    ///
    /// Blocks until a sender is ready.
    #[inline]
    pub fn recv(&self) -> Result<IpcRecvResult, SyscallError> {
        recv(self.cptr)
    }

    /// Perform a call (send + wait for reply).
    #[inline]
    pub fn call(&self, label: u64, msg: [u64; 4]) -> Result<IpcRecvResult, SyscallError> {
        call(self.cptr, label, msg[0], msg[1], msg[2])
    }

    /// Try to receive without blocking.
    #[inline]
    pub fn try_recv(&self) -> Result<IpcRecvResult, SyscallError> {
        nb_recv(self.cptr)
    }

    /// Try to send without blocking.
    #[inline]
    pub fn try_send(&self, label: u64, msg: [u64; 4]) -> Result<(), SyscallError> {
        nb_send(self.cptr, label, msg[0], msg[1], msg[2])?;
        Ok(())
    }
}

impl core::fmt::Debug for Endpoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Endpoint")
            .field("cptr", &self.cptr)
            .finish()
    }
}

// -- Notification wrapper

/// A wrapper around a notification capability.
///
/// Notifications provide asynchronous signalling using a bitmask.
#[derive(Clone, Copy)]
pub struct Notification {
    cptr: u64,
}

impl Notification {
    /// Create a notification wrapper from a raw capability pointer.
    #[inline]
    pub const fn from_cptr(cptr: u64) -> Self {
        Self { cptr }
    }

    /// Get the raw capability pointer.
    #[inline]
    pub const fn cptr(&self) -> u64 {
        self.cptr
    }

    /// Allocate a new notification from untyped memory.
    pub fn create() -> Result<Self, SyscallError> {
        let slot = NEXT_IPC_SLOT.fetch_add(1, Ordering::Relaxed);
        let cptr = slot << (64 - CNODE_RADIX as u64);

        retype(
            UNTYPED_CPTR,
            ObjectType::Notification as u64,
            0, // Notification size is fixed
            ROOT_CNODE_CPTR,
            slot,
            1,
        )?;

        Ok(Self { cptr })
    }

    /// Signal this notification.
    ///
    /// ORs the badge into the notification word.
    #[inline]
    pub fn signal(&self) -> Result<(), SyscallError> {
        signal(self.cptr)?;
        Ok(())
    }

    /// Wait for a signal on this notification.
    ///
    /// Blocks until signalled, returns the signal word.
    #[inline]
    pub fn wait(&self) -> Result<u64, SyscallError> {
        wait(self.cptr).map(|v| v as u64)
    }

    /// Poll this notification without blocking.
    ///
    /// Returns the signal word if any bits are set.
    #[inline]
    pub fn poll(&self) -> Result<u64, SyscallError> {
        poll(self.cptr).map(|v| v as u64)
    }
}

impl core::fmt::Debug for Notification {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Notification")
            .field("cptr", &self.cptr)
            .finish()
    }
}

// -- Simple typed channel

/// Error returned when sending on a channel fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendError {
    /// The receiver was disconnected.
    Disconnected,
    /// Syscall error.
    Syscall(SyscallError),
}

impl From<SyscallError> for SendError {
    fn from(e: SyscallError) -> Self {
        SendError::Syscall(e)
    }
}

/// Error returned when receiving from a channel fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecvError {
    /// The channel is empty (for try_recv).
    Empty,
    /// The sender was disconnected.
    Disconnected,
    /// Syscall error.
    Syscall(SyscallError),
}

impl From<SyscallError> for RecvError {
    fn from(e: SyscallError) -> Self {
        RecvError::Syscall(e)
    }
}

/// The sending half of a channel.
///
/// Messages can be sent through this using [`send`](Sender::send).
pub struct Sender<T> {
    endpoint: Endpoint,
    _marker: PhantomData<T>,
}

impl<T> Sender<T> {
    /// Send a value on this channel.
    ///
    /// This will block until a receiver is ready.
    ///
    /// # Panics
    ///
    /// Panics if the message doesn't fit in the IPC registers.
    pub fn send(&self, value: T) -> Result<(), SendError>
    where
        T: IntoMessage,
    {
        let msg = value.into_message();
        self.endpoint
            .send(msg.label, msg.payload)
            .map_err(SendError::from)
    }

    /// Try to send without blocking.
    pub fn try_send(&self, value: T) -> Result<(), SendError>
    where
        T: IntoMessage,
    {
        let msg = value.into_message();
        self.endpoint
            .try_send(msg.label, msg.payload)
            .map_err(SendError::from)
    }
}

impl<T> Clone for Sender<T> {
    fn clone(&self) -> Self {
        Self {
            endpoint: self.endpoint,
            _marker: PhantomData,
        }
    }
}

impl<T> core::fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Sender")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// The receiving half of a channel.
///
/// Messages can be received through this using [`recv`](Receiver::recv).
pub struct Receiver<T> {
    endpoint: Endpoint,
    _marker: PhantomData<T>,
}

impl<T> Receiver<T> {
    /// Receive a value from this channel.
    ///
    /// This will block until a sender sends a value.
    pub fn recv(&self) -> Result<T, RecvError>
    where
        T: FromMessage,
    {
        let result = self.endpoint.recv().map_err(RecvError::from)?;
        let msg = Message {
            label: result.label,
            payload: result.msg,
        };
        T::from_message(msg).ok_or(RecvError::Disconnected)
    }

    /// Try to receive without blocking.
    pub fn try_recv(&self) -> Result<T, RecvError>
    where
        T: FromMessage,
    {
        let result = self.endpoint.try_recv().map_err(|e| match e {
            SyscallError::WouldBlock => RecvError::Empty,
            e => RecvError::Syscall(e),
        })?;
        let msg = Message {
            label: result.label,
            payload: result.msg,
        };
        T::from_message(msg).ok_or(RecvError::Disconnected)
    }
}

impl<T> core::fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Receiver")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

/// Create a new channel.
///
/// Returns a `(Sender, Receiver)` pair that can be used for typed message passing.
pub fn channel<T>() -> Result<(Sender<T>, Receiver<T>), SyscallError> {
    let endpoint = Endpoint::create()?;

    Ok((
        Sender {
            endpoint,
            _marker: PhantomData,
        },
        Receiver {
            endpoint,
            _marker: PhantomData,
        },
    ))
}

// -- Message serialisation traits

/// A raw IPC message.
#[derive(Clone, Copy, Debug)]
pub struct Message {
    /// Message label (type tag).
    pub label: u64,
    /// Message payload (up to 4 words).
    pub payload: [u64; 4],
}

impl Message {
    /// Create a new message.
    pub const fn new(label: u64, payload: [u64; 4]) -> Self {
        Self { label, payload }
    }

    /// Create an empty message with just a label.
    pub const fn with_label(label: u64) -> Self {
        Self {
            label,
            payload: [0; 4],
        }
    }
}

/// Trait for types that can be converted into an IPC message.
pub trait IntoMessage {
    /// Convert this value into a message.
    fn into_message(self) -> Message;
}

/// Trait for types that can be constructed from an IPC message.
pub trait FromMessage: Sized {
    /// Try to construct a value from a message.
    fn from_message(msg: Message) -> Option<Self>;
}

// -- Implementations for basic types

impl IntoMessage for u64 {
    fn into_message(self) -> Message {
        Message::new(0, [self, 0, 0, 0])
    }
}

impl FromMessage for u64 {
    fn from_message(msg: Message) -> Option<Self> {
        Some(msg.payload[0])
    }
}

impl IntoMessage for (u64, u64) {
    fn into_message(self) -> Message {
        Message::new(0, [self.0, self.1, 0, 0])
    }
}

impl FromMessage for (u64, u64) {
    fn from_message(msg: Message) -> Option<Self> {
        Some((msg.payload[0], msg.payload[1]))
    }
}

impl IntoMessage for (u64, u64, u64) {
    fn into_message(self) -> Message {
        Message::new(0, [self.0, self.1, self.2, 0])
    }
}

impl FromMessage for (u64, u64, u64) {
    fn from_message(msg: Message) -> Option<Self> {
        Some((msg.payload[0], msg.payload[1], msg.payload[2]))
    }
}

impl IntoMessage for (u64, u64, u64, u64) {
    fn into_message(self) -> Message {
        Message::new(0, [self.0, self.1, self.2, self.3])
    }
}

impl FromMessage for (u64, u64, u64, u64) {
    fn from_message(msg: Message) -> Option<Self> {
        Some((msg.payload[0], msg.payload[1], msg.payload[2], msg.payload[3]))
    }
}

impl IntoMessage for Message {
    fn into_message(self) -> Message {
        self
    }
}

impl FromMessage for Message {
    fn from_message(msg: Message) -> Option<Self> {
        Some(msg)
    }
}

/// Unit type sends an empty message.
impl IntoMessage for () {
    fn into_message(self) -> Message {
        Message::with_label(0)
    }
}

impl FromMessage for () {
    fn from_message(_msg: Message) -> Option<Self> {
        Some(())
    }
}
