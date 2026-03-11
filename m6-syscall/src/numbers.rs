//! Syscall numbers
//!
//! Defines the syscall ABI for the M6 microkernel. Following seL4 conventions:
//! - x7: syscall number
//! - x0-x5: arguments
//! - x0: return value (negative = error)

/// Sentinel CPtr for self-invocations (Exit, Sleep, GetRandom, Cache ops).
///
/// Must not collide with any valid CPtr. Slot 0 is the root CNode in every
/// CSpace, so `0` cannot be used as a sentinel. `u64::MAX` is safe because
/// the kernel checks for this value before CPtr resolution.
pub const SELF_CAP: u64 = u64::MAX;

/// Method labels for the Invoke syscall.
///
/// Each object type has its own label namespace. The same numeric label
/// can mean different operations for different object types.
pub mod method {
    /// Self-invocations (cap_cptr = 0, meaning "current thread context").
    pub mod current {
        pub const EXIT: u64 = 0;
        pub const SLEEP: u64 = 1;
        pub const GET_RANDOM: u64 = 2;
        pub const CACHE_CLEAN: u64 = 3;
        pub const CACHE_INVALIDATE: u64 = 4;
        pub const CACHE_FLUSH: u64 = 5;
        pub const RESTRICTED_BIND: u64 = 6;
    }

    /// Untyped memory operations.
    pub mod untyped {
        pub const RETYPE: u64 = 0;
    }

    /// Frame / DeviceFrame operations.
    pub mod frame {
        pub const GET_PHYS: u64 = 0;
        pub const WRITE: u64 = 1;
    }

    /// VSpace operations.
    pub mod vspace {
        pub const MAP_FRAME: u64 = 0;
        pub const UNMAP_FRAME: u64 = 1;
        pub const MAP_PAGE_TABLE: u64 = 2;
    }

    /// ASID pool operations.
    pub mod asid_pool {
        pub const ASSIGN: u64 = 0;
    }

    /// CNode operations.
    pub mod cnode {
        pub const COPY: u64 = 0;
        pub const MOVE: u64 = 1;
        pub const MINT: u64 = 2;
        pub const DELETE: u64 = 3;
        pub const REVOKE: u64 = 4;
        pub const MUTATE: u64 = 5;
        pub const ROTATE: u64 = 6;
    }

    /// TCB operations.
    pub mod tcb {
        pub const CONFIGURE: u64 = 0;
        pub const WRITE_REGS: u64 = 1;
        pub const READ_REGS: u64 = 2;
        pub const RESUME: u64 = 3;
        pub const SUSPEND: u64 = 4;
        pub const SET_PRIORITY: u64 = 5;
        pub const BIND_NOTIF: u64 = 6;
        pub const KICK_RESTRICTED: u64 = 8;
    }

    /// Restricted mode exit reasons.
    pub mod restricted {
        /// Linux code executed `svc #0`.
        pub const REASON_SYSCALL: u64 = 0;
        /// Linux code triggered a fault (data abort, etc.).
        pub const REASON_EXCEPTION: u64 = 1;
        /// Another thread kicked the restricted-mode thread.
        pub const REASON_KICK: u64 = 2;
    }

    /// IRQ handler operations.
    pub mod irq_handler {
        pub const ACK: u64 = 0;
        pub const SET_HANDLER: u64 = 1;
        pub const CLEAR_HANDLER: u64 = 2;
    }

    /// IRQ control operations.
    pub mod irq_control {
        pub const GET: u64 = 0;
        pub const MSI_ALLOCATE: u64 = 1;
    }

    /// Timer control operations.
    pub mod timer_control {
        pub const GET: u64 = 0;
    }

    /// Timer operations.
    pub mod timer {
        pub const BIND: u64 = 0;
        pub const ARM: u64 = 1;
        pub const CANCEL: u64 = 2;
        pub const CLEAR: u64 = 3;
    }

    /// SMMU control operations.
    pub mod smmu_control {
        pub const CREATE_IOSPACE: u64 = 0;
    }

    /// IOSpace operations.
    pub mod iospace {
        pub const CREATE_DMA_POOL: u64 = 0;
        pub const MAP_FRAME: u64 = 1;
        pub const UNMAP_FRAME: u64 = 2;
        pub const BIND_STREAM: u64 = 3;
        pub const UNBIND_STREAM: u64 = 4;
        pub const SET_FAULT_HANDLER: u64 = 5;
    }

    /// DMA pool operations.
    pub mod dma_pool {
        pub const ALLOC: u64 = 0;
        pub const FREE: u64 = 1;
    }
}

/// Syscall numbers following seL4 conventions.
///
/// IPC primitives have dedicated low numbers for fast-path dispatch.
/// All object-manipulation operations go through the single `Invoke`
/// syscall (32), with the method label in x1 selecting the operation.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    // -- IPC operations (high-frequency, low numbers)
    /// Send message to endpoint (blocks if no receiver).
    Send = 0,
    /// Receive message from endpoint (blocks if no sender).
    Recv = 1,
    /// Combined Send + Recv (call pattern).
    Call = 2,
    /// Reply to caller then wait for next message.
    ReplyRecv = 3,
    /// Non-blocking send (returns immediately if would block).
    NBSend = 4,
    /// Non-blocking receive (polls).
    NBRecv = 5,
    /// Yield CPU to scheduler.
    Yield = 6,

    // -- Restricted mode (Starnix)
    /// Enter restricted mode: run Linux code in a different VSpace.
    /// x0 = VSpace capability pointer.
    RestrictedEnter = 10,

    // -- Notification operations
    /// Signal a notification (OR badge into signal word).
    Signal = 7,
    /// Wait on notification (blocks until signalled).
    Wait = 8,
    /// Poll notification (non-blocking).
    Poll = 9,

    // -- Object invocation (central dispatcher for all cap operations)
    /// Invoke capability: x0=cap, x1=method label, x2-x6=args.
    Invoke = 32,

    // -- Debug (development only)
    /// Debug print string (pointer + length).
    DebugPuts = 254,
    /// Debug print character.
    DebugPutChar = 255,
}

impl Syscall {
    /// Try to convert from a raw syscall number.
    pub fn from_number(num: u64) -> Option<Self> {
        match num {
            0 => Some(Self::Send),
            1 => Some(Self::Recv),
            2 => Some(Self::Call),
            3 => Some(Self::ReplyRecv),
            4 => Some(Self::NBSend),
            5 => Some(Self::NBRecv),
            6 => Some(Self::Yield),
            7 => Some(Self::Signal),
            8 => Some(Self::Wait),
            9 => Some(Self::Poll),
            10 => Some(Self::RestrictedEnter),
            32 => Some(Self::Invoke),
            254 => Some(Self::DebugPuts),
            255 => Some(Self::DebugPutChar),
            _ => None,
        }
    }

    /// Get the syscall name for logging.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Send => "Send",
            Self::Recv => "Recv",
            Self::Call => "Call",
            Self::ReplyRecv => "ReplyRecv",
            Self::NBSend => "NBSend",
            Self::NBRecv => "NBRecv",
            Self::Yield => "Yield",
            Self::Signal => "Signal",
            Self::Wait => "Wait",
            Self::Poll => "Poll",
            Self::RestrictedEnter => "RestrictedEnter",
            Self::Invoke => "Invoke",
            Self::DebugPuts => "DebugPuts",
            Self::DebugPutChar => "DebugPutChar",
        }
    }
}
