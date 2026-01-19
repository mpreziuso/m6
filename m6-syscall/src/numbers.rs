//! Syscall numbers
//!
//! Defines the syscall ABI for the M6 microkernel. Following seL4 conventions:
//! - x7: syscall number
//! - x0-x5: arguments
//! - x0: return value (negative = error)

/// Syscall numbers following seL4 conventions.
///
/// Low numbers are reserved for high-frequency IPC operations.
#[repr(u64)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syscall {
    // === IPC Operations (high-frequency, low numbers) ===
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

    // === Notification Operations ===
    /// Signal a notification (OR badge into signal word).
    Signal = 7,
    /// Wait on notification (blocks until signalled).
    Wait = 8,
    /// Poll notification (non-blocking).
    Poll = 9,

    // === Capability Management ===
    /// Copy capability.
    CapCopy = 16,
    /// Move capability.
    CapMove = 17,
    /// Mint capability (derive with reduced rights/badge).
    CapMint = 18,
    /// Delete capability.
    CapDelete = 19,
    /// Revoke capability and all derivatives.
    CapRevoke = 20,
    /// Mutate capability rights in-place.
    CapMutate = 21,
    /// Rotate capabilities between slots.
    CapRotate = 22,

    // === Object Invocation ===
    /// Invoke capability (object-specific operation).
    Invoke = 32,

    // === Memory Operations ===
    /// Retype untyped memory into new objects.
    Retype = 48,
    /// Map frame into address space.
    MapFrame = 49,
    /// Unmap frame from address space.
    UnmapFrame = 50,
    /// Map page table.
    MapPageTable = 51,
    /// Assign ASID from pool to VSpace.
    AsidPoolAssign = 52,
    /// Write data from userspace into a frame.
    FrameWrite = 53,

    // === TCB Operations ===
    /// Configure TCB (set CSpace, VSpace, etc.).
    TcbConfigure = 64,
    /// Set TCB registers.
    TcbWriteRegisters = 65,
    /// Read TCB registers.
    TcbReadRegisters = 66,
    /// Resume/start TCB.
    TcbResume = 67,
    /// Suspend TCB.
    TcbSuspend = 68,
    /// Set TCB priority.
    TcbSetPriority = 69,
    /// Bind notification to TCB.
    TcbBindNotification = 70,
    /// Exit the current thread with an exit code.
    TcbExit = 71,
    /// Sleep the current thread for a specified duration.
    TcbSleep = 72,

    // === IRQ Operations ===
    /// Acknowledge IRQ.
    IrqAck = 80,
    /// Set IRQ handler notification.
    IrqSetHandler = 81,
    /// Clear IRQ handler.
    IrqClearHandler = 82,
    /// Get IRQ handler from IRQ control.
    IrqControlGet = 83,

    // === Timer Operations ===
    /// Get timer from timer control.
    TimerControlGet = 84,
    /// Bind timer to notification.
    TimerBind = 85,
    /// Arm timer (one-shot or periodic).
    TimerArm = 86,
    /// Cancel armed timer.
    TimerCancel = 87,
    /// Clear timer (unbind from notification).
    TimerClear = 88,
    /// Allocate MSI vectors and get configuration.
    /// Args: x0 = IRQ control cap, x1 = vector count
    /// Returns: x0 = result, x1 = MSI target address, x2 = base SPI, x3 = actual count
    MsiAllocate = 89,

    // === IOMMU Operations ===
    /// Create IOSpace from untyped memory.
    IOSpaceCreate = 96,
    /// Map frame into IOSpace for DMA.
    IOSpaceMapFrame = 97,
    /// Unmap frame from IOSpace.
    IOSpaceUnmapFrame = 98,
    /// Bind stream ID to IOSpace.
    IOSpaceBindStream = 99,
    /// Unbind stream ID from IOSpace.
    IOSpaceUnbindStream = 100,
    /// Configure fault handler for IOSpace stream.
    IOSpaceSetFaultHandler = 101,
    /// Create DmaPool from IOSpace.
    DmaPoolCreate = 104,
    /// Allocate DMA buffer from pool.
    DmaPoolAlloc = 105,
    /// Free DMA buffer.
    DmaPoolFree = 106,

    // === Cache Maintenance Operations ===
    /// Clean cache range (before DMA to device).
    CacheClean = 120,
    /// Invalidate cache range (after DMA from device).
    CacheInvalidate = 121,
    /// Flush cache range (clean + invalidate, for bidirectional DMA).
    CacheFlush = 122,

    // === Miscellaneous Operations ===
    /// Get cryptographically random bytes.
    /// Used for ASLR, stack canaries, heap allocator secrets, etc.
    GetRandom = 112,

    // === Debug (development only) ===
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
            16 => Some(Self::CapCopy),
            17 => Some(Self::CapMove),
            18 => Some(Self::CapMint),
            19 => Some(Self::CapDelete),
            20 => Some(Self::CapRevoke),
            21 => Some(Self::CapMutate),
            22 => Some(Self::CapRotate),
            32 => Some(Self::Invoke),
            48 => Some(Self::Retype),
            49 => Some(Self::MapFrame),
            50 => Some(Self::UnmapFrame),
            51 => Some(Self::MapPageTable),
            52 => Some(Self::AsidPoolAssign),
            53 => Some(Self::FrameWrite),
            64 => Some(Self::TcbConfigure),
            65 => Some(Self::TcbWriteRegisters),
            66 => Some(Self::TcbReadRegisters),
            67 => Some(Self::TcbResume),
            68 => Some(Self::TcbSuspend),
            69 => Some(Self::TcbSetPriority),
            70 => Some(Self::TcbBindNotification),
            71 => Some(Self::TcbExit),
            72 => Some(Self::TcbSleep),
            80 => Some(Self::IrqAck),
            81 => Some(Self::IrqSetHandler),
            82 => Some(Self::IrqClearHandler),
            83 => Some(Self::IrqControlGet),
            84 => Some(Self::TimerControlGet),
            85 => Some(Self::TimerBind),
            86 => Some(Self::TimerArm),
            87 => Some(Self::TimerCancel),
            88 => Some(Self::TimerClear),
            89 => Some(Self::MsiAllocate),
            96 => Some(Self::IOSpaceCreate),
            97 => Some(Self::IOSpaceMapFrame),
            98 => Some(Self::IOSpaceUnmapFrame),
            99 => Some(Self::IOSpaceBindStream),
            100 => Some(Self::IOSpaceUnbindStream),
            101 => Some(Self::IOSpaceSetFaultHandler),
            104 => Some(Self::DmaPoolCreate),
            105 => Some(Self::DmaPoolAlloc),
            106 => Some(Self::DmaPoolFree),
            112 => Some(Self::GetRandom),
            120 => Some(Self::CacheClean),
            121 => Some(Self::CacheInvalidate),
            122 => Some(Self::CacheFlush),
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
            Self::CapCopy => "CapCopy",
            Self::CapMove => "CapMove",
            Self::CapMint => "CapMint",
            Self::CapDelete => "CapDelete",
            Self::CapRevoke => "CapRevoke",
            Self::CapMutate => "CapMutate",
            Self::CapRotate => "CapRotate",
            Self::Invoke => "Invoke",
            Self::Retype => "Retype",
            Self::MapFrame => "MapFrame",
            Self::UnmapFrame => "UnmapFrame",
            Self::MapPageTable => "MapPageTable",
            Self::AsidPoolAssign => "AsidPoolAssign",
            Self::FrameWrite => "FrameWrite",
            Self::TcbConfigure => "TcbConfigure",
            Self::TcbWriteRegisters => "TcbWriteRegisters",
            Self::TcbReadRegisters => "TcbReadRegisters",
            Self::TcbResume => "TcbResume",
            Self::TcbSuspend => "TcbSuspend",
            Self::TcbSetPriority => "TcbSetPriority",
            Self::TcbBindNotification => "TcbBindNotification",
            Self::TcbExit => "TcbExit",
            Self::TcbSleep => "TcbSleep",
            Self::IrqAck => "IrqAck",
            Self::IrqSetHandler => "IrqSetHandler",
            Self::IrqClearHandler => "IrqClearHandler",
            Self::IrqControlGet => "IrqControlGet",
            Self::TimerControlGet => "TimerControlGet",
            Self::TimerBind => "TimerBind",
            Self::TimerArm => "TimerArm",
            Self::TimerCancel => "TimerCancel",
            Self::TimerClear => "TimerClear",
            Self::MsiAllocate => "MsiAllocate",
            Self::IOSpaceCreate => "IOSpaceCreate",
            Self::IOSpaceMapFrame => "IOSpaceMapFrame",
            Self::IOSpaceUnmapFrame => "IOSpaceUnmapFrame",
            Self::IOSpaceBindStream => "IOSpaceBindStream",
            Self::IOSpaceUnbindStream => "IOSpaceUnbindStream",
            Self::IOSpaceSetFaultHandler => "IOSpaceSetFaultHandler",
            Self::DmaPoolCreate => "DmaPoolCreate",
            Self::DmaPoolAlloc => "DmaPoolAlloc",
            Self::DmaPoolFree => "DmaPoolFree",
            Self::GetRandom => "GetRandom",
            Self::CacheClean => "CacheClean",
            Self::CacheInvalidate => "CacheInvalidate",
            Self::CacheFlush => "CacheFlush",
            Self::DebugPuts => "DebugPuts",
            Self::DebugPutChar => "DebugPutChar",
        }
    }
}
