//! The Starnix lock-ordering graph.
//!
//! M6: faithful port of Fuchsia's `lock_ordering.rs` (SHA f8046198). Each level
//! is declared as a zero-sized `pub enum` by the `lock_ordering!` proc-macro,
//! which also emits the transitive `LockAfter` impls. `UninterruptibleLock` and
//! all the marker types the Starnix core references (`FileOpsCore`,
//! `TaskRelease`, `ProcessGroupState`, `ThreadGroupLimits`, `UserFaultInner`,
//! `KernelIpTables`, `DeviceRegistryState`, `TerminalLock`, ...) are generated
//! here.

use crate::Unlocked;
use lock_ordering_macro::lock_ordering;

lock_ordering! {
    // UninterruptibleLock represents a virtual level before which lock must be interruptible.
    Unlocked => UninterruptibleLock,
    // Artificial level for ResourceAccessor.add_file_with_flags(..)
    Unlocked => ResourceAccessorLevel,
    // Artificial level for methods in FsNodeOps/FileOps that require access to the
    // FsNode.append_lock
    Unlocked => BeforeFsNodeAppend,
    BeforeFsNodeAppend => FsNodeAppend,
    // Artificial level for file operations.
    FsNodeAppend => FileOpsCore,
    ResourceAccessorLevel => FileOpsCore,
    // FileOpsCore are interruptible
    FileOpsCore => UninterruptibleLock,
    // Artificial lock level for {Task, CurrentTask}.release()
    Unlocked => TaskRelease,
    // During task release, file must be closed.
    TaskRelease => FileOpsCore,
    // Kernel.iptables
    UninterruptibleLock => KernelIpTables,
    // Kernel.swap_files
    UninterruptibleLock => KernelSwapFiles,
    // ThreadGroup.limits
    ProcessGroupState => ThreadGroupLimits,
    MmDumpable => ThreadGroupLimits,
    // MemoryManager.dumpable
    UninterruptibleLock => MmDumpable,
    // ProcessGroup.mutable_state.
    // Needs to be before TaskRelease because of the dependency in CurrentTask.release()
    TaskRelease => ProcessGroupState,
    UninterruptibleLock => ProcessGroupState,
    // ProcessGroup.mutable_state. Artificial locks above need to be before it because of
    // dependencies in DevPtsFile.{read, write, ioctl}.
    FileOpsCore => ProcessGroupState,
    // Userfaultfd
    FileOpsCore => UserFaultInner,
    UninterruptibleLock => UserFaultInner,
    // MemoryPressureMonitor
    UninterruptibleLock => MemoryPressureMonitor,
    FileOpsCore => MemoryPressureMonitor,
    MemoryPressureMonitor => MemoryPressureMonitorClientState,
    // Fastrpc
    UninterruptibleLock => FastrpcInnerState,
    // MemoryXattrStorage
    UninterruptibleLock => MemoryXattrStorageLevel,
    // DeviceRegistry
    UninterruptibleLock => DeviceRegistryState,
    FileOpsCore => DeviceRegistryState,

    // Terminal Level. No lock level should ever be defined after this. Can be used for any locks
    // that is never acquired before any other lock.
    UninterruptibleLock => TerminalLock,
    FileOpsCore => TerminalLock,

    // eBPF locks
    UninterruptibleLock => EbpfStateLock,
    UninterruptibleLock => EbpfMapStateLevel,
    EbpfStateLock => EbpfSuspendLock,
    EbpfMapStateLevel => EbpfSuspendLock,
}
