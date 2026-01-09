//! Capability object types
//!
//! This module defines the kernel object types that can be accessed via
//! capabilities. It uses the sealed trait pattern to prevent external
//! implementations, ensuring only kernel-defined object types exist.
//!
//! # Object Categories
//!
//! ## Memory Objects
//! - [`Untyped`]: Raw physical memory (can be retyped into other objects)
//! - [`Frame`]: Normal memory page (4KB or 2MB)
//! - [`DeviceFrame`]: Device memory page (non-cacheable)
//! - [`PageTableL0`], [`PageTableL1`], [`PageTableL2`], [`PageTableL3`]: Page table levels
//! - [`VSpace`]: Virtual address space root
//!
//! ## ASID Objects
//! - [`ASIDPool`]: Pool of ASIDs for address space isolation
//! - [`ASIDControl`]: Root authority to create ASID pools
//!
//! ## IPC Objects
//! - [`Endpoint`]: Synchronous IPC destination (supports badging)
//! - [`Notification`]: Asynchronous signalling (supports badging)
//! - [`Reply`]: One-time reply capability
//!
//! ## Execution Objects
//! - [`CNodeObj`]: Capability storage container
//! - [`TCB`]: Thread control block
//!
//! ## System Objects
//! - [`IRQHandler`]: Per-interrupt binding to notification
//! - [`IRQControl`]: Root authority to create IRQ handlers
//! - [`SchedContext`]: CPU time budget authority
//! - [`SchedControl`]: Authority to create scheduling contexts

// Object metadata submodules
pub mod asid;
pub mod cnode_obj;
pub mod endpoint;
pub mod frame;
pub mod irq;
pub mod page_table;
pub mod sched;
pub mod tcb;
pub mod untyped;
pub mod vspace;

pub use asid::{ASIDS_PER_POOL, AsidControlObject, AsidPoolObject};
pub use cnode_obj::CNodeObject;
pub use endpoint::{EndpointObject, EndpointState, NotificationObject, ReplyObject};
pub use frame::FrameObject;
pub use irq::{IrqControlObject, IrqHandlerObject, IrqNumber, IrqState, MAX_IRQ};
pub use page_table::{PageTableLevel, PageTableObject};
pub use sched::{Microseconds, SchedContextObject, SchedControlObject};
pub use tcb::{DEFAULT_PRIORITY, MAX_PRIORITY, Priority, TcbObject, ThreadState};
pub use untyped::{RetypeParams, UntypedObject};
pub use vspace::{Asid, VSpaceObject};

use crate::CapRights;

/// Marker trait for capability object types.
///
/// This trait is sealed to prevent external implementations, ensuring
/// only kernel-defined object types can be used with capabilities.
///
/// # Associated Constants
///
/// - `NAME`: Human-readable name for debugging and logging
/// - `SUPPORTS_BADGE`: Whether this object type supports badging
/// - `DEFAULT_RIGHTS`: Default rights for newly created capabilities
pub trait CapObjectType: private::Sealed + Copy + Clone + 'static {
    /// Human-readable name for debugging and logging.
    const NAME: &'static str;

    /// Whether this object type supports badging.
    ///
    /// Only [`Endpoint`] and [`Notification`] objects support badges.
    const SUPPORTS_BADGE: bool = false;

    /// Default rights for capabilities of this type.
    const DEFAULT_RIGHTS: CapRights;
}

/// Sealed trait module to prevent external implementations.
mod private {
    pub trait Sealed {}
}

// -- Memory Objects

/// Untyped memory capability.
///
/// Represents raw physical memory that can be subdivided and retyped into
/// other kernel objects. Untyped memory is the root of all memory authority
/// in the system.
///
/// # Properties
/// - Contains a contiguous region of physical memory
/// - Has a watermark tracking allocated space
/// - Children are created by retyping
/// - When all children are revoked, the watermark resets
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Untyped;

impl private::Sealed for Untyped {}
impl CapObjectType for Untyped {
    const NAME: &'static str = "Untyped";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Normal memory frame capability.
///
/// Represents a physical memory page that can be mapped into an address space.
/// Supports 4KB (standard) and 2MB (huge page) sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Frame;

impl private::Sealed for Frame {}
impl CapObjectType for Frame {
    const NAME: &'static str = "Frame";
    const DEFAULT_RIGHTS: CapRights = CapRights::RW;
}

/// Device memory frame capability.
///
/// Represents a device memory page (MMIO region) that can be mapped into
/// an address space. Device memory is non-cacheable and has strict ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DeviceFrame;

impl private::Sealed for DeviceFrame {}
impl CapObjectType for DeviceFrame {
    const NAME: &'static str = "DeviceFrame";
    const DEFAULT_RIGHTS: CapRights = CapRights::RW;
}

/// Page table level 0 (root) capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageTableL0;

impl private::Sealed for PageTableL0 {}
impl CapObjectType for PageTableL0 {
    const NAME: &'static str = "PageTableL0";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Page table level 1 capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageTableL1;

impl private::Sealed for PageTableL1 {}
impl CapObjectType for PageTableL1 {
    const NAME: &'static str = "PageTableL1";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Page table level 2 capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageTableL2;

impl private::Sealed for PageTableL2 {}
impl CapObjectType for PageTableL2 {
    const NAME: &'static str = "PageTableL2";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Page table level 3 (leaf) capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PageTableL3;

impl private::Sealed for PageTableL3 {}
impl CapObjectType for PageTableL3 {
    const NAME: &'static str = "PageTableL3";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Virtual address space capability.
///
/// Represents the root of a virtual address space (TTBR0 on ARM64).
/// A VSpace owns the page table hierarchy for user space.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VSpace;

impl private::Sealed for VSpace {}
impl CapObjectType for VSpace {
    const NAME: &'static str = "VSpace";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

// -- ASID Objects

/// ASID pool capability.
///
/// Contains a pool of ASIDs (Address Space IDentifiers) for TLB isolation.
/// Each VSpace requires an ASID to ensure TLB entries are correctly isolated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ASIDPool;

impl private::Sealed for ASIDPool {}
impl CapObjectType for ASIDPool {
    const NAME: &'static str = "ASIDPool";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// ASID control capability.
///
/// Root authority to create ASID pools. There is exactly one ASIDControl
/// capability in the system, given to the initial task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ASIDControl;

impl private::Sealed for ASIDControl {}
impl CapObjectType for ASIDControl {
    const NAME: &'static str = "ASIDControl";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

// -- IPC Objects

/// Endpoint capability.
///
/// A synchronous IPC destination. Threads can send messages to and receive
/// messages from endpoints. Endpoints support badging for sender identification.
///
/// # Rights
/// - Read: Can receive messages
/// - Write: Can send messages
/// - Grant: Can transfer capabilities in messages
/// - GrantReply: Can transfer reply capabilities
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint;

impl private::Sealed for Endpoint {}
impl CapObjectType for Endpoint {
    const NAME: &'static str = "Endpoint";
    const SUPPORTS_BADGE: bool = true;
    const DEFAULT_RIGHTS: CapRights = CapRights::RWG;
}

/// Notification capability.
///
/// An asynchronous signalling mechanism. A notification contains a single
/// word that is OR'd with the badge when signalled. Supports non-blocking
/// signal delivery and can be bound to a TCB.
///
/// # Rights
/// - Read: Can wait for notifications
/// - Write: Can send signals
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Notification;

impl private::Sealed for Notification {}
impl CapObjectType for Notification {
    const NAME: &'static str = "Notification";
    const SUPPORTS_BADGE: bool = true;
    const DEFAULT_RIGHTS: CapRights = CapRights::RW;
}

/// Reply capability.
///
/// A one-time capability for replying to a synchronous IPC call.
/// Reply capabilities are automatically created during Call operations
/// and are consumed when used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Reply;

impl private::Sealed for Reply {}
impl CapObjectType for Reply {
    const NAME: &'static str = "Reply";
    const DEFAULT_RIGHTS: CapRights = CapRights::RWG;
}

// -- Execution Objects

/// CNode (capability node) capability.
///
/// A table of capability slots. CNodes form the hierarchical capability
/// space (CSpace) structure. Each CNode has a fixed number of slots
/// determined by its radix (2^radix slots).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct CNodeObj;

impl private::Sealed for CNodeObj {}
impl CapObjectType for CNodeObj {
    const NAME: &'static str = "CNode";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Thread control block capability.
///
/// Represents a thread of execution. The TCB contains the register context,
/// scheduling parameters, and references to the thread's CSpace and VSpace.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct TCB;

impl private::Sealed for TCB {}
impl CapObjectType for TCB {
    const NAME: &'static str = "TCB";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

// -- System Objects

/// IRQ handler capability.
///
/// Binds a hardware interrupt to a notification object. When the interrupt
/// fires, the notification is signalled with the configured badge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IRQHandler;

impl private::Sealed for IRQHandler {}
impl CapObjectType for IRQHandler {
    const NAME: &'static str = "IRQHandler";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// IRQ control capability.
///
/// Root authority to create IRQ handlers. There is exactly one IRQControl
/// capability in the system, given to the initial task.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IRQControl;

impl private::Sealed for IRQControl {}
impl CapObjectType for IRQControl {
    const NAME: &'static str = "IRQControl";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Scheduling context capability.
///
/// Represents CPU time budget authority. A scheduling context contains
/// a time budget and period for sporadic server scheduling. Threads
/// require a scheduling context to execute.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchedContext;

impl private::Sealed for SchedContext {}
impl CapObjectType for SchedContext {
    const NAME: &'static str = "SchedContext";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

/// Scheduling control capability.
///
/// Authority to create and configure scheduling contexts. Used for
/// implementing hierarchical scheduling and time partitioning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SchedControl;

impl private::Sealed for SchedControl {}
impl CapObjectType for SchedControl {
    const NAME: &'static str = "SchedControl";
    const DEFAULT_RIGHTS: CapRights = CapRights::ALL;
}

// -- Null Object Type (for untyped CPtrs)

/// Untyped marker for generic capability pointers.
///
/// Used as the default type parameter for [`CPtr`](crate::CPtr) when
/// the capability type is not statically known.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NullObj;

impl private::Sealed for NullObj {}
impl CapObjectType for NullObj {
    const NAME: &'static str = "Null";
    const DEFAULT_RIGHTS: CapRights = CapRights::NONE;
}
