//! Kernel object table
//!
//! The object table stores all kernel objects indexed by [`ObjectRef`].
//! It is protected by [`IrqSpinMutex`] to allow safe access from both
//! normal and interrupt contexts.
//!
//! # Design
//!
//! - Index 0 is reserved (NULL reference)
//! - Objects are stored in a flat array with a free list
//! - Generation counters prevent ABA problems
//! - Reference counts track capability references

extern crate alloc;

use core::mem::ManuallyDrop;

use alloc::boxed::Box;
use m6_arch::IrqSpinMutex;
use m6_cap::{
    ObjectRef,
    objects::{EndpointObject, NotificationObject, ReplyObject, UntypedObject, VSpaceObject},
};
use spin::Once;

use super::cnode_storage::CNodeStorage;
use super::tcb_storage::TcbFull;

/// Maximum number of kernel objects.
pub const MAX_OBJECTS: usize = 65536;

/// Kernel object type discriminant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum KernelObjectType {
    /// Free slot (in free list).
    #[default]
    Free = 0,
    /// Untyped memory.
    Untyped = 1,
    /// Normal memory frame.
    Frame = 2,
    /// Device memory frame.
    DeviceFrame = 3,
    /// Page table (any level).
    PageTable = 4,
    /// Virtual address space.
    VSpace = 5,
    /// ASID pool.
    AsidPool = 6,
    /// ASID control (singleton).
    AsidControl = 7,
    /// Synchronous IPC endpoint.
    Endpoint = 8,
    /// Asynchronous notification.
    Notification = 9,
    /// One-time reply capability.
    Reply = 10,
    /// Capability node.
    CNode = 11,
    /// Thread control block.
    Tcb = 12,
    /// IRQ handler.
    IrqHandler = 13,
    /// IRQ control (singleton).
    IrqControl = 14,
    /// Scheduling context.
    SchedContext = 15,
    /// Scheduling control (singleton).
    SchedControl = 16,
}

/// Union of all kernel object data.
///
/// Small objects are stored inline. Large objects (TCB, CNode) use
/// heap-allocated storage with a pointer here.
///
/// Non-Copy types are wrapped in ManuallyDrop to satisfy union requirements.
#[repr(C)]
pub union KernelObjectData {
    /// Free list link (next free index).
    pub next_free: u32,
    /// Untyped memory metadata.
    pub untyped: ManuallyDrop<UntypedObject>,
    /// Endpoint metadata.
    pub endpoint: ManuallyDrop<EndpointObject>,
    /// Notification metadata.
    pub notification: ManuallyDrop<NotificationObject>,
    /// Reply metadata.
    pub reply: ManuallyDrop<ReplyObject>,
    /// VSpace metadata.
    pub vspace: ManuallyDrop<VSpaceObject>,
    /// TCB pointer (heap-allocated).
    pub tcb_ptr: *mut TcbFull,
    /// CNode pointer (heap-allocated).
    pub cnode_ptr: *mut CNodeStorage,
}

// SAFETY: Pointers are only accessed with object table lock held.
unsafe impl Send for KernelObjectData {}
unsafe impl Sync for KernelObjectData {}

impl Default for KernelObjectData {
    fn default() -> Self {
        Self { next_free: 0 }
    }
}

impl Clone for KernelObjectData {
    fn clone(&self) -> Self {
        // SAFETY: We only clone free slots or when we know the active variant.
        Self {
            next_free: unsafe { self.next_free },
        }
    }
}

/// Kernel object entry.
#[repr(C)]
#[derive(Clone)]
pub struct KernelObject {
    /// Object type discriminant.
    pub obj_type: KernelObjectType,
    /// Generation counter (incremented on each reuse).
    pub generation: u16,
    /// Padding for alignment.
    _pad: u8,
    /// Reference count (number of capabilities pointing here).
    pub ref_count: u32,
    /// Object-specific data.
    pub data: KernelObjectData,
}

impl KernelObject {
    /// Create a free object slot.
    fn free() -> Self {
        Self {
            obj_type: KernelObjectType::Free,
            generation: 0,
            _pad: 0,
            ref_count: 0,
            data: KernelObjectData { next_free: 0 },
        }
    }

    /// Check if this slot is free.
    #[inline]
    pub fn is_free(&self) -> bool {
        matches!(self.obj_type, KernelObjectType::Free)
    }
}

/// Object table storage.
pub struct ObjectTable {
    /// Object storage array (boxed to avoid stack overflow).
    objects: Box<[KernelObject]>,
    /// Head of free list (index).
    free_head: u32,
    /// Number of allocated objects.
    allocated: u32,
}

impl ObjectTable {
    /// Create a new object table.
    fn new() -> Self {
        // Allocate on heap to avoid stack overflow
        let mut objects: Box<[KernelObject]> =
            (0..MAX_OBJECTS).map(|_| KernelObject::free()).collect();

        // Build free list: index 0 is NULL, so start at 1
        for i in 1..MAX_OBJECTS - 1 {
            objects[i].data.next_free = (i + 1) as u32;
        }
        // Last entry points to 0 (end of list)
        objects[MAX_OBJECTS - 1].data.next_free = 0;

        Self {
            objects,
            free_head: 1, // Start at index 1 (0 is NULL)
            allocated: 0,
        }
    }

    /// Allocate a new object slot.
    ///
    /// Returns the [`ObjectRef`] for the new slot, or `None` if exhausted.
    pub fn alloc(&mut self, obj_type: KernelObjectType) -> Option<ObjectRef> {
        if self.free_head == 0 {
            return None;
        }

        let index = self.free_head;
        let obj = &mut self.objects[index as usize];

        // SAFETY: This slot is in the free list, so data.next_free is valid.
        let next_free = unsafe { obj.data.next_free };
        self.free_head = next_free;

        // Initialise the object
        obj.obj_type = obj_type;
        obj.generation = obj.generation.wrapping_add(1);
        obj.ref_count = 0;
        obj.data = KernelObjectData::default();

        self.allocated += 1;
        Some(ObjectRef::from_index(index))
    }

    /// Free an object slot.
    ///
    /// The object should have ref_count == 0 and be fully cleaned up.
    ///
    /// # Safety
    ///
    /// The caller must ensure any heap-allocated data (TCB, CNode) has been
    /// freed before calling this.
    pub unsafe fn free(&mut self, obj_ref: ObjectRef) {
        let index = obj_ref.index();
        if index == 0 || index as usize >= MAX_OBJECTS {
            return;
        }

        let obj = &mut self.objects[index as usize];
        if obj.is_free() {
            return; // Already free
        }

        // Add to free list
        obj.obj_type = KernelObjectType::Free;
        obj.data.next_free = self.free_head;
        self.free_head = index;
        self.allocated = self.allocated.saturating_sub(1);
    }

    /// Get a reference to an object.
    #[inline]
    pub fn get(&self, obj_ref: ObjectRef) -> Option<&KernelObject> {
        let index = obj_ref.index() as usize;
        if index == 0 || index >= MAX_OBJECTS {
            return None;
        }
        let obj = &self.objects[index];
        if obj.is_free() {
            return None;
        }
        Some(obj)
    }

    /// Get a mutable reference to an object.
    #[inline]
    pub fn get_mut(&mut self, obj_ref: ObjectRef) -> Option<&mut KernelObject> {
        let index = obj_ref.index() as usize;
        if index == 0 || index >= MAX_OBJECTS {
            return None;
        }
        let obj = &mut self.objects[index];
        if obj.is_free() {
            return None;
        }
        Some(obj)
    }

    /// Increment reference count for an object.
    pub fn inc_ref(&mut self, obj_ref: ObjectRef) {
        if let Some(obj) = self.get_mut(obj_ref) {
            obj.ref_count = obj.ref_count.saturating_add(1);
        }
    }

    /// Decrement reference count for an object.
    ///
    /// Returns `true` if the reference count reached zero.
    pub fn dec_ref(&mut self, obj_ref: ObjectRef) -> bool {
        if let Some(obj) = self.get_mut(obj_ref) {
            obj.ref_count = obj.ref_count.saturating_sub(1);
            obj.ref_count == 0
        } else {
            false
        }
    }

    /// Get the number of allocated objects.
    #[inline]
    pub fn allocated(&self) -> u32 {
        self.allocated
    }

    /// Get the number of free slots.
    #[inline]
    pub fn free_count(&self) -> u32 {
        (MAX_OBJECTS as u32 - 1).saturating_sub(self.allocated)
    }
}

/// Global kernel object table.
///
/// Lazily initialised on first access. Protected by [`IrqSpinMutex`].
static OBJECT_TABLE: Once<IrqSpinMutex<ObjectTable>> = Once::new();

/// Get the global object table, initialising if necessary.
fn get_table() -> &'static IrqSpinMutex<ObjectTable> {
    OBJECT_TABLE.call_once(|| {
        log::debug!("Object table initialised with {} slots", MAX_OBJECTS - 1);
        IrqSpinMutex::new(ObjectTable::new())
    })
}

/// Initialise the global object table.
///
/// This is called during kernel initialisation. It's safe to call multiple
/// times (subsequent calls are no-ops).
pub fn init() {
    let _ = get_table();
}

/// Allocate a new kernel object.
pub fn alloc(obj_type: KernelObjectType) -> Option<ObjectRef> {
    get_table().lock().alloc(obj_type)
}

/// Free a kernel object.
///
/// # Safety
///
/// The caller must ensure any heap-allocated data has been freed.
pub unsafe fn free(obj_ref: ObjectRef) {
    // SAFETY: Caller guarantees cleanup is complete.
    unsafe { get_table().lock().free(obj_ref) }
}

/// Access the object table with a closure.
///
/// This is the primary way to access objects. The closure receives
/// a mutable reference to the table while holding the lock.
pub fn with_table<F, R>(f: F) -> R
where
    F: FnOnce(&mut ObjectTable) -> R,
{
    f(&mut get_table().lock())
}

/// Get a read-only view of an object.
///
/// Useful when you only need to read object metadata.
pub fn with_object<F, R>(obj_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&KernelObject) -> R,
{
    let table = get_table().lock();
    table.get(obj_ref).map(f)
}

/// Get a mutable view of an object.
pub fn with_object_mut<F, R>(obj_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut KernelObject) -> R,
{
    let mut table = get_table().lock();
    table.get_mut(obj_ref).map(f)
}
