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
    objects::{
        AsidPoolObject, DmaPoolObject, EndpointObject, EndpointState, FrameObject, IOSpaceObject,
        IrqControlObject, IrqHandlerObject, NotificationObject, PageTableObject, ReplyObject,
        SmmuControlObject, TimerControlObject, TimerObject, UntypedObject, VSpaceObject,
    },
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
    /// I/O address space (IOMMU domain).
    IOSpace = 17,
    /// DMA memory pool.
    DmaPool = 18,
    /// SMMU control (singleton per SMMU).
    SmmuControl = 19,
    /// Timer object.
    Timer = 20,
    /// Timer control (singleton).
    TimerControl = 21,
}

/// Union of all kernel object data.
///
/// Small objects are stored inline. Large objects (TCB, CNode, SmmuControl)
/// use heap-allocated storage with a pointer here.
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
    /// Frame metadata.
    pub frame: ManuallyDrop<FrameObject>,
    /// TCB pointer (heap-allocated).
    pub tcb_ptr: *mut TcbFull,
    /// CNode pointer (heap-allocated).
    pub cnode_ptr: *mut CNodeStorage,
    /// IOSpace metadata.
    pub iospace: ManuallyDrop<IOSpaceObject>,
    /// DMA pool metadata.
    pub dma_pool: ManuallyDrop<DmaPoolObject>,
    /// SMMU control pointer (heap-allocated due to large bitmap).
    pub smmu_control_ptr: *mut SmmuControlObject,
    /// IRQ handler metadata.
    pub irq_handler: ManuallyDrop<IrqHandlerObject>,
    /// IRQ control pointer (heap-allocated due to large bitmap).
    pub irq_control_ptr: *mut IrqControlObject,
    /// Page table metadata.
    pub page_table: ManuallyDrop<PageTableObject>,
    /// ASID pool pointer (heap-allocated due to large arrays).
    pub asid_pool_ptr: *mut AsidPoolObject,
    /// Timer metadata.
    pub timer: ManuallyDrop<TimerObject>,
    /// Timer control metadata.
    pub timer_control: ManuallyDrop<TimerControlObject>,
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

        // Cleanup timer from timer queue if armed
        if obj.obj_type == KernelObjectType::Timer {
            // SAFETY: We verified the object type, so timer is the active variant.
            let timer = unsafe { &obj.data.timer };
            if timer.is_armed() {
                // Unregister from timer queue
                crate::sched::timer_queue::unregister_timer(obj_ref);
            }
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

    /// Atomically dequeue a receiver from an endpoint's RecvQueue.
    ///
    /// If the endpoint is in `RecvQueue` state, removes the head TCB from the queue
    /// (clearing its IPC links) and returns `Dequeued(receiver_ref)`. Otherwise
    /// returns `NoneQueued { old_tail }` with the current queue tail for enqueue use.
    ///
    /// Performing check-and-dequeue within a single lock acquisition prevents the
    /// SMP race where two concurrent senders both observe the same receiver.
    ///
    /// # Safety invariants
    ///
    /// `TcbFull` is heap-allocated behind `tcb_ptr`. Accessing it via raw pointer
    /// while holding `&mut self` is safe because:
    /// - No other code can acquire the table lock concurrently.
    /// - `TcbFull` does not alias any element of `self.objects`.
    fn ipc_dequeue_recv(&mut self, ep_ref: ObjectRef) -> Option<IpcDequeueResult> {
        let ep_idx = ep_ref.index() as usize;
        if ep_idx == 0 || ep_idx >= MAX_OBJECTS {
            return None;
        }

        // Phase 1: read endpoint state. Borrow dropped at end of block.
        let receiver_ref: ObjectRef = {
            let obj = &self.objects[ep_idx];
            if obj.is_free() || obj.obj_type != KernelObjectType::Endpoint {
                return None;
            }
            // SAFETY: verified Endpoint type above.
            unsafe {
                let ep = &*obj.data.endpoint;
                match ep.state {
                    EndpointState::RecvQueue => ep.queue_head,
                    EndpointState::Idle | EndpointState::SendQueue => {
                        return Some(IpcDequeueResult::NoneQueued { old_tail: ep.queue_tail });
                    }
                }
            }
        };

        if !receiver_ref.is_valid() {
            panic!("ipc_dequeue_recv: RecvQueue with invalid queue_head");
        }

        // Phase 2: get receiver TCB pointer. Borrow dropped at end of block.
        let tcb_idx = receiver_ref.index() as usize;
        if tcb_idx == 0 || tcb_idx >= MAX_OBJECTS {
            return None;
        }
        let tcb_ptr: *mut TcbFull = {
            let obj = &self.objects[tcb_idx];
            if obj.is_free() || obj.obj_type != KernelObjectType::Tcb {
                return None;
            }
            // SAFETY: verified Tcb type above.
            unsafe { obj.data.tcb_ptr }
        };
        if tcb_ptr.is_null() {
            return None;
        }

        // Phase 3: clear dequeued TCB's IPC links, capture next.
        // TcbFull is heap-allocated; this does not borrow self.objects.
        // SAFETY: tcb_ptr is valid; we hold the table lock for exclusive access.
        let next = unsafe {
            let tcb = &mut *tcb_ptr;
            let next = tcb.ipc_next;
            tcb.clear_ipc_links();
            next
        };

        // Phase 4: update endpoint queue head and state. Borrow dropped at end of block.
        {
            let obj = &mut self.objects[ep_idx];
            // SAFETY: verified Endpoint type in phase 1.
            unsafe {
                let ep = &mut *obj.data.endpoint;
                ep.queue_head = next;
                if !next.is_valid() {
                    ep.queue_tail = ObjectRef::NULL;
                    ep.state = EndpointState::Idle;
                }
            }
        }

        // Phase 5: clear ipc_prev on the new queue head. Borrow dropped at end of block.
        if next.is_valid() {
            let next_idx = next.index() as usize;
            if next_idx != 0 && next_idx < MAX_OBJECTS {
                let next_tcb_ptr: *mut TcbFull = {
                    let obj = &self.objects[next_idx];
                    if !obj.is_free() && obj.obj_type == KernelObjectType::Tcb {
                        // SAFETY: verified Tcb type above.
                        unsafe { obj.data.tcb_ptr }
                    } else {
                        core::ptr::null_mut()
                    }
                };
                if !next_tcb_ptr.is_null() {
                    // SAFETY: TcbFull is heap-allocated and valid; we hold the table lock.
                    unsafe { (*next_tcb_ptr).ipc_prev = ObjectRef::NULL; }
                }
            }
        }

        Some(IpcDequeueResult::Dequeued(receiver_ref))
    }

    /// Atomically dequeue a sender from an endpoint's SendQueue.
    ///
    /// If the endpoint is in `SendQueue` state, removes the head TCB from the queue
    /// (clearing its IPC links) and returns `Dequeued(sender_ref)`. Otherwise
    /// returns `NoneQueued { old_tail }` with the current queue tail for enqueue use.
    ///
    /// Performing check-and-dequeue within a single lock acquisition prevents the
    /// SMP race where two concurrent receivers both observe the same sender.
    fn ipc_dequeue_send(&mut self, ep_ref: ObjectRef) -> Option<IpcDequeueResult> {
        let ep_idx = ep_ref.index() as usize;
        if ep_idx == 0 || ep_idx >= MAX_OBJECTS {
            return None;
        }

        // Phase 1: read endpoint state. Borrow dropped at end of block.
        let sender_ref: ObjectRef = {
            let obj = &self.objects[ep_idx];
            if obj.is_free() || obj.obj_type != KernelObjectType::Endpoint {
                return None;
            }
            // SAFETY: verified Endpoint type above.
            unsafe {
                let ep = &*obj.data.endpoint;
                match ep.state {
                    EndpointState::SendQueue => ep.queue_head,
                    EndpointState::Idle | EndpointState::RecvQueue => {
                        return Some(IpcDequeueResult::NoneQueued { old_tail: ep.queue_tail });
                    }
                }
            }
        };

        if !sender_ref.is_valid() {
            panic!("ipc_dequeue_send: SendQueue with invalid queue_head");
        }

        // Phase 2: get sender TCB pointer. Borrow dropped at end of block.
        let tcb_idx = sender_ref.index() as usize;
        if tcb_idx == 0 || tcb_idx >= MAX_OBJECTS {
            return None;
        }
        let tcb_ptr: *mut TcbFull = {
            let obj = &self.objects[tcb_idx];
            if obj.is_free() || obj.obj_type != KernelObjectType::Tcb {
                return None;
            }
            // SAFETY: verified Tcb type above.
            unsafe { obj.data.tcb_ptr }
        };
        if tcb_ptr.is_null() {
            return None;
        }

        // Phase 3: clear dequeued TCB's IPC links, capture next.
        // SAFETY: tcb_ptr is valid; we hold the table lock for exclusive access.
        let next = unsafe {
            let tcb = &mut *tcb_ptr;
            let next = tcb.ipc_next;
            tcb.clear_ipc_links();
            next
        };

        // Phase 4: update endpoint queue head and state. Borrow dropped at end of block.
        {
            let obj = &mut self.objects[ep_idx];
            // SAFETY: verified Endpoint type in phase 1.
            unsafe {
                let ep = &mut *obj.data.endpoint;
                ep.queue_head = next;
                if !next.is_valid() {
                    ep.queue_tail = ObjectRef::NULL;
                    ep.state = EndpointState::Idle;
                }
            }
        }

        // Phase 5: clear ipc_prev on the new queue head. Borrow dropped at end of block.
        if next.is_valid() {
            let next_idx = next.index() as usize;
            if next_idx != 0 && next_idx < MAX_OBJECTS {
                let next_tcb_ptr: *mut TcbFull = {
                    let obj = &self.objects[next_idx];
                    if !obj.is_free() && obj.obj_type == KernelObjectType::Tcb {
                        // SAFETY: verified Tcb type above.
                        unsafe { obj.data.tcb_ptr }
                    } else {
                        core::ptr::null_mut()
                    }
                };
                if !next_tcb_ptr.is_null() {
                    // SAFETY: TcbFull is heap-allocated and valid; we hold the table lock.
                    unsafe { (*next_tcb_ptr).ipc_prev = ObjectRef::NULL; }
                }
            }
        }

        Some(IpcDequeueResult::Dequeued(sender_ref))
    }

    // -- IPC commit helpers

    /// Get a TCB raw pointer from the object table by ObjectRef.
    ///
    /// Returns null if the ref is invalid or not a TCB.
    /// Caller must hold the table lock.
    fn tcb_ptr(&self, tcb_ref: ObjectRef) -> *mut TcbFull {
        let idx = tcb_ref.index() as usize;
        if idx == 0 || idx >= MAX_OBJECTS {
            return core::ptr::null_mut();
        }
        let obj = &self.objects[idx];
        if obj.is_free() || obj.obj_type != KernelObjectType::Tcb {
            return core::ptr::null_mut();
        }
        // SAFETY: verified Tcb type above.
        unsafe { obj.data.tcb_ptr }
    }

    /// Get a mutable reference to an endpoint by ObjectRef.
    ///
    /// Returns None if the ref is invalid or not an Endpoint.
    fn endpoint_mut(&mut self, ep_ref: ObjectRef) -> Option<&mut EndpointObject> {
        let idx = ep_ref.index() as usize;
        if idx == 0 || idx >= MAX_OBJECTS {
            return None;
        }
        let obj = &mut self.objects[idx];
        if obj.is_free() || obj.obj_type != KernelObjectType::Endpoint {
            return None;
        }
        // SAFETY: verified Endpoint type above.
        Some(unsafe { &mut obj.data.endpoint })
    }

    /// Dequeue the head TCB from an endpoint queue, advancing head/tail/state.
    ///
    /// Returns the dequeued ref and clears its IPC links. Updates the
    /// endpoint queue pointers. Caller must hold the table lock.
    fn dequeue_queue_head(&mut self, ep_ref: ObjectRef) -> Option<ObjectRef> {
        let ep = self.endpoint_mut(ep_ref)?;
        let head = ep.queue_head;
        if !head.is_valid() {
            return None;
        }

        let head_ptr = self.tcb_ptr(head);
        if head_ptr.is_null() {
            return None;
        }

        // SAFETY: valid TCB, we hold the table lock for exclusive access.
        let next = unsafe {
            let tcb = &mut *head_ptr;
            let n = tcb.ipc_next;
            tcb.clear_ipc_links();
            n
        };

        // Re-borrow endpoint (previous borrow ended with tcb_ptr call).
        let ep = self.endpoint_mut(ep_ref).unwrap();
        ep.queue_head = next;
        if !next.is_valid() {
            ep.queue_tail = ObjectRef::NULL;
            ep.state = EndpointState::Idle;
        }

        // Clear ipc_prev on new head.
        if next.is_valid() {
            let next_ptr = self.tcb_ptr(next);
            if !next_ptr.is_null() {
                // SAFETY: valid TCB, we hold the table lock.
                unsafe { (*next_ptr).ipc_prev = ObjectRef::NULL; }
            }
        }

        Some(head)
    }

    /// Commit phase of do_recv: enqueue receiver or recover from SendQueue.
    ///
    /// Handles all queue manipulation and TCB field reads atomically within
    /// a single lock acquisition. TCB state changes and scheduling happen
    /// outside the lock.
    fn ipc_recv_commit(
        &mut self,
        ep_ref: ObjectRef,
        receiver_ref: ObjectRef,
        old_tail: ObjectRef,
    ) -> Option<IpcRecvCommitResult> {
        let ep = self.endpoint_mut(ep_ref)?;
        let state = ep.state;

        match state {
            EndpointState::Idle | EndpointState::RecvQueue => {
                ep.state = EndpointState::RecvQueue;
                if old_tail.is_valid() {
                    ep.queue_tail = receiver_ref;
                } else {
                    ep.queue_head = receiver_ref;
                    ep.queue_tail = receiver_ref;
                }
                Some(IpcRecvCommitResult::Enqueued)
            }
            EndpointState::SendQueue => {
                // Clean up stale old_tail->ipc_next link written outside the lock.
                if old_tail.is_valid() {
                    let ptr = self.tcb_ptr(old_tail);
                    if !ptr.is_null() {
                        // SAFETY: valid TCB, we hold the table lock.
                        unsafe { (*ptr).ipc_next = ObjectRef::NULL; }
                    }
                }

                // Dequeue sender from SendQueue head.
                let sender_ref = match self.dequeue_queue_head(ep_ref) {
                    Some(s) => s,
                    None => return Some(IpcRecvCommitResult::Enqueued),
                };

                // Read sender's pending message and reply_slot while we hold the lock.
                let sender_ptr = self.tcb_ptr(sender_ref);
                if sender_ptr.is_null() {
                    return Some(IpcRecvCommitResult::Enqueued);
                }

                // SAFETY: valid TCB, we hold the table lock.
                let (reply_slot, pending_msg, badge) = unsafe {
                    let tcb = &*sender_ptr;
                    (tcb.tcb.reply_slot, tcb.ipc_message, tcb.ipc_badge)
                };

                Some(IpcRecvCommitResult::Recovery(RecvRecoveryInfo {
                    sender_ref,
                    sender_reply_slot: reply_slot,
                    pending_msg,
                    badge,
                }))
            }
        }
    }

    /// Commit phase of do_send / do_call: enqueue sender or recover from RecvQueue.
    ///
    /// Handles all queue manipulation atomically within a single lock
    /// acquisition. TCB state changes and scheduling happen outside the lock.
    fn ipc_send_commit(
        &mut self,
        ep_ref: ObjectRef,
        sender_ref: ObjectRef,
        old_tail: ObjectRef,
    ) -> Option<IpcSendCommitResult> {
        let ep = self.endpoint_mut(ep_ref)?;
        let state = ep.state;

        match state {
            EndpointState::Idle | EndpointState::SendQueue => {
                ep.state = EndpointState::SendQueue;
                if old_tail.is_valid() {
                    ep.queue_tail = sender_ref;
                } else {
                    ep.queue_head = sender_ref;
                    ep.queue_tail = sender_ref;
                }
                Some(IpcSendCommitResult::Enqueued)
            }
            EndpointState::RecvQueue => {
                // Clean up stale old_tail->ipc_next link written outside the lock.
                if old_tail.is_valid() {
                    let ptr = self.tcb_ptr(old_tail);
                    if !ptr.is_null() {
                        // SAFETY: valid TCB, we hold the table lock.
                        unsafe { (*ptr).ipc_next = ObjectRef::NULL; }
                    }
                }

                // Dequeue receiver from RecvQueue head.
                let receiver_ref = match self.dequeue_queue_head(ep_ref) {
                    Some(r) => r,
                    None => return Some(IpcSendCommitResult::Enqueued),
                };

                Some(IpcSendCommitResult::Recovery(SendRecoveryInfo {
                    receiver_ref,
                }))
            }
        }
    }
}

/// Result of an atomic IPC dequeue operation.
pub enum IpcDequeueResult {
    /// A thread was successfully dequeued from the endpoint queue.
    Dequeued(ObjectRef),
    /// No thread was queued; contains the current tail for use when enqueuing.
    NoneQueued { old_tail: ObjectRef },
}

/// Result of a recv commit operation.
pub enum IpcRecvCommitResult {
    /// Receiver was enqueued in RecvQueue (normal path).
    Enqueued,
    /// A sender was dequeued from the SendQueue (recovery path).
    Recovery(RecvRecoveryInfo),
}

/// Information extracted from a sender during recv recovery.
pub struct RecvRecoveryInfo {
    /// The dequeued sender TCB reference.
    pub sender_ref: ObjectRef,
    /// Sender's reply_slot (valid = Call operation, NULL = Send operation).
    pub sender_reply_slot: ObjectRef,
    /// Pending message registers from sender's TCB.
    pub pending_msg: [u64; 5],
    /// Badge to deliver with the message.
    pub badge: u64,
}

/// Result of a send/call commit operation.
pub enum IpcSendCommitResult {
    /// Sender was enqueued in SendQueue (normal path).
    Enqueued,
    /// A receiver was dequeued from the RecvQueue (recovery path).
    Recovery(SendRecoveryInfo),
}

/// Information extracted from a receiver during send recovery.
pub struct SendRecoveryInfo {
    /// The dequeued receiver TCB reference.
    pub receiver_ref: ObjectRef,
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

/// Access a TCB with a closure (read-only).
///
/// Returns the result of the closure, or the default value if the object
/// is not a valid TCB.
pub fn with_tcb<F, R>(tcb_ref: ObjectRef, f: F) -> R
where
    F: FnOnce(&TcbFull) -> R,
    R: Default,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(tcb_ref)
        && obj.obj_type == KernelObjectType::Tcb
    {
        // SAFETY: We verified the object type, so tcb_ptr is the active variant.
        let tcb_ptr = unsafe { obj.data.tcb_ptr };
        if !tcb_ptr.is_null() {
            // SAFETY: The TCB was allocated by TcbFull::alloc and is valid.
            return f(unsafe { &*tcb_ptr });
        }
    }
    R::default()
}

/// Access a TCB with a closure (mutable).
///
/// Executes the closure with a mutable reference to the TCB.
/// Returns the result of the closure, or default if not a valid TCB.
pub fn with_tcb_mut<F, R>(tcb_ref: ObjectRef, f: F) -> R
where
    F: FnOnce(&mut TcbFull) -> R,
    R: Default,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(tcb_ref)
        && obj.obj_type == KernelObjectType::Tcb
    {
        // SAFETY: We verified the object type, so tcb_ptr is the active variant.
        let tcb_ptr = unsafe { obj.data.tcb_ptr };
        if !tcb_ptr.is_null() {
            // SAFETY: The TCB was allocated by TcbFull::alloc and is valid.
            // We hold the object table lock so no concurrent access.
            return f(unsafe { &mut *tcb_ptr });
        }
    }
    R::default()
}

/// Access an endpoint with a closure (mutable).
///
/// Executes the closure with a mutable reference to the endpoint.
/// Does nothing if the object is not a valid endpoint.
pub fn with_endpoint_mut<F, R>(ep_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut EndpointObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(ep_ref)
        && obj.obj_type == KernelObjectType::Endpoint
    {
        // SAFETY: We verified the object type, so endpoint is the active variant.
        return Some(f(unsafe { &mut obj.data.endpoint }));
    }
    None
}

/// Access a notification with a closure (mutable).
///
/// Executes the closure with a mutable reference to the notification.
/// Does nothing if the object is not a valid notification.
pub fn with_notification_mut<F, R>(notif_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut NotificationObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(notif_ref)
        && obj.obj_type == KernelObjectType::Notification
    {
        // SAFETY: We verified the object type, so notification is the active variant.
        return Some(f(unsafe { &mut obj.data.notification }));
    }
    None
}

/// Access a reply object with a closure (mutable).
///
/// Executes the closure with a mutable reference to the reply object.
/// Does nothing if the object is not a valid reply.
pub fn with_reply_mut<F, R>(reply_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut ReplyObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(reply_ref)
        && obj.obj_type == KernelObjectType::Reply
    {
        // SAFETY: We verified the object type, so reply is the active variant.
        return Some(f(unsafe { &mut obj.data.reply }));
    }
    None
}

/// Access an untyped object with a closure (mutable).
///
/// Executes the closure with a mutable reference to the untyped object.
/// Does nothing if the object is not a valid untyped.
pub fn with_untyped_mut<F, R>(untyped_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut UntypedObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(untyped_ref)
        && obj.obj_type == KernelObjectType::Untyped
    {
        // SAFETY: We verified the object type, so untyped is the active variant.
        return Some(f(unsafe { &mut obj.data.untyped }));
    }
    None
}

/// Access an untyped object with a closure (immutable).
///
/// Executes the closure with an immutable reference to the untyped object.
/// Used for offset-based allocation from device untypeds.
/// Does nothing if the object is not a valid untyped.
pub fn with_untyped<F, R>(untyped_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&UntypedObject) -> R,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(untyped_ref)
        && obj.obj_type == KernelObjectType::Untyped
    {
        // SAFETY: We verified the object type, so untyped is the active variant.
        return Some(f(unsafe { &obj.data.untyped }));
    }
    None
}

/// Access a frame with a closure (mutable).
///
/// Executes the closure with a mutable reference to the frame.
/// Does nothing if the object is not a valid frame.
pub fn with_frame_mut<F, R>(frame_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut FrameObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(frame_ref)
        && (obj.obj_type == KernelObjectType::Frame
            || obj.obj_type == KernelObjectType::DeviceFrame)
    {
        // SAFETY: We verified the object type, so frame is the active variant.
        return Some(f(unsafe { &mut obj.data.frame }));
    }
    None
}

/// Access an IOSpace with a closure (mutable).
///
/// Executes the closure with a mutable reference to the IOSpace.
/// Does nothing if the object is not a valid IOSpace.
pub fn with_iospace_mut<F, R>(iospace_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut IOSpaceObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(iospace_ref)
        && obj.obj_type == KernelObjectType::IOSpace
    {
        // SAFETY: We verified the object type, so iospace is the active variant.
        return Some(f(unsafe { &mut obj.data.iospace }));
    }
    None
}

/// Access a DmaPool with a closure (mutable).
///
/// Executes the closure with a mutable reference to the DmaPool.
/// Does nothing if the object is not a valid DmaPool.
pub fn with_dma_pool_mut<F, R>(pool_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut DmaPoolObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(pool_ref)
        && obj.obj_type == KernelObjectType::DmaPool
    {
        // SAFETY: We verified the object type, so dma_pool is the active variant.
        return Some(f(unsafe { &mut obj.data.dma_pool }));
    }
    None
}

/// Access an SmmuControl with a closure (mutable).
///
/// Executes the closure with a mutable reference to the SmmuControl.
/// Does nothing if the object is not a valid SmmuControl.
pub fn with_smmu_control_mut<F, R>(smmu_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut SmmuControlObject) -> R,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(smmu_ref)
        && obj.obj_type == KernelObjectType::SmmuControl
    {
        // SAFETY: We verified the object type, so smmu_control_ptr is the active variant.
        let ptr = unsafe { obj.data.smmu_control_ptr };
        if !ptr.is_null() {
            // SAFETY: The SmmuControl was heap-allocated and is valid.
            // We hold the object table lock so no concurrent access.
            return Some(f(unsafe { &mut *ptr }));
        }
    }
    None
}

/// Access an IRQ handler with a closure (mutable).
///
/// Executes the closure with a mutable reference to the IRQ handler.
/// Does nothing if the object is not a valid IRQ handler.
pub fn with_irq_handler_mut<F, R>(handler_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut IrqHandlerObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(handler_ref)
        && obj.obj_type == KernelObjectType::IrqHandler
    {
        // SAFETY: We verified the object type, so irq_handler is the active variant.
        return Some(f(unsafe { &mut obj.data.irq_handler }));
    }
    None
}

/// Access an IRQ control with a closure (mutable).
///
/// Executes the closure with a mutable reference to the IRQ control.
/// Does nothing if the object is not a valid IRQ control.
pub fn with_irq_control_mut<F, R>(control_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut IrqControlObject) -> R,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(control_ref) {
        if obj.obj_type == KernelObjectType::IrqControl {
            // SAFETY: We verified the object type, so irq_control_ptr is the active variant.
            let ptr = unsafe { obj.data.irq_control_ptr };
            if !ptr.is_null() {
                // SAFETY: The IrqControl was heap-allocated and is valid.
                // We hold the object table lock so no concurrent access.
                return Some(f(unsafe { &mut *ptr }));
            } else {
                log::warn!(
                    "with_irq_control_mut: irq_control_ptr is null for {:?}",
                    control_ref
                );
            }
        } else {
            log::warn!(
                "with_irq_control_mut: obj_type is {:?}, expected IrqControl for {:?}",
                obj.obj_type,
                control_ref
            );
        }
    } else {
        log::warn!(
            "with_irq_control_mut: table.get returned None for {:?}",
            control_ref
        );
    }
    None
}

/// Access a timer with a closure (mutable).
///
/// Executes the closure with a mutable reference to the timer.
/// Does nothing if the object is not a valid timer.
pub fn with_timer_mut<F, R>(timer_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut TimerObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(timer_ref)
        && obj.obj_type == KernelObjectType::Timer
    {
        // SAFETY: We verified the object type, so timer is the active variant.
        return Some(f(unsafe { &mut obj.data.timer }));
    }
    None
}

/// Access a timer control with a closure (mutable).
///
/// Executes the closure with a mutable reference to the timer control.
/// Does nothing if the object is not a valid timer control.
pub fn with_timer_control_mut<F, R>(control_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut TimerControlObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(control_ref)
        && obj.obj_type == KernelObjectType::TimerControl
    {
        // SAFETY: We verified the object type, so timer_control is the active variant.
        return Some(f(unsafe { &mut obj.data.timer_control }));
    }
    None
}

/// Access a VSpace with a closure (mutable).
///
/// Executes the closure with a mutable reference to the VSpace.
/// Does nothing if the object is not a valid VSpace.
pub fn with_vspace_mut<F, R>(vspace_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut VSpaceObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(vspace_ref)
        && obj.obj_type == KernelObjectType::VSpace
    {
        // SAFETY: We verified the object type, so vspace is the active variant.
        return Some(f(unsafe { &mut obj.data.vspace }));
    }
    None
}

/// Access a VSpace with a closure (read-only).
///
/// Executes the closure with a reference to the VSpace.
/// Does nothing if the object is not a valid VSpace.
pub fn with_vspace<F, R>(vspace_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&VSpaceObject) -> R,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(vspace_ref)
        && obj.obj_type == KernelObjectType::VSpace
    {
        // SAFETY: We verified the object type, so vspace is the active variant.
        return Some(f(unsafe { &obj.data.vspace }));
    }
    None
}

/// Access an ASID pool with a closure (mutable).
///
/// Executes the closure with a mutable reference to the ASID pool.
/// Does nothing if the object is not a valid ASID pool.
pub fn with_asid_pool_mut<F, R>(asid_pool_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut AsidPoolObject) -> R,
{
    let mut table = get_table().lock();
    if let Some(obj) = table.get_mut(asid_pool_ref)
        && obj.obj_type == KernelObjectType::AsidPool
    {
        let asid_pool_ptr = unsafe { obj.data.asid_pool_ptr };
        if !asid_pool_ptr.is_null() {
            // SAFETY: We verified the object type and null checked the pointer.
            return Some(f(unsafe { &mut *asid_pool_ptr }));
        }
    }
    None
}

/// Atomically check endpoint state and dequeue a receiver.
///
/// Acquires the object table lock once and performs both the state check
/// and dequeue atomically, preventing SMP races in `do_send`/`do_call`.
pub fn ipc_dequeue_recv(ep_ref: ObjectRef) -> Option<IpcDequeueResult> {
    get_table().lock().ipc_dequeue_recv(ep_ref)
}

/// Atomically check endpoint state and dequeue a sender.
///
/// Acquires the object table lock once and performs both the state check
/// and dequeue atomically, preventing SMP races in `do_recv`.
pub fn ipc_dequeue_send(ep_ref: ObjectRef) -> Option<IpcDequeueResult> {
    get_table().lock().ipc_dequeue_send(ep_ref)
}

/// Commit phase for do_recv: enqueue receiver or recover from SendQueue.
///
/// Acquires the object table lock once for all queue manipulation and
/// TCB field reads, preventing self-deadlock on SMP recovery paths.
pub fn ipc_recv_commit(
    ep_ref: ObjectRef,
    receiver_ref: ObjectRef,
    old_tail: ObjectRef,
) -> Option<IpcRecvCommitResult> {
    get_table().lock().ipc_recv_commit(ep_ref, receiver_ref, old_tail)
}

/// Commit phase for do_send / do_call: enqueue sender or recover from RecvQueue.
///
/// Acquires the object table lock once for all queue manipulation,
/// preventing self-deadlock on SMP recovery paths.
pub fn ipc_send_commit(
    ep_ref: ObjectRef,
    sender_ref: ObjectRef,
    old_tail: ObjectRef,
) -> Option<IpcSendCommitResult> {
    get_table().lock().ipc_send_commit(ep_ref, sender_ref, old_tail)
}

/// Access a PageTable with a closure (read-only).
///
/// Executes the closure with a reference to the PageTable.
/// Does nothing if the object is not a valid PageTable.
pub fn with_page_table<F, R>(pt_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&PageTableObject) -> R,
{
    let table = get_table().lock();
    if let Some(obj) = table.get(pt_ref)
        && obj.obj_type == KernelObjectType::PageTable
    {
        // SAFETY: We verified the object type, so page_table is the active variant.
        return Some(f(unsafe { &obj.data.page_table }));
    }
    None
}
