//! Run Queue Implementation
//!
//! Uses an intrusive doubly-linked list with the `sched_next` and `sched_prev`
//! fields in `TcbFull`. Tasks are ordered by virtual deadline for EEVDF.

use m6_cap::ObjectRef;

use crate::cap::object_table::{self, KernelObjectType};
use crate::cap::tcb_storage::TcbFull;

/// Per-CPU run queue using intrusive linked list.
///
/// Tasks are linked via their `sched_next` and `sched_prev` fields.
/// The list is ordered by virtual deadline (earliest first).
pub struct RunQueue {
    /// Head of the run queue (earliest deadline).
    head: ObjectRef,
    /// Tail of the run queue (latest deadline).
    tail: ObjectRef,
    /// Number of tasks in the queue.
    count: u32,
}

impl RunQueue {
    /// Create a new empty run queue.
    pub const fn new() -> Self {
        Self {
            head: ObjectRef::NULL,
            tail: ObjectRef::NULL,
            count: 0,
        }
    }

    /// Check if the run queue is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Get the number of tasks in the queue.
    #[inline]
    pub const fn len(&self) -> u32 {
        self.count
    }

    /// Get the head of the queue.
    #[inline]
    pub const fn head(&self) -> ObjectRef {
        self.head
    }

    /// Get the tail of the queue.
    #[inline]
    pub const fn tail(&self) -> ObjectRef {
        self.tail
    }

    /// Insert a task into the run queue in virtual-deadline order.
    ///
    /// This walks the list to find the correct insertion point based on
    /// the task's virtual deadline.
    pub fn insert(&mut self, tcb_ref: ObjectRef, v_deadline: u128) {
        if !tcb_ref.is_valid() {
            return;
        }

        // First, ensure the task is not already in the queue
        let already_in_queue = object_table::with_object(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &*obj.data.tcb_ptr };
                tcb.is_in_sched_queue()
            } else {
                false
            }
        })
        .unwrap_or(false);

        if already_in_queue {
            return;
        }

        // Find insertion point (ordered by v_deadline, earliest first)
        let mut insert_after = ObjectRef::NULL;
        let mut current = self.head;

        while current.is_valid() {
            let current_deadline = object_table::with_object(current, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &*obj.data.tcb_ptr };
                    Some(tcb.v_deadline)
                } else {
                    None
                }
            })
            .flatten();

            match current_deadline {
                Some(current_vd) if current_vd <= v_deadline => {
                    // Current task has earlier or equal deadline, keep searching
                    insert_after = current;
                    current = object_table::with_object(current, |obj| {
                        if obj.obj_type == KernelObjectType::Tcb {
                            // SAFETY: We verified the type.
                            unsafe { (*obj.data.tcb_ptr).sched_next }
                        } else {
                            ObjectRef::NULL
                        }
                    })
                    .unwrap_or(ObjectRef::NULL);
                }
                _ => break,
            }
        }

        // Insert the task
        if !insert_after.is_valid() {
            // Insert at head
            self.insert_at_head(tcb_ref);
        } else if insert_after == self.tail {
            // Insert at tail
            self.insert_at_tail(tcb_ref);
        } else {
            // Insert in the middle
            self.insert_after(insert_after, tcb_ref);
        }

        self.count += 1;
    }

    /// Insert a task at the head of the queue.
    fn insert_at_head(&mut self, tcb_ref: ObjectRef) {
        let old_head = self.head;

        // Update new task's links
        object_table::with_object_mut(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &mut *obj.data.tcb_ptr };
                tcb.sched_prev = ObjectRef::NULL;
                tcb.sched_next = old_head;
            }
        });

        // Update old head's prev link
        if old_head.is_valid() {
            object_table::with_object_mut(old_head, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &mut *obj.data.tcb_ptr };
                    tcb.sched_prev = tcb_ref;
                }
            });
        } else {
            // Queue was empty, new task is also tail
            self.tail = tcb_ref;
        }

        self.head = tcb_ref;
    }

    /// Insert a task at the tail of the queue.
    fn insert_at_tail(&mut self, tcb_ref: ObjectRef) {
        let old_tail = self.tail;

        // Update new task's links
        object_table::with_object_mut(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &mut *obj.data.tcb_ptr };
                tcb.sched_prev = old_tail;
                tcb.sched_next = ObjectRef::NULL;
            }
        });

        // Update old tail's next link
        if old_tail.is_valid() {
            object_table::with_object_mut(old_tail, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &mut *obj.data.tcb_ptr };
                    tcb.sched_next = tcb_ref;
                }
            });
        } else {
            // Queue was empty, new task is also head
            self.head = tcb_ref;
        }

        self.tail = tcb_ref;
    }

    /// Insert a task after a specific task.
    fn insert_after(&mut self, after: ObjectRef, tcb_ref: ObjectRef) {
        // Get the task that will be after the new one
        let next = object_table::with_object(after, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                unsafe { (*obj.data.tcb_ptr).sched_next }
            } else {
                ObjectRef::NULL
            }
        })
        .unwrap_or(ObjectRef::NULL);

        // Update new task's links
        object_table::with_object_mut(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &mut *obj.data.tcb_ptr };
                tcb.sched_prev = after;
                tcb.sched_next = next;
            }
        });

        // Update after's next link
        object_table::with_object_mut(after, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &mut *obj.data.tcb_ptr };
                tcb.sched_next = tcb_ref;
            }
        });

        // Update next's prev link
        if next.is_valid() {
            object_table::with_object_mut(next, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &mut *obj.data.tcb_ptr };
                    tcb.sched_prev = tcb_ref;
                }
            });
        } else {
            // We're now the tail
            self.tail = tcb_ref;
        }
    }

    /// Remove a task from the run queue.
    pub fn remove(&mut self, tcb_ref: ObjectRef) {
        if !tcb_ref.is_valid() {
            return;
        }

        // Get the task's links
        let (prev, next) = object_table::with_object(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &*obj.data.tcb_ptr };
                if tcb.is_in_sched_queue() {
                    Some((tcb.sched_prev, tcb.sched_next))
                } else {
                    None
                }
            } else {
                None
            }
        })
        .flatten()
        .unwrap_or((ObjectRef::NULL, ObjectRef::NULL));

        // Check if task was in queue
        let was_in_queue = object_table::with_object(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &*obj.data.tcb_ptr };
                tcb.is_in_sched_queue()
            } else {
                false
            }
        })
        .unwrap_or(false);

        if !was_in_queue {
            return;
        }

        // Update prev's next link
        if prev.is_valid() {
            object_table::with_object_mut(prev, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &mut *obj.data.tcb_ptr };
                    tcb.sched_next = next;
                }
            });
        } else {
            // We were the head
            self.head = next;
        }

        // Update next's prev link
        if next.is_valid() {
            object_table::with_object_mut(next, |obj| {
                if obj.obj_type == KernelObjectType::Tcb {
                    // SAFETY: We verified the type.
                    let tcb = unsafe { &mut *obj.data.tcb_ptr };
                    tcb.sched_prev = prev;
                }
            });
        } else {
            // We were the tail
            self.tail = prev;
        }

        // Clear the task's links
        object_table::with_object_mut(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &mut *obj.data.tcb_ptr };
                tcb.clear_sched_links();
            }
        });

        self.count = self.count.saturating_sub(1);
    }

    /// Check if a task is in this run queue.
    pub fn contains(&self, tcb_ref: ObjectRef) -> bool {
        if !tcb_ref.is_valid() {
            return false;
        }

        object_table::with_object(tcb_ref, |obj| {
            if obj.obj_type == KernelObjectType::Tcb {
                // SAFETY: We verified the type.
                let tcb = unsafe { &*obj.data.tcb_ptr };
                // Check if task is in a scheduler queue by examining its links
                // A task is in this queue if it has sched links set OR if it's the head/tail
                if tcb.is_in_sched_queue() {
                    // Walk the list to confirm it's in THIS queue
                    let mut current = self.head;
                    while current.is_valid() {
                        if current == tcb_ref {
                            return true;
                        }
                        current = object_table::with_object(current, |o| {
                            if o.obj_type == KernelObjectType::Tcb {
                                // SAFETY: We verified the type.
                                unsafe { (*o.data.tcb_ptr).sched_next }
                            } else {
                                ObjectRef::NULL
                            }
                        })
                        .unwrap_or(ObjectRef::NULL);
                    }
                }
                false
            } else {
                false
            }
        })
        .unwrap_or(false)
    }

    /// Get the first (earliest deadline) task without removing it.
    #[inline]
    pub fn peek(&self) -> Option<ObjectRef> {
        if self.head.is_valid() {
            Some(self.head)
        } else {
            None
        }
    }

    /// Pop the first (earliest deadline) task.
    pub fn pop(&mut self) -> Option<ObjectRef> {
        let head = self.head;
        if head.is_valid() {
            self.remove(head);
            Some(head)
        } else {
            None
        }
    }
}

impl Default for RunQueue {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper function to get a TCB from the object table.
pub fn with_tcb<F, R>(tcb_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&TcbFull) -> R,
{
    object_table::with_object(tcb_ref, |obj| {
        if obj.obj_type == KernelObjectType::Tcb {
            // SAFETY: We verified the type.
            Some(f(unsafe { &*obj.data.tcb_ptr }))
        } else {
            None
        }
    })
    .flatten()
}

/// Helper function to mutably access a TCB from the object table.
pub fn with_tcb_mut<F, R>(tcb_ref: ObjectRef, f: F) -> Option<R>
where
    F: FnOnce(&mut TcbFull) -> R,
{
    object_table::with_object_mut(tcb_ref, |obj| {
        if obj.obj_type == KernelObjectType::Tcb {
            // SAFETY: We verified the type.
            Some(f(unsafe { &mut *obj.data.tcb_ptr }))
        } else {
            None
        }
    })
    .flatten()
}
