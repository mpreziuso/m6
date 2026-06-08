// Forked from Fuchsia's Starnix `expando` for M6 (no_std).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::any::{Any, TypeId};
use core::marker::{Send, Sync};
use core::ops::Deref;
use starnix_sync::Mutex;

// -- A spot in an `Expando`, holding a value of type `Arc<T>`.
#[derive(Debug)]
struct ExpandoSlot {
    value: Arc<dyn Any + Send + Sync>,
}

impl ExpandoSlot {
    fn new(value: Arc<dyn Any + Send + Sync>) -> Self {
        ExpandoSlot { value }
    }

    fn downcast<T: Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.value.clone().downcast::<T>().ok()
    }
}

/// A lazy collection of values of every type.
///
/// An Expando contains a single instance of every type. The values are instantiated lazily
/// when accessed. Useful for letting modules add their own state to context objects without
/// requiring the context object itself to know about the types in every module.
#[derive(Debug, Default)]
pub struct Expando {
    properties: Mutex<BTreeMap<TypeId, ExpandoSlot>>,
}

impl Expando {
    /// Get the slot in the expando associated with the given type, lazily creating it.
    pub fn get<T: Any + Send + Sync + Default + 'static>(&self) -> Arc<T> {
        let mut properties = self.properties.lock();
        let type_id = TypeId::of::<T>();
        let slot =
            properties.entry(type_id).or_insert_with(|| ExpandoSlot::new(Arc::new(T::default())));
        assert_eq!(type_id, slot.value.deref().type_id());
        slot.downcast().expect("downcast of expando slot was successful")
    }

    /// Get the slot, running `init` to initialise it if needed.
    pub fn get_or_init<T: Any + Send + Sync + 'static>(&self, init: impl FnOnce() -> T) -> Arc<T> {
        self.get_or_try_init::<T, ()>(|| Ok(init())).expect("infallible initializer")
    }

    /// Get the slot, running `try_init` to initialise it if needed; errors only if `try_init` does.
    pub fn get_or_try_init<T: Any + Send + Sync + 'static, E>(
        &self,
        try_init: impl FnOnce() -> Result<T, E>,
    ) -> Result<Arc<T>, E> {
        let type_id = TypeId::of::<T>();

        // Acquire the lock each time we look at the map so the user-provided initialiser can use
        // the expando too.
        if let Some(slot) = self.properties.lock().get(&type_id) {
            assert_eq!(type_id, slot.value.deref().type_id());
            return Ok(slot.downcast().expect("downcast of expando slot was successful"));
        }

        // Initialise the new value without holding the lock.
        let newly_init = Arc::new(try_init()?);

        // Only insert the newly-initialised value if no other thread got there first.
        let mut properties = self.properties.lock();
        let slot = properties.entry(type_id).or_insert_with(|| ExpandoSlot::new(newly_init));
        assert_eq!(type_id, slot.value.deref().type_id());
        Ok(slot.downcast().expect("downcast of expando slot was successful"))
    }

    /// Get the slot if it has previously been initialised.
    pub fn peek<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        let properties = self.properties.lock();
        let type_id = TypeId::of::<T>();
        let slot = properties.get(&type_id)?;
        assert_eq!(type_id, slot.value.deref().type_id());
        Some(slot.downcast().expect("downcast of expando slot was successful"))
    }

    /// Remove the provided type from the expando if present.
    pub fn remove<T: Any + Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        let mut properties = self.properties.lock();
        let type_id = TypeId::of::<T>();
        let slot = properties.remove(&type_id)?;
        assert_eq!(type_id, slot.value.deref().type_id());
        Some(slot.downcast().expect("downcast of expando slot was successful"))
    }
}
