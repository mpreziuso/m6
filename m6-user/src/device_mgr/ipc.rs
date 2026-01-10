//! IPC message protocol for device manager
//!
//! Messages use the standard 6-register format (x0-x5):
//! - x0: Message label (operation type)
//! - x1-x5: Operation-specific arguments
//!
//! Badge on receive identifies the sender.

// -- Request labels (client -> device-mgr)

pub mod request {
    /// Ensure a device driver is running.
    ///
    /// Arguments:
    ///   x1: device path pointer (in shared memory / IPC buffer)
    ///   x2: device path length
    ///
    /// Returns:
    ///   x0: response code
    ///   Capability transfer: endpoint cap to driver (via IPC buffer)
    pub const ENSURE: u64 = 0x0001;

    /// Subscribe to device events (hot-plug, driver death).
    ///
    /// Arguments:
    ///   x1: event mask (which events to subscribe to)
    ///
    /// Capability transfer (in):
    ///   Notification cap to signal when events occur
    ///
    /// Returns:
    ///   x0: response code
    ///   x1: subscription_id
    pub const SUBSCRIBE: u64 = 0x0002;

    /// Unsubscribe from device events.
    ///
    /// Arguments:
    ///   x1: subscription_id
    ///
    /// Returns:
    ///   x0: response code
    pub const UNSUBSCRIBE: u64 = 0x0003;

    /// List available devices.
    ///
    /// Arguments:
    ///   x1: offset (for pagination)
    ///   x2: max_count
    ///
    /// Returns:
    ///   x0: response code
    ///   x1: total device count
    ///   x2: returned count
    ///   Data written to IPC buffer extra data region
    pub const LIST_DEVICES: u64 = 0x0004;

    /// Get detailed device information.
    ///
    /// Arguments:
    ///   x1: device path pointer
    ///   x2: device path length
    ///
    /// Returns:
    ///   x0: response code
    ///   x1: device state
    ///   x2: phys_base
    ///   x3: size
    ///   x4: irq
    pub const GET_DEVICE_INFO: u64 = 0x0005;

    /// Notify device-mgr that supervisor has made a restart decision.
    ///
    /// Arguments:
    ///   x1: driver_id (from death notification)
    ///   x2: action (0 = do not restart, 1 = restart)
    ///
    /// Returns:
    ///   x0: response code
    pub const RESTART_DECISION: u64 = 0x0006;
}

// -- Response codes

pub mod response {
    /// Success
    pub const OK: u64 = 0;
    /// Invalid capability pointer
    pub const ERR_INVALID_CAP: u64 = 1;
    /// No driver available for this device
    pub const ERR_NO_DRIVER: u64 = 2;
    /// Driver spawn failed
    pub const ERR_SPAWN_FAILED: u64 = 3;
    /// Out of memory
    pub const ERR_NO_MEMORY: u64 = 4;
    /// Invalid request (unknown label or bad arguments)
    pub const ERR_INVALID_REQUEST: u64 = 5;
    /// Device not found in registry
    pub const ERR_DEVICE_NOT_FOUND: u64 = 6;
    /// Already subscribed
    pub const ERR_ALREADY_SUBSCRIBED: u64 = 7;
    /// Invalid subscription ID
    pub const ERR_INVALID_SUBSCRIPTION: u64 = 8;
    /// Driver is dead, awaiting restart decision
    pub const ERR_DRIVER_DEAD: u64 = 9;
    /// Driver is starting (try again)
    pub const ERR_DRIVER_STARTING: u64 = 10;
}

// -- Event types for subscription

pub mod event {
    /// A driver has died
    pub const DRIVER_DIED: u64 = 1 << 0;
    /// A device was added (hot-plug)
    pub const DEVICE_ADDED: u64 = 1 << 1;
    /// A device was removed (hot-unplug)
    pub const DEVICE_REMOVED: u64 = 1 << 2;
    /// A driver has started
    pub const DRIVER_STARTED: u64 = 1 << 3;

    /// All events
    pub const ALL: u64 = DRIVER_DIED | DEVICE_ADDED | DEVICE_REMOVED | DRIVER_STARTED;
}

// -- Notification badges

pub mod badge {
    /// Badge bit indicating a driver fault occurred.
    /// The lower bits encode the driver index.
    pub const DRIVER_FAULT_BASE: u64 = 1 << 32;

    /// Extract driver index from fault badge
    #[inline]
    pub const fn driver_index_from_badge(badge: u64) -> u32 {
        (badge & 0xFFFF_FFFF) as u32
    }

    /// Create fault badge for a driver index
    #[inline]
    pub const fn fault_badge_for_driver(index: u32) -> u64 {
        DRIVER_FAULT_BASE | (index as u64)
    }
}

// -- Device state values (for GET_DEVICE_INFO response)

pub mod device_state {
    /// Device enumerated, no driver bound
    pub const UNBOUND: u64 = 0;
    /// Driver is starting
    pub const STARTING: u64 = 1;
    /// Driver is running
    pub const RUNNING: u64 = 2;
    /// Driver has died, awaiting restart decision
    pub const DEAD: u64 = 3;
}
