//! Device registry for tracking enumerated devices and spawned drivers.
//!
//! The registry maintains:
//! - List of devices discovered from DTB
//! - List of spawned drivers
//! - Client subscriptions for event notifications
//! - Capability slot allocation

/// Maximum supported devices
pub const MAX_DEVICES: usize = 128;
/// Maximum supported drivers
pub const MAX_DRIVERS: usize = 64;
/// Maximum subscriptions
pub const MAX_SUBSCRIPTIONS: usize = 16;
/// Maximum device path length
pub const MAX_PATH_LEN: usize = 128;
/// Maximum compatible string length
pub const MAX_COMPAT_LEN: usize = 64;

/// Device state in the registry
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceState {
    /// Device enumerated, no driver assigned
    Unbound = 0,
    /// Driver is starting
    Starting = 1,
    /// Driver is running
    Running = 2,
    /// Driver died, pending restart decision
    Dead = 3,
}

/// MSI-X capability information for PCIe devices
#[derive(Clone, Copy, Debug, Default)]
pub struct MsixInfo {
    /// Whether MSI-X capability is present
    pub present: bool,
    /// Number of MSI-X vectors available
    pub table_size: u16,
    /// BAR index containing MSI-X table (0-5)
    pub table_bir: u8,
    /// Offset of MSI-X table within the BAR
    pub table_offset: u32,
    /// Config space offset of MSI-X capability
    pub cap_offset: u8,
}

/// Device entry in registry
#[derive(Clone)]
pub struct DeviceEntry {
    /// FDT node path (e.g., "/soc/uart@9000000") or PCIe BDF (e.g., "pcie:00:00.0")
    pub path: [u8; MAX_PATH_LEN],
    pub path_len: usize,
    /// First compatible string from FDT or PCIe class code (e.g., "pcie:010802")
    pub compatible: [u8; MAX_COMPAT_LEN],
    pub compatible_len: usize,
    /// Physical base address (from reg property or BAR0 for PCIe)
    pub phys_base: u64,
    /// Size of MMIO region
    pub size: u64,
    /// IRQ number (from interrupts property), 0 if none
    pub irq: u32,
    /// VirtIO device ID (0 if not a virtio device or not yet probed)
    /// Value read from MMIO offset 0x08: 1=net, 2=blk, 3=console, etc.
    pub virtio_device_id: u32,
    /// PCIe Bus/Device/Function (None for platform devices)
    pub pcie_bdf: Option<(u8, u8, u8)>,
    /// IOMMU stream ID (0 = none, used for PCIe devices)
    pub stream_id: u32,
    /// MSI-X capability info (for PCIe devices)
    pub msix: MsixInfo,
    /// Current state
    pub state: DeviceState,
    /// Index into drivers array if bound, or usize::MAX
    pub driver_idx: usize,
}

impl DeviceEntry {
    /// Create an empty device entry.
    pub const fn empty() -> Self {
        Self {
            path: [0; MAX_PATH_LEN],
            path_len: 0,
            compatible: [0; MAX_COMPAT_LEN],
            compatible_len: 0,
            phys_base: 0,
            size: 0,
            irq: 0,
            virtio_device_id: 0,
            pcie_bdf: None,
            stream_id: 0,
            msix: MsixInfo {
                present: false,
                table_size: 0,
                table_bir: 0,
                table_offset: 0,
                cap_offset: 0,
            },
            state: DeviceState::Unbound,
            driver_idx: usize::MAX,
        }
    }

    /// Get device path as string slice.
    pub fn path_str(&self) -> &str {
        core::str::from_utf8(&self.path[..self.path_len]).unwrap_or("")
    }

    /// Get compatible string as string slice.
    pub fn compatible_str(&self) -> &str {
        core::str::from_utf8(&self.compatible[..self.compatible_len]).unwrap_or("")
    }

    /// Set path from string.
    pub fn set_path(&mut self, path: &str) {
        let bytes = path.as_bytes();
        let len = bytes.len().min(MAX_PATH_LEN);
        self.path[..len].copy_from_slice(&bytes[..len]);
        self.path_len = len;
    }

    /// Set compatible string.
    pub fn set_compatible(&mut self, compat: &str) {
        let bytes = compat.as_bytes();
        let len = bytes.len().min(MAX_COMPAT_LEN);
        self.compatible[..len].copy_from_slice(&bytes[..len]);
        self.compatible_len = len;
    }
}

/// Driver entry in registry
pub struct DriverEntry {
    /// TCB capability slot in device-mgr's CSpace
    pub tcb_slot: u64,
    /// VSpace capability slot
    pub vspace_slot: u64,
    /// CSpace capability slot
    pub cspace_slot: u64,
    /// Driver's service endpoint slot (for minting to clients)
    pub endpoint_slot: u64,
    /// Device indices this driver handles
    pub device_indices: [usize; 4],
    pub device_count: usize,
    /// Whether driver is alive
    pub alive: bool,
    /// Badge used for driver's fault endpoint
    pub fault_badge: u64,
}

impl DriverEntry {
    /// Create an empty driver entry.
    pub const fn empty() -> Self {
        Self {
            tcb_slot: 0,
            vspace_slot: 0,
            cspace_slot: 0,
            endpoint_slot: 0,
            device_indices: [usize::MAX; 4],
            device_count: 0,
            alive: false,
            fault_badge: 0,
        }
    }
}

/// Subscription entry for clients
pub struct Subscription {
    /// Client's notification cap slot (in device-mgr's CSpace)
    pub notification_slot: u64,
    /// Event mask (which events to notify about)
    pub event_mask: u64,
    /// Whether this slot is in use
    pub active: bool,
}

impl Subscription {
    /// Create an empty subscription.
    pub const fn empty() -> Self {
        Self {
            notification_slot: 0,
            event_mask: 0,
            active: false,
        }
    }
}

/// Maximum VirtIO probe frames we keep
pub const MAX_VIRTIO_PROBE_FRAMES: usize = 8;

/// VirtIO probe frame entry - maps physical base address to capability slot
#[derive(Clone, Copy)]
pub struct VirtioProbeFrame {
    /// Physical base address of this 4KB frame
    pub phys_base: u64,
    /// Capability slot in device-mgr's CSpace
    pub slot: u64,
    /// Whether this entry is valid
    pub valid: bool,
}

impl VirtioProbeFrame {
    pub const fn empty() -> Self {
        Self {
            phys_base: 0,
            slot: 0,
            valid: false,
        }
    }
}

/// Device registry
pub struct Registry {
    /// Enumerated devices
    pub devices: [DeviceEntry; MAX_DEVICES],
    pub device_count: usize,
    /// Spawned drivers
    pub drivers: [DriverEntry; MAX_DRIVERS],
    pub driver_count: usize,
    /// Client subscriptions
    pub subscriptions: [Subscription; MAX_SUBSCRIPTIONS],
    /// Next free capability slot for allocations
    pub next_free_slot: u64,
    /// Console endpoint slot (UART driver), for passing to other drivers
    pub console_ep_slot: Option<u64>,
    /// VirtIO probe frames - kept around for reuse when spawning drivers
    pub virtio_probe_frames: [VirtioProbeFrame; MAX_VIRTIO_PROBE_FRAMES],
}

impl Registry {
    /// Create a new registry with the given first free slot.
    pub fn new(first_free_slot: u64) -> Self {
        Self {
            devices: [const { DeviceEntry::empty() }; MAX_DEVICES],
            device_count: 0,
            drivers: [const { DriverEntry::empty() }; MAX_DRIVERS],
            driver_count: 0,
            subscriptions: [const { Subscription::empty() }; MAX_SUBSCRIPTIONS],
            next_free_slot: first_free_slot,
            console_ep_slot: None,
            virtio_probe_frames: [const { VirtioProbeFrame::empty() }; MAX_VIRTIO_PROBE_FRAMES],
        }
    }

    /// Find a VirtIO probe frame that covers the given physical address.
    /// Returns the slot number if found.
    pub fn find_virtio_probe_frame(&self, phys_addr: u64) -> Option<u64> {
        // A 4KB frame covers addresses from phys_base to phys_base + 0xFFF
        for frame in &self.virtio_probe_frames {
            if frame.valid && phys_addr >= frame.phys_base && phys_addr < frame.phys_base + 0x1000 {
                return Some(frame.slot);
            }
        }
        None
    }

    /// Add a VirtIO probe frame to the registry.
    pub fn add_virtio_probe_frame(&mut self, phys_base: u64, slot: u64) -> bool {
        for frame in &mut self.virtio_probe_frames {
            if !frame.valid {
                *frame = VirtioProbeFrame {
                    phys_base,
                    slot,
                    valid: true,
                };
                return true;
            }
        }
        false
    }

    /// Find device by exact path.
    pub fn find_device_by_path(&self, path: &str) -> Option<usize> {
        (0..self.device_count).find(|&i| self.devices[i].path_str() == path)
    }

    /// Find device by compatible string (partial match).
    pub fn find_device_by_compatible(&self, compat: &str) -> Option<usize> {
        (0..self.device_count).find(|&i| self.devices[i].compatible_str().contains(compat))
    }

    /// Find all devices matching a compatible string.
    pub fn find_devices_by_compatible(&self, compat: &str, out: &mut [usize]) -> usize {
        let mut count = 0;
        for i in 0..self.device_count {
            if self.devices[i].compatible_str().contains(compat) && count < out.len() {
                out[count] = i;
                count += 1;
            }
        }
        count
    }

    /// Add a device to the registry.
    pub fn add_device(&mut self, device: DeviceEntry) -> Option<usize> {
        if self.device_count >= MAX_DEVICES {
            return None;
        }
        let idx = self.device_count;
        self.devices[idx] = device;
        self.device_count += 1;
        Some(idx)
    }

    /// Add a driver to the registry.
    pub fn add_driver(&mut self, driver: DriverEntry) -> Option<usize> {
        if self.driver_count >= MAX_DRIVERS {
            return None;
        }
        let idx = self.driver_count;
        self.drivers[idx] = driver;
        self.driver_count += 1;
        Some(idx)
    }

    /// Allocate a capability slot.
    pub fn alloc_slot(&mut self) -> u64 {
        let slot = self.next_free_slot;
        self.next_free_slot += 1;
        slot
    }

    /// Allocate N consecutive capability slots.
    pub fn alloc_slots(&mut self, count: u64) -> u64 {
        let first = self.next_free_slot;
        self.next_free_slot += count;
        first
    }

    /// Mark a driver as dead and update associated devices.
    pub fn mark_driver_dead(&mut self, driver_idx: usize) {
        if driver_idx >= self.driver_count {
            return;
        }

        let driver = &mut self.drivers[driver_idx];
        driver.alive = false;

        // Update all devices handled by this driver
        for i in 0..driver.device_count {
            let dev_idx = driver.device_indices[i];
            if dev_idx < self.device_count {
                self.devices[dev_idx].state = DeviceState::Dead;
            }
        }
    }

    /// Find a free subscription slot.
    pub fn find_free_subscription(&self) -> Option<usize> {
        (0..MAX_SUBSCRIPTIONS).find(|&i| !self.subscriptions[i].active)
    }
}
