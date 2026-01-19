//! Well-known capability slots for device manager
//!
//! These slots define the capability layout for device-mgr.
//! Slots 0-9 follow the standard inherited pattern.
//! Slots 10+ are specific to device-mgr's role.

// -- Inherited from parent (init)

/// Root CNode capability (self-reference)
pub const ROOT_CNODE: u64 = 0;
/// Root TCB capability
pub const ROOT_TCB: u64 = 1;
/// Root VSpace capability
pub const ROOT_VSPACE: u64 = 2;

// -- Provided by init for device-mgr

/// DTB Frame capability - read-only mapped device tree blob
pub const DTB_FRAME: u64 = 10;
/// InitRD Frame capability - read-only TAR archive with drivers
pub const INITRD_FRAME: u64 = 11;
/// Registry endpoint - where device-mgr receives client requests
pub const REGISTRY_EP: u64 = 12;
/// Supervisor notification - for reporting driver deaths
pub const SUPERVISOR_NOTIF: u64 = 13;
/// IRQ control capability (delegated from init)
pub const IRQ_CONTROL: u64 = 14;
/// Untyped memory capability for spawning drivers
pub const RAM_UNTYPED: u64 = 15;
/// ASID pool for driver VSpaces
pub const ASID_POOL: u64 = 16;
/// Notification bound to this TCB for driver fault delivery
pub const FAULT_NOTIF: u64 = 17;
/// SMMU control capability (optional, only if SMMU present)
pub const SMMU_CONTROL: u64 = 18;

/// First device untyped slot
/// Device untyped capabilities are placed starting here
/// Each covers a device MMIO region that can be retyped to DeviceFrame
pub const FIRST_DEVICE_UNTYPED: u64 = 20;

/// Maximum number of device untyped regions
/// RK3588 has 10+ UARTs, 5 PCIe controllers with multiple reg entries, etc.
pub const MAX_DEVICE_UNTYPED: usize = 48;

/// First free slot for dynamic allocation
/// Must be greater than FIRST_DEVICE_UNTYPED + MAX_DEVICE_UNTYPED
pub const FIRST_FREE_SLOT: u64 = 72;

// -- Well-known slots in spawned driver CSpaces

/// Slots granted to spawned drivers
pub mod driver {
    /// Root CNode (self-reference)
    pub const ROOT_CNODE: u64 = 0;
    /// Root TCB
    pub const ROOT_TCB: u64 = 1;
    /// Root VSpace
    pub const ROOT_VSPACE: u64 = 2;

    /// DeviceFrame for MMIO access
    pub const DEVICE_FRAME: u64 = 10;
    /// IRQHandler for interrupt handling (if needed)
    pub const IRQ_HANDLER: u64 = 11;
    /// Service endpoint for clients to connect
    pub const SERVICE_EP: u64 = 12;
    /// IOSpace for DMA (if needed, for PCIe devices)
    pub const IOSPACE: u64 = 13;
    /// Notification for signalling from device-mgr
    pub const NOTIF: u64 = 14;
    /// SMMU control capability (if needed, for DMA-capable drivers)
    pub const SMMU_CONTROL: u64 = 15;
    /// DMA pool for IOVA allocation (if needs_iommu)
    pub const DMA_POOL: u64 = 16;

    /// Console endpoint for IPC-based output (optional)
    /// If present, drivers can use io::init_console() with this slot
    pub const CONSOLE_EP: u64 = 20;

    /// First DMA buffer frame slot (for DMA-capable drivers)
    /// Slots 21-28 contain pre-allocated frames for virtqueue and DMA buffers
    pub const DMA_BUFFER_START: u64 = 21;
    /// Number of DMA buffer frames provided to DMA-capable drivers
    pub const DMA_BUFFER_COUNT: usize = 8;

    /// First MSI-X IRQHandler slot (for PCIe devices with MSI-X)
    /// Slots 40-47 contain IRQHandler caps for MSI-X vectors 0-7
    pub const MSIX_IRQ_START: u64 = 40;
    /// Maximum number of MSI-X vectors we support per driver
    pub const MSIX_MAX_VECTORS: usize = 8;

    /// First free slot for driver's own allocations
    pub const FIRST_FREE_SLOT: u64 = 50;
}
