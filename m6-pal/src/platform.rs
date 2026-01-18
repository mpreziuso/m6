//! Platform Detection and Abstraction
//!
//! Provides a unified interface for different hardware platforms.

use crate::dtb;
use crate::dtb_platform::{DtbPlatform, SmmuConfig};
use m6_common::boot::BootInfo;
use once_cell_no_std::OnceCell;

pub trait Platform: Send + Sync {
    /// Get the platform name
    fn name(&self) -> &'static str;

    /// Get the peripheral base address
    fn peripheral_base(&self) -> u64;

    /// Get the GIC distributor base address
    fn gic_distributor_base(&self) -> u64;

    /// Get the GIC CPU interface base address (for GICv2)
    fn gic_cpu_base(&self) -> u64;

    /// Get the GIC redistributor base address (for GICv3+)
    fn gic_redistributor_base(&self) -> u64;

    /// Get the GIC version detected from DTB
    fn gic_version(&self) -> crate::dtb_platform::GicVersion;

    /// Get the timer IRQ number
    fn timer_irq(&self) -> u32;

    /// Get the UART base address for early console
    fn uart_base(&self) -> u64;

    /// Get the RAM base address
    fn ram_base(&self) -> u64;

    /// Get the RAM size (or 0 if determined by memory map)
    fn ram_size(&self) -> u64;

    /// Perform early platform initialisation
    fn early_init(&self);

    /// Perform late platform initialisation (after memory management)
    fn late_init(&self);

    /// Get the SMMU base address (None if no SMMU present).
    fn smmu_base(&self) -> Option<u64> {
        None
    }

    /// Get the SMMU configuration (None if no SMMU present).
    fn smmu_config(&self) -> Option<&SmmuConfig> {
        None
    }

    /// Check if IOMMU is available (required for userspace drivers).
    fn has_iommu(&self) -> bool {
        false
    }

    /// Get the number of CPUs detected (None if unknown).
    fn cpu_count(&self) -> Option<u32> {
        None
    }

    /// Get the UART type for early console.
    fn uart_type(&self) -> crate::dtb_platform::UartType {
        crate::dtb_platform::UartType::Unknown
    }

    /// Get the PSCI invocation method (SMC or HVC).
    fn psci_method(&self) -> crate::dtb_platform::PsciMethod {
        crate::dtb_platform::PsciMethod::Hvc
    }
}

pub struct PlatformInfo {
    platform: &'static dyn Platform,
}

impl PlatformInfo {
    fn from_dtb(dtb_platform: DtbPlatform) -> Self {
        // Store DtbPlatform in static storage
        static DTB_PLATFORM_STORAGE: OnceCell<DtbPlatform> = OnceCell::new();

        // Initialise with the DTB platform (ignoring error if already initialised)
        let _ = DTB_PLATFORM_STORAGE.set(dtb_platform);

        // Get the stored reference
        let platform_ref = DTB_PLATFORM_STORAGE.get()
            .expect("DTB platform should be initialised");

        Self {
            platform: platform_ref,
        }
    }

    pub fn platform(&self) -> &'static dyn Platform {
        self.platform
    }
}

static CURRENT_PLATFORM: OnceCell<PlatformInfo> = OnceCell::new();

/// Initialise the platform abstraction layer
///
/// This function parses the Device Tree Blob to dynamically configure the platform.
/// The DTB must be present and valid - if parsing fails, initialisation will panic.
pub fn init(boot_info: &'static BootInfo) {
    // DTB is required - fail if not present
    if boot_info.dtb_address.as_u64() == 0 {
        panic!("No DTB address provided in BootInfo - cannot initialise platform");
    }

    // Parse DTB and create platform configuration
    let dtb_platform = dtb::parse_dtb(boot_info)
        .expect("Failed to parse DTB - cannot initialise platform");

    let info = PlatformInfo::from_dtb(dtb_platform);
    CURRENT_PLATFORM.set(info).ok();

    if let Some(info) = CURRENT_PLATFORM.get() {
        info.platform().early_init();
    }
}

pub fn current_platform() -> Option<&'static dyn Platform> {
    CURRENT_PLATFORM.get().map(|info| info.platform())
}

pub fn platform() -> &'static dyn Platform {
    current_platform().expect("Platform not initialised")
}
