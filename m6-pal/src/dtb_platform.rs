//! DTB-based platform configuration
//!
//! This module provides a Platform implementation that is dynamically
//! configured from the Device Tree Blob at runtime.

use crate::platform::Platform;

/// GIC version detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GicVersion {
    /// ARM GICv2
    V2,
    /// ARM GICv3+
    V3,
    /// Unknown GIC version
    Unknown,
}

/// UART type detection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UartType {
    /// ARM PL011 UART
    Pl011,
    /// Unknown UART type
    Unknown,
}

/// SMMU (System Memory Management Unit) configuration
#[derive(Debug, Clone, Copy, Default)]
pub struct SmmuConfig {
    /// Physical base address of the SMMU registers.
    pub base_addr: u64,
    /// Size of the SMMU register region.
    pub size: u64,
    /// Event queue interrupt (SPI number, not including offset).
    pub event_irq: u32,
    /// Global error interrupt.
    pub gerror_irq: u32,
    /// Command queue sync interrupt.
    pub cmdq_sync_irq: u32,
}

impl SmmuConfig {
    /// Create a new SMMU configuration.
    #[inline]
    #[must_use]
    pub const fn new(base_addr: u64, size: u64) -> Self {
        Self {
            base_addr,
            size,
            event_irq: 0,
            gerror_irq: 0,
            cmdq_sync_irq: 0,
        }
    }

    /// Check if this configuration is valid.
    #[inline]
    #[must_use]
    pub const fn is_valid(&self) -> bool {
        self.base_addr != 0
    }
}

/// Platform configuration derived from Device Tree Blob
pub struct DtbPlatform {
    pub(crate) name: &'static str,
    pub(crate) gic_distributor_base: u64,
    pub(crate) gic_cpu_base: u64,
    pub(crate) gic_redistributor_base: u64,
    pub(crate) gic_version: GicVersion,
    pub(crate) timer_irq: u32,
    pub(crate) uart_base: u64,
    #[expect(dead_code)]
    pub(crate) uart_type: UartType,
    pub(crate) ram_base: u64,
    pub(crate) ram_size: u64,
    /// SMMU configuration (None if no SMMU detected).
    pub(crate) smmu_config: Option<SmmuConfig>,
    /// Number of CPUs detected.
    pub(crate) cpu_count: u32,
}

impl Platform for DtbPlatform {
    fn name(&self) -> &'static str {
        self.name
    }

    fn peripheral_base(&self) -> u64 {
        // DTB platforms don't have a single peripheral base
        0
    }

    fn gic_distributor_base(&self) -> u64 {
        self.gic_distributor_base
    }

    fn gic_cpu_base(&self) -> u64 {
        self.gic_cpu_base
    }

    fn gic_redistributor_base(&self) -> u64 {
        self.gic_redistributor_base
    }

    fn gic_version(&self) -> GicVersion {
        self.gic_version
    }

    fn timer_irq(&self) -> u32 {
        self.timer_irq
    }

    fn uart_base(&self) -> u64 {
        self.uart_base
    }

    fn ram_base(&self) -> u64 {
        self.ram_base
    }

    fn ram_size(&self) -> u64 {
        self.ram_size
    }

    fn early_init(&self) {
        // DTB platforms don't need special early initialisation
    }

    fn late_init(&self) {
        // DTB platforms don't need special late initialisation
    }

    fn smmu_base(&self) -> Option<u64> {
        self.smmu_config.as_ref().map(|c| c.base_addr)
    }

    fn smmu_config(&self) -> Option<&SmmuConfig> {
        self.smmu_config.as_ref()
    }

    fn has_iommu(&self) -> bool {
        self.smmu_config.as_ref().is_some_and(|c| c.is_valid())
    }

    fn cpu_count(&self) -> Option<u32> {
        if self.cpu_count > 0 {
            Some(self.cpu_count)
        } else {
            None
        }
    }
}
