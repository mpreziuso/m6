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

/// Platform configuration derived from Device Tree Blob
pub struct DtbPlatform {
    pub(crate) name: &'static str,
    pub(crate) gic_distributor_base: u64,
    pub(crate) gic_cpu_base: u64,
    pub(crate) gic_redistributor_base: u64,
    pub(crate) gic_version: GicVersion,
    pub(crate) timer_irq: u32,
    pub(crate) uart_base: u64,
    pub(crate) uart_type: UartType,
    pub(crate) ram_base: u64,
    pub(crate) ram_size: u64,
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
}
