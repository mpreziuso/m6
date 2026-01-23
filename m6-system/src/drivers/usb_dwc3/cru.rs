//! RK3588 Clock and Reset Unit (CRU) implementation
//!
//! Provides reset control for USB3 controllers and PHYs on RK3588.
//!
//! # RK3588 CRU Addresses
//!
//! - CRU: 0xFD7C0000 (main clock/reset controller)
//! - PHPTOPCRU: 0xFD7E0000 (PHY top clock/reset)
//!
//! # Reset Registers
//!
//! The CRU uses write-enable bits to allow atomic register updates.
//! Upper 16 bits are write mask, lower 16 bits are value.

use crab_usb::CruOp;

/// RK3588 CRU reset register offsets
pub mod regs {
    /// CRU_SOFTRST_CON32 - USB3 controller resets
    pub const SOFTRST_CON32: u32 = 0x0A80;
    /// CRU_SOFTRST_CON33 - USB PHY resets
    pub const SOFTRST_CON33: u32 = 0x0A84;
    /// CRU_SOFTRST_CON34 - Additional USB resets
    pub const SOFTRST_CON34: u32 = 0x0A88;
    /// CRU_SOFTRST_CON35 - PHY USB2 resets
    pub const SOFTRST_CON35: u32 = 0x0A8C;

    /// PHP CRU reset offsets (relative to 0xFD7E0000)
    pub const PHP_SOFTRST_CON00: u32 = 0x0A00;

    // Clock gate registers for USB3 OTG controllers
    /// CLK_GATE_CON38 - USB3OTG0 clock gates
    pub const CLK_GATE_CON38: u32 = 0x0398;
    /// CLK_GATE_CON39 - USB3OTG1 clock gates
    pub const CLK_GATE_CON39: u32 = 0x039C;
    /// CLK_GATE_CON40 - USB3OTG2 and additional USB clocks
    pub const CLK_GATE_CON40: u32 = 0x03A0;
}

/// Reset bit definitions for USB3OTG controllers
#[allow(dead_code)]
pub mod reset_bits {
    // SOFTRST_CON32 bits
    pub const USB3OTG0_RST: u32 = 1 << 0;
    pub const USB3OTG1_RST: u32 = 1 << 1;

    // SOFTRST_CON33 bits
    pub const USB3OTG0_PHY_RST: u32 = 1 << 0;
    pub const USB3OTG1_PHY_RST: u32 = 1 << 1;

    // USBDP PHY resets (in PHPTOPCRU)
    pub const USBDP_PHY0_RST_INIT: u32 = 1 << 0;
    pub const USBDP_PHY0_RST_CMN: u32 = 1 << 1;
    pub const USBDP_PHY0_RST_LANE: u32 = 1 << 2;
    pub const USBDP_PHY0_RST_PCS_APB: u32 = 1 << 3;
    pub const USBDP_PHY0_RST_PMA_APB: u32 = 1 << 4;
}

/// RK3588 CRU driver for USB reset control.
///
/// Provides register-level access to CRU reset controls via mapped MMIO.
/// The CRU base address must be provided after mapping the CRU device frame.
pub struct RK3588Cru {
    /// CRU MMIO base address (virtual address after mapping)
    base: u64,
    /// When true, reset operations are no-ops (firmware already initialised)
    skip_resets: bool,
}

impl RK3588Cru {
    /// Create a new CRU instance with no MMIO mapping.
    ///
    /// The CRU will not perform actual hardware writes until
    /// `set_base` is called with a valid mapped address.
    pub fn new() -> Self {
        Self { base: 0, skip_resets: false }
    }

    /// Create a new CRU instance with a mapped MMIO base address.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` is a valid virtual address
    /// pointing to the CRU registers (mapped via DeviceFrame).
    pub unsafe fn with_base(base: u64) -> Self {
        Self { base, skip_resets: false }
    }

    /// Create a CRU instance that skips all reset operations.
    ///
    /// Use this when firmware has already initialised the hardware and
    /// reset operations would disrupt the working state.
    pub fn skip_resets() -> Self {
        Self { base: 0, skip_resets: true }
    }

    /// Set the CRU MMIO base address.
    ///
    /// # Safety
    ///
    /// The caller must ensure `base` is a valid virtual address
    /// pointing to the CRU registers (mapped via DeviceFrame).
    #[allow(dead_code)]
    pub unsafe fn set_base(&mut self, base: u64) {
        self.base = base;
    }

    /// Check if the CRU has a valid base address.
    #[allow(dead_code)]
    pub fn is_mapped(&self) -> bool {
        self.base != 0
    }

    /// Write to a CRU register with write-enable mask.
    ///
    /// RK3588 CRU uses upper 16 bits as write mask:
    /// - Bits [31:16] = write enable mask
    /// - Bits [15:0] = value to write
    ///
    /// This allows atomic bit manipulation without read-modify-write.
    fn write_reg(&self, offset: u32, mask: u32, value: u32) {
        if self.base == 0 {
            crate::io::puts("[cru] ERROR: CRU not mapped, cannot write\n");
            return;
        }

        let reg_addr = self.base + offset as u64;

        // Combine mask and value: upper 16 bits = mask, lower 16 bits = value
        let write_val = (mask << 16) | (value & mask);

        crate::io::puts("[cru] write_reg: addr=");
        crate::io::put_hex(reg_addr);
        crate::io::puts(" val=");
        crate::io::put_hex(write_val as u64);
        crate::io::newline();

        // SAFETY: Caller has ensured base is valid via with_base() or set_base()
        unsafe {
            core::ptr::write_volatile(reg_addr as *mut u32, write_val);
        }

        // Memory barrier to ensure write completes before continuing
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }

    /// Read from a CRU register.
    #[allow(dead_code)]
    fn read_reg(&self, offset: u32) -> u32 {
        if self.base == 0 {
            crate::io::puts("[cru] ERROR: CRU not mapped, cannot read\n");
            return 0;
        }

        // SAFETY: Caller has ensured base is valid via with_base() or set_base()
        unsafe {
            let reg = (self.base + offset as u64) as *const u32;
            core::ptr::read_volatile(reg)
        }
    }

    /// Enable clocks for USB3OTG controller.
    ///
    /// On RK3588, setting clock gate bits to 0 enables the clock.
    /// This enables all USB-related clocks in CLK_GATE_CON38/39/40.
    ///
    /// # Arguments
    /// * `controller` - Controller index (0, 1, or 2)
    pub fn enable_usb3_clocks(&self, controller: usize) {
        if self.base == 0 {
            crate::io::puts("[cru] Clocks not enabled (CRU not mapped)\n");
            return;
        }

        crate::io::puts("[cru] Enabling USB3 clocks for controller ");
        crate::io::put_u64(controller as u64);
        crate::io::newline();

        // Each controller has clocks spread across CLK_GATE_CON38/39/40
        // For simplicity, enable all USB-related clocks in all three registers
        // by clearing bits 0-15 (setting value to 0 with mask covering all bits)
        //
        // CLK_GATE_CON38: USB3OTG0 clocks (bits 0-6)
        // CLK_GATE_CON39: USB3OTG1 clocks (bits 0-6)
        // CLK_GATE_CON40: USB3OTG2 and additional clocks
        //
        // Write mask=0xFFFF, value=0x0000 to enable all clocks in the register
        let clk_gate_reg = match controller {
            0 => regs::CLK_GATE_CON38,
            1 => regs::CLK_GATE_CON39,
            2 => regs::CLK_GATE_CON40,
            _ => {
                crate::io::puts("[cru] Invalid controller index\n");
                return;
            }
        };

        // Enable clocks: write 0 to clock gate bits (0 = clock enabled)
        // Use mask 0x7F (bits 0-6) which are typically the USB clock gates
        self.write_reg(clk_gate_reg, 0x7F, 0);

        crate::io::puts("[cru] USB3 clocks enabled\n");
    }

    /// Deassert reset for USB3OTG controller to bring it out of reset.
    ///
    /// This should be called after enabling clocks.
    ///
    /// # Arguments
    /// * `controller` - Controller index (0, 1, or 2)
    pub fn deassert_usb3_reset(&self, controller: usize) {
        if self.base == 0 {
            crate::io::puts("[cru] Reset not deasserted (CRU not mapped)\n");
            return;
        }

        crate::io::puts("[cru] Deasserting USB3 reset for controller ");
        crate::io::put_u64(controller as u64);
        crate::io::newline();

        // USB3OTG resets are in SOFTRST_CON32
        // Bit 0 = USB3OTG0, Bit 1 = USB3OTG1
        let bit = match controller {
            0 => 0,
            1 => 1,
            2 => 2, // USB3OTG2 might be in a different register or bit
            _ => {
                crate::io::puts("[cru] Invalid controller index\n");
                return;
            }
        };

        // Deassert reset: write 0 to reset bit (0 = not in reset)
        let mask = 1u32 << bit;
        self.write_reg(regs::SOFTRST_CON32, mask, 0);

        crate::io::puts("[cru] USB3 reset deasserted\n");
    }
}

impl Default for RK3588Cru {
    fn default() -> Self {
        Self::new()
    }
}

impl CruOp for RK3588Cru {
    fn reset_assert(&self, id: u64) {
        // Skip reset operations when firmware has already initialised
        if self.skip_resets {
            return;
        }

        // Map reset IDs to register/bit combinations
        // ID encoding: bits [7:0] = bit position, bits [15:8] = register offset index
        let bit = (id & 0xFF) as u32;
        let reg_idx = ((id >> 8) & 0xFF) as u32;

        // Calculate register offset based on index
        let reg_offset = match reg_idx {
            0 => regs::SOFTRST_CON32,
            1 => regs::SOFTRST_CON33,
            2 => regs::SOFTRST_CON34,
            3 => regs::SOFTRST_CON35,
            _ => {
                crate::io::puts("[cru] ERROR: invalid reset reg_idx=");
                crate::io::put_u64(reg_idx as u64);
                crate::io::newline();
                return;
            }
        };

        crate::io::puts("[cru] reset_assert id=");
        crate::io::put_u64(id);
        crate::io::puts(" reg=0x");
        crate::io::put_hex(reg_offset as u64);
        crate::io::puts(" bit=");
        crate::io::put_u64(bit as u64);
        crate::io::newline();

        // Assert reset: set the bit to 1
        let mask = 1u32 << bit;
        self.write_reg(reg_offset, mask, mask);
    }

    fn reset_deassert(&self, id: u64) {
        // Skip reset operations when firmware has already initialised
        if self.skip_resets {
            return;
        }

        // Map reset IDs to register/bit combinations
        let bit = (id & 0xFF) as u32;
        let reg_idx = ((id >> 8) & 0xFF) as u32;

        // Calculate register offset based on index
        let reg_offset = match reg_idx {
            0 => regs::SOFTRST_CON32,
            1 => regs::SOFTRST_CON33,
            2 => regs::SOFTRST_CON34,
            3 => regs::SOFTRST_CON35,
            _ => {
                crate::io::puts("[cru] ERROR: invalid reset reg_idx=");
                crate::io::put_u64(reg_idx as u64);
                crate::io::newline();
                return;
            }
        };

        crate::io::puts("[cru] reset_deassert id=");
        crate::io::put_u64(id);
        crate::io::puts(" reg=0x");
        crate::io::put_hex(reg_offset as u64);
        crate::io::puts(" bit=");
        crate::io::put_u64(bit as u64);
        crate::io::newline();

        // Deassert reset: set the bit to 0 (mask enables write, value is 0)
        let mask = 1u32 << bit;
        self.write_reg(reg_offset, mask, 0);
    }
}

// SAFETY: CRU is stateless (only writes to hardware registers)
// The base address is thread-local to the driver process.
unsafe impl Send for RK3588Cru {}
unsafe impl Sync for RK3588Cru {}
