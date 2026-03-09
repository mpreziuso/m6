//! ARM SMMUv3 driver
//!
//! Provides IOMMU management for DMA isolation of userspace drivers.
//! The SMMU (System Memory Management Unit) translates device addresses
//! to physical addresses, enabling secure DMA operations.
//!
//! # Architecture
//!
//! SMMUv3 uses several key data structures:
//! - **Stream Table**: Maps StreamID to Stream Table Entry (STE)
//! - **Context Descriptor (CD)**: Per-stream translation context
//! - **Command Queue**: Software → hardware commands
//! - **Event Queue**: Hardware → software fault notifications
//!
//! # Security
//!
//! The SMMU is mandatory for userspace drivers. Without it, DMA-capable
//! devices could access arbitrary physical memory, bypassing capability
//! isolation.

pub mod registers;

extern crate alloc;

use alloc::collections::BTreeMap;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use m6_arch::IrqSpinMutex;
use m6_cap::ObjectRef;
use m6_common::memory::page;
use spin::Once;

use crate::memory::frame::{alloc_frames_aligned, alloc_frames_zeroed};
use crate::memory::translate::phys_to_virt;
use registers::*;

/// Maximum number of SMMUs supported.
const MAX_SMMUS: usize = 4;

// -- Direct console hex output helpers (for diagnostics that must be visible)

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

fn put_hex_u8(v: u8) {
    m6_pal::console::putc(HEX_CHARS[(v >> 4) as usize]);
    m6_pal::console::putc(HEX_CHARS[(v & 0xF) as usize]);
}

fn put_hex_u32(v: u32) {
    for i in (0..8).rev() {
        m6_pal::console::putc(HEX_CHARS[((v >> (i * 4)) & 0xF) as usize]);
    }
}

fn put_hex_u64(v: u64) {
    for i in (0..16).rev() {
        m6_pal::console::putc(HEX_CHARS[((v >> (i * 4)) & 0xF) as usize]);
    }
}

/// Command queue size (must be power of 2).
const CMDQ_ENTRIES: usize = 1024;

/// Event queue size (must be power of 2).
const EVENTQ_ENTRIES: usize = 1024;

/// Global SMMU state.
static SMMU_INSTANCES: Once<IrqSpinMutex<SmmuInstances>> = Once::new();

/// Whether any SMMU is available.
static SMMU_AVAILABLE: AtomicBool = AtomicBool::new(false);

/// Collection of SMMU instances.
struct SmmuInstances {
    instances: [Option<SmmuInstance>; MAX_SMMUS],
    count: usize,
}

/// Queue state (command or event).
struct QueueState {
    /// Physical address of queue base.
    #[expect(dead_code)]
    base_phys: u64,
    /// Virtual address of queue base.
    base_virt: u64,
    /// Log2 of queue size in entries.
    log2size: u8,
    /// Producer index.
    prod: u32,
    /// Consumer index.
    cons: u32,
}

// -- Stream Binding Tracking

/// Per-stream binding information for fault delivery.
///
/// This tracks the association between a stream ID and its IOSpace,
/// including the fault handler notification for delivering SMMU
/// events to userspace.
#[derive(Clone, Copy, Debug)]
pub struct StreamBindingEntry {
    /// Physical address of Context Descriptor table for this stream.
    /// Used for cleanup on unbind.
    pub cd_table_phys: u64,
    /// Bound IOSpace reference.
    pub iospace_ref: ObjectRef,
    /// Notification to signal on fault.
    pub fault_notification: ObjectRef,
    /// Badge to OR with fault info when signalling.
    pub fault_badge: u64,
    /// Whether this stream is currently bound.
    pub is_bound: bool,
}

impl Default for StreamBindingEntry {
    fn default() -> Self {
        Self {
            cd_table_phys: 0,
            iospace_ref: ObjectRef::NULL,
            fault_notification: ObjectRef::NULL,
            fault_badge: 0,
            is_bound: false,
        }
    }
}

/// Single SMMU instance state.
pub struct SmmuInstance {
    /// Base virtual address of SMMU registers.
    base: NonNull<u8>,
    /// Physical base address of SMMU registers.
    base_phys: u64,
    /// Physical address of stream table.
    strtab_phys: u64,
    /// Virtual address of stream table.
    strtab_virt: u64,
    /// Log2 of max stream ID.
    strtab_log2size: u8,
    /// Output Address Size from IDR5 (raw 3-bit value, used as IPS in CDs).
    oas: u8,
    /// Command queue state.
    cmdq: QueueState,
    /// Event queue state.
    eventq: QueueState,
    /// Whether the SMMU is enabled.
    enabled: bool,
    /// SMMU instance index.
    index: u8,
    /// Per-stream binding tracking (sparse — only bound streams have entries).
    stream_bindings: BTreeMap<u32, StreamBindingEntry>,
}

// SAFETY: SmmuInstance is only accessed with the SMMU_INSTANCES lock held.
// The NonNull<u8> points to MMIO memory that is valid for the lifetime of the kernel.
unsafe impl Send for SmmuInstance {}
unsafe impl Sync for SmmuInstance {}

impl SmmuInstance {
    /// Read a 32-bit register.
    #[inline]
    unsafe fn read32(&self, offset: usize) -> u32 {
        let ptr = unsafe { self.base.as_ptr().add(offset) as *const u32 };
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write a 32-bit register.
    #[inline]
    unsafe fn write32(&self, offset: usize, value: u32) {
        let ptr = unsafe { self.base.as_ptr().add(offset) as *mut u32 };
        unsafe { core::ptr::write_volatile(ptr, value) }
    }

    /// Read a 64-bit register.
    #[inline]
    #[allow(dead_code)]
    unsafe fn read64(&self, offset: usize) -> u64 {
        let ptr = unsafe { self.base.as_ptr().add(offset) as *const u64 };
        unsafe { core::ptr::read_volatile(ptr) }
    }

    /// Write a 64-bit register.
    #[inline]
    unsafe fn write64(&self, offset: usize, value: u64) {
        let ptr = unsafe { self.base.as_ptr().add(offset) as *mut u64 };
        unsafe { core::ptr::write_volatile(ptr, value) }
    }

    /// Mask for extracting the index+wrap bits from CMDQ_CONS/CMDQ_PROD.
    /// Bits [log2size:0] are valid; bits [31:24] in CONS are CERROR.
    #[inline]
    fn cmdq_idx_mask(&self) -> u32 {
        (1u32 << (self.cmdq.log2size + 1)) - 1
    }

    /// Submit a command to the command queue.
    pub fn submit_cmd(&mut self, cmd: CommandEntry) -> Result<(), SmmuError> {
        let queue_size = 1usize << self.cmdq.log2size;
        let idx_mask = self.cmdq_idx_mask();

        // SAFETY: Reading CMDQ_CONS register.
        let cons_raw = unsafe { self.read32(SMMU_CMDQ_CONS) };

        // Check for CERROR (command error) in bits [31:24]
        let cerror = (cons_raw >> 24) & 0xFF;
        if cerror != 0 {
            log::error!("SMMU #{}: CERROR={} in submit_cmd", self.index, cerror);
            return Err(SmmuError::InvalidConfig);
        }

        // Check for queue full (mask to index+wrap bits only)
        let cons = cons_raw & idx_mask;
        if ((self.cmdq.prod & idx_mask).wrapping_sub(cons) as usize) >= queue_size {
            return Err(SmmuError::QueueFull);
        }

        // Write command to queue
        let entry_offset = (self.cmdq.prod as usize % queue_size) * CommandEntry::SIZE;
        let entry_vaddr = self.cmdq.base_virt + entry_offset as u64;
        let entry_ptr = entry_vaddr as *mut CommandEntry;
        // SAFETY: We own the command queue and the offset is within bounds.
        unsafe { core::ptr::write_volatile(entry_ptr, cmd) };

        // Clean cache to ensure the SMMU (a non-coherent bus master) sees our writes.
        // Without this, the SMMU reads stale data from DRAM → CERROR_ILL.
        m6_arch::cache::cache_clean_range(entry_vaddr, CommandEntry::SIZE);

        // Update producer
        self.cmdq.prod = self.cmdq.prod.wrapping_add(1);
        // SAFETY: Writing CMDQ_PROD register.
        unsafe { self.write32(SMMU_CMDQ_PROD, self.cmdq.prod) };

        Ok(())
    }

    /// Submit a command and wait for completion.
    pub fn submit_cmd_sync(&mut self, cmd: CommandEntry) -> Result<(), SmmuError> {
        self.submit_cmd(cmd)?;
        self.submit_cmd(CommandEntry::cmd_sync())?;

        let expected_cons = self.cmdq.prod;
        let idx_mask = self.cmdq_idx_mask();

        // Poll for completion
        for _ in 0..10000 {
            // SAFETY: Reading CMDQ_CONS register.
            let cons_raw = unsafe { self.read32(SMMU_CMDQ_CONS) };

            // Check for CERROR (bits [31:24])
            let cerror = (cons_raw >> 24) & 0xFF;
            if cerror != 0 {
                log::error!(
                    "SMMU #{}: CERROR={} during cmd_sync (cons={:#x} prod={})",
                    self.index, cerror, cons_raw, self.cmdq.prod
                );
                // Acknowledge error: write cons with CERROR cleared
                let cons_idx = cons_raw & idx_mask;
                // SAFETY: Writing CMDQ_CONS to acknowledge CERROR.
                unsafe { self.write32(SMMU_CMDQ_CONS, cons_idx) };
                // Reset queue state to match hardware
                self.cmdq.prod = cons_idx;
                // SAFETY: Writing CMDQ_PROD to re-sync with hardware.
                unsafe { self.write32(SMMU_CMDQ_PROD, cons_idx) };
                return Err(SmmuError::InvalidConfig);
            }

            if (cons_raw & idx_mask) == (expected_cons & idx_mask) {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        // SAFETY: Reading CMDQ_CONS register for diagnostic.
        let final_cons = unsafe { self.read32(SMMU_CMDQ_CONS) };
        log::warn!(
            "SMMU #{}: cmd_sync timeout - prod={} cons={:#x} (expected cons={})",
            self.index,
            self.cmdq.prod,
            final_cons,
            expected_cons
        );

        Err(SmmuError::Timeout)
    }

    /// Output Address Size from IDR5 (raw 3-bit IPS encoding for CDs).
    #[inline]
    pub fn oas(&self) -> u8 {
        self.oas
    }

    /// Configure a stream table entry.
    pub fn configure_ste(
        &mut self,
        stream_id: u32,
        ste: StreamTableEntry,
    ) -> Result<(), SmmuError> {
        let max_streams = 1u32 << self.strtab_log2size;
        if stream_id >= max_streams {
            return Err(SmmuError::InvalidStreamId);
        }

        // Write STE to stream table
        let ste_offset = (stream_id as usize) * StreamTableEntry::SIZE;
        let ste_vaddr = self.strtab_virt + ste_offset as u64;
        let ste_phys = self.strtab_phys + ste_offset as u64;
        let ste_ptr = ste_vaddr as *mut StreamTableEntry;
        // SAFETY: We own the stream table and the offset is within bounds.
        unsafe { core::ptr::write_volatile(ste_ptr, ste) };

        // Clean cache so the SMMU sees the updated STE in DRAM
        m6_arch::cache::cache_clean_range(ste_vaddr, StreamTableEntry::SIZE);

        // Diagnostic: read back STE from DRAM (after cache invalidate) to verify
        m6_arch::cache::cache_invalidate_range(ste_vaddr, StreamTableEntry::SIZE);
        let readback = unsafe { core::ptr::read_volatile(ste_ptr) };
        m6_pal::console::puts("[SMMU] STE write: sid=0x");
        put_hex_u32(stream_id);
        m6_pal::console::puts(" phys=0x");
        put_hex_u64(ste_phys);
        m6_pal::console::puts(" strtab_base=0x");
        put_hex_u64(self.strtab_phys);
        m6_pal::console::puts("\n[SMMU]   DW0=0x");
        put_hex_u64(readback.dwords[0]);
        m6_pal::console::puts(" DW1=0x");
        put_hex_u64(readback.dwords[1]);
        m6_pal::console::puts("\n[SMMU]   align=");
        let table_size = 1u64 << (self.strtab_log2size as u64 + 6); // entries * 64
        let aligned = (self.strtab_phys & (table_size - 1)) == 0;
        m6_pal::console::puts(if aligned { "OK" } else { "MISALIGNED!" });
        m6_pal::console::puts("\n");

        // Invalidate STE cache
        self.submit_cmd_sync(CommandEntry::cfgi_ste(stream_id))
    }

    /// Invalidate IOTLB entries for an ASID.
    pub fn invalidate_asid(&mut self, asid: u16) -> Result<(), SmmuError> {
        self.submit_cmd_sync(CommandEntry::tlbi_nh_asid(asid))
    }

    /// Invalidate a single IOTLB entry by VA and ASID.
    ///
    /// # Arguments
    /// - `asid`: The IOASID to invalidate
    /// - `iova`: The I/O virtual address to invalidate
    pub fn invalidate_va(&mut self, asid: u16, iova: u64) -> Result<(), SmmuError> {
        // leaf=true since we're invalidating a page mapping
        self.submit_cmd_sync(CommandEntry::tlbi_nh_va(asid, iova, true))
    }

    /// Prefetch an IOVA translation (diagnostic: tests page table walk).
    ///
    /// Submits CMD_PREFETCH_ADDR for the given stream and IOVA. If the
    /// SMMU can't walk the page tables, an event is generated in the
    /// event queue. If the walk succeeds, the entry is silently cached.
    pub fn prefetch_va(
        &mut self,
        stream_id: u32,
        iova: u64,
    ) -> Result<(), SmmuError> {
        self.submit_cmd_sync(CommandEntry::prefetch_addr(stream_id, iova))
    }

    /// Dump SMMU hardware state for diagnostics (output via direct console).
    ///
    /// This reads back live SMMU register state and the STE at the given
    /// stream ID. Output goes directly to the serial console so it is always
    /// visible, even after the userspace console transition.
    pub fn dump_state(&self, stream_id: u32) {
        m6_pal::console::puts("[SMMU] -- Diagnostic dump (SMMU #");
        put_hex_u8(self.index);
        m6_pal::console::puts(") --\n");

        // SAFETY: SMMU MMIO reads are always safe when the base pointer is valid.
        unsafe {
            let cr0 = self.read32(SMMU_CR0);
            let cr0ack = self.read32(SMMU_CR0ACK);
            let gerror = self.read32(SMMU_GERROR);
            let gerrorn = self.read32(SMMU_GERRORN);
            let eventq_prod = self.read32(SMMU_EVENTQ_PROD);
            let eventq_cons = self.read32(SMMU_EVENTQ_CONS);

            m6_pal::console::puts("[SMMU]   CR0=0x");
            put_hex_u32(cr0);
            m6_pal::console::puts(" CR0ACK=0x");
            put_hex_u32(cr0ack);
            m6_pal::console::puts("\n[SMMU]   GERROR=0x");
            put_hex_u32(gerror);
            m6_pal::console::puts(" GERRORN=0x");
            put_hex_u32(gerrorn);
            if gerror != gerrorn {
                m6_pal::console::puts(" ** ACTIVE ERRORS **");
            }
            m6_pal::console::puts("\n[SMMU]   EVENTQ prod=0x");
            put_hex_u32(eventq_prod);
            m6_pal::console::puts(" cons=0x");
            put_hex_u32(eventq_cons);
            m6_pal::console::puts("\n");
        }

        // Dump STE at stream_id
        let max_streams = 1u32 << self.strtab_log2size;
        if stream_id < max_streams {
            let ste_offset = (stream_id as usize) * StreamTableEntry::SIZE;
            let ste_vaddr = self.strtab_virt + ste_offset as u64;

            // Invalidate cache to read what SMMU sees in DRAM
            m6_arch::cache::cache_invalidate_range(ste_vaddr, StreamTableEntry::SIZE);
            let ste = unsafe {
                core::ptr::read_volatile(ste_vaddr as *const StreamTableEntry)
            };

            m6_pal::console::puts("[SMMU]   STE[0x");
            put_hex_u32(stream_id);
            m6_pal::console::puts("]:\n");
            for i in 0..8 {
                m6_pal::console::puts("[SMMU]     DW");
                put_hex_u8(i as u8);
                m6_pal::console::puts("=0x");
                put_hex_u64(ste.dwords[i]);
                m6_pal::console::puts("\n");
            }

            // Decode key fields
            let valid = ste.dwords[0] & 1;
            let config = (ste.dwords[0] >> 1) & 0x7;
            m6_pal::console::puts("[SMMU]     V=");
            put_hex_u8(valid as u8);
            m6_pal::console::puts(" Config=0b");
            put_hex_u8(config as u8);
            m6_pal::console::puts("\n");
        } else {
            m6_pal::console::puts("[SMMU]   SID 0x");
            put_hex_u32(stream_id);
            m6_pal::console::puts(" out of range (max=0x");
            put_hex_u32(max_streams);
            m6_pal::console::puts(")\n");
        }

        m6_pal::console::puts("[SMMU] -- End dump --\n");
    }

    // -- Stream Binding Management

    /// Bind a stream with fault handler configuration.
    ///
    /// # Arguments
    /// - `stream_id`: Stream ID to bind
    /// - `cd_table_phys`: Physical address of CD table for this stream
    /// - `iospace_ref`: IOSpace object reference
    /// - `fault_notif`: Notification to signal on fault (or NULL)
    /// - `fault_badge`: Badge to OR with fault info
    pub fn bind_stream(
        &mut self,
        stream_id: u32,
        cd_table_phys: u64,
        iospace_ref: ObjectRef,
        fault_notif: ObjectRef,
        fault_badge: u64,
    ) -> Result<(), SmmuError> {
        // Validate stream_id fits in the stream table
        if stream_id >= (1u32 << self.strtab_log2size) {
            return Err(SmmuError::InvalidStreamId);
        }

        self.stream_bindings.insert(stream_id, StreamBindingEntry {
            cd_table_phys,
            iospace_ref,
            fault_notification: fault_notif,
            fault_badge,
            is_bound: true,
        });
        Ok(())
    }

    /// Unbind a stream and clear its binding entry.
    pub fn unbind_stream(&mut self, stream_id: u32) -> Result<(), SmmuError> {
        self.stream_bindings
            .remove(&stream_id)
            .ok_or(SmmuError::InvalidStreamId)?;
        Ok(())
    }

    /// Get stream binding info for fault delivery.
    pub fn get_stream_binding(&self, stream_id: u32) -> Option<&StreamBindingEntry> {
        self.stream_bindings
            .get(&stream_id)
            .filter(|e| e.is_bound)
    }

    /// Find any stream ID bound to the given IOSpace.
    pub fn find_stream_for_iospace(&self, iospace_ref: ObjectRef) -> Option<u32> {
        self.stream_bindings
            .iter()
            .find(|(_, e)| e.is_bound && e.iospace_ref == iospace_ref)
            .map(|(&sid, _)| sid)
    }

    /// Prefetch a VA for ALL streams bound to the given IOSpace.
    /// Returns the number of streams tested.
    pub fn prefetch_all_for_iospace(
        &mut self,
        iospace_ref: ObjectRef,
        iova: u64,
    ) -> usize {
        // Collect stream IDs first (can't borrow self mutably during iteration)
        let sids: alloc::vec::Vec<u32> = self.stream_bindings
            .iter()
            .filter(|(_, e)| e.is_bound && e.iospace_ref == iospace_ref)
            .map(|(&sid, _)| sid)
            .collect();
        let count = sids.len();
        for sid in sids {
            log::info!("SMMU prefetch: stream_id={:#x} iova={:#x}", sid, iova);
            if let Err(e) = self.prefetch_va(sid, iova) {
                log::warn!("SMMU prefetch failed for stream {:#x}: {:?}", sid, e);
            }
        }
        count
    }

    /// Configure fault handler for an already-bound stream.
    pub fn set_fault_handler(
        &mut self,
        stream_id: u32,
        fault_notif: ObjectRef,
        fault_badge: u64,
    ) -> Result<(), SmmuError> {
        let entry = self
            .stream_bindings
            .get_mut(&stream_id)
            .ok_or(SmmuError::InvalidStreamId)?;

        if !entry.is_bound {
            return Err(SmmuError::InvalidStreamId);
        }

        entry.fault_notification = fault_notif;
        entry.fault_badge = fault_badge;
        Ok(())
    }

    /// Check and acknowledge GERROR (global errors).
    ///
    /// Returns true if any errors were active.
    pub fn check_gerror(&mut self) -> bool {
        // SAFETY: Reading GERROR/GERRORN registers.
        let gerror = unsafe { self.read32(SMMU_GERROR) };
        let gerrorn = unsafe { self.read32(SMMU_GERRORN) };
        let active = gerror ^ gerrorn;

        if active != 0 {
            use m6_pal::console;
            console::puts("[SMMU");
            put_hex_u8(self.index);
            console::puts("] GERROR active=0x");
            put_hex_u32(active);
            if active & GERROR_CMDQ_ERR != 0 {
                console::puts(" CMDQ_ERR");
            }
            if active & GERROR_EVENTQ_ABT != 0 {
                console::puts(" EVENTQ_ABT");
            }
            if active & GERROR_SFM_ERR != 0 {
                console::puts(" SFM_ERR");
            }
            console::puts("\n");

            // Acknowledge all active errors
            // SAFETY: Writing GERRORN register.
            unsafe { self.write32(SMMU_GERRORN, gerror) };
            true
        } else {
            false
        }
    }

    /// Process pending events in the event queue.
    ///
    /// Returns the number of events processed.
    pub fn process_events(&mut self) -> usize {
        // Check for global errors first
        self.check_gerror();

        let mut processed = 0;
        let queue_size = 1usize << self.eventq.log2size;

        loop {
            // Read hardware producer
            // SAFETY: Reading EVENTQ_PROD register.
            let hw_prod = unsafe { self.read32(SMMU_EVENTQ_PROD) };

            if self.eventq.cons == hw_prod {
                break; // Queue empty
            }

            // Invalidate the event entry from CPU cache before reading.
            // The SMMU is a non-coherent bus master — it writes events to DRAM
            // but the CPU may have a stale cache line for this address.
            let entry_offset = (self.eventq.cons as usize % queue_size) * EventEntry::SIZE;
            let entry_vaddr = self.eventq.base_virt + entry_offset as u64;
            m6_arch::cache::cache_invalidate_range(entry_vaddr, EventEntry::SIZE);

            // Read event entry
            let entry_ptr = entry_vaddr as *const EventEntry;
            // SAFETY: We own the event queue and the offset is within bounds.
            let event = unsafe { core::ptr::read_volatile(entry_ptr) };

            // Handle the event with stream binding context
            Self::handle_event(self.index, &self.stream_bindings, &event);

            // Update consumer
            self.eventq.cons = self.eventq.cons.wrapping_add(1);
            // SAFETY: Writing EVENTQ_CONS register.
            unsafe { self.write32(SMMU_EVENTQ_CONS, self.eventq.cons) };

            processed += 1;

            // Limit processing per call
            if processed >= 64 {
                break;
            }
        }

        processed
    }

    /// Handle a single SMMU event and deliver to userspace if possible.
    ///
    /// # Arguments
    /// - `smmu_index`: SMMU instance index
    /// - `stream_bindings`: Stream binding table for fault delivery
    /// - `event`: Event queue entry
    fn handle_event(smmu_index: u8, stream_bindings: &BTreeMap<u32, StreamBindingEntry>, event: &EventEntry) {
        let event_type = event.event_type();
        let stream_id = event.stream_id();
        let address = event.address();

        // Skip empty/spurious events (type=0x00 with all zeros is a stale entry)
        if event_type == 0 && stream_id == 0 && address == 0 {
            return;
        }

        // Print SMMU events directly to the serial console so they're always
        // visible. After transition_to_userspace_console(), log::* only goes
        // to the ring buffer which is invisible during debugging.
        use m6_pal::console;
        console::puts("[SMMU");
        put_hex_u8(smmu_index);
        console::puts("] event type=0x");
        put_hex_u8(event_type);
        console::puts(" stream=0x");
        put_hex_u32(stream_id);
        console::puts(" addr=0x");
        put_hex_u64(address);
        console::puts("\n");

        // Dump raw DWORDs for detailed debugging
        console::puts("[SMMU");
        put_hex_u8(smmu_index);
        console::puts("]   DW0=0x");
        put_hex_u64(event.dwords[0]);
        console::puts(" DW1=0x");
        put_hex_u64(event.dwords[1]);
        console::puts("\n[SMMU");
        put_hex_u8(smmu_index);
        console::puts("]   DW2=0x");
        put_hex_u64(event.dwords[2]);
        console::puts(" DW3=0x");
        put_hex_u64(event.dwords[3]);
        console::puts("\n");

        // Look up stream binding for fault delivery
        if let Some(binding) = stream_bindings.get(&stream_id)
            && binding.is_bound
            && binding.fault_notification.is_valid()
        {
            // Encode fault info into badge
            // Bits [63:48]: stream_id, Bits [47:40]: event_type
            let fault_info = ((stream_id as u64) << 48) | ((event_type as u64) << 40);
            let combined_badge = binding.fault_badge | fault_info;

            // Signal fault notification
            use crate::ipc::notification::do_signal;
            match do_signal(binding.fault_notification, combined_badge) {
                Ok(()) => return,
                Err(_) => {
                    console::puts("[SMMU] fault delivery failed for stream 0x");
                    put_hex_u32(stream_id);
                    console::puts("\n");
                }
            }
        }

        // No fault handler configured - print detail to console
        if event.is_translation_fault() {
            console::puts("[SMMU] TRANSLATION FAULT: stream=0x");
            put_hex_u32(stream_id);
            console::puts(" addr=0x");
            put_hex_u64(address);
            console::puts("\n");
        } else if event.is_permission_fault() {
            console::puts("[SMMU] PERMISSION FAULT: stream=0x");
            put_hex_u32(stream_id);
            console::puts(" addr=0x");
            put_hex_u64(address);
            console::puts("\n");
        }
    }
}

/// SMMU errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmmuError {
    /// SMMU not detected or not initialised.
    NotAvailable,
    /// Invalid stream ID.
    InvalidStreamId,
    /// Command queue full.
    QueueFull,
    /// Operation timed out.
    Timeout,
    /// Invalid configuration.
    InvalidConfig,
    /// Allocation failed.
    AllocFailed,
}

// -- RK3588 MMU600 clock/reset initialisation

/// RK3588 MMU600 (PCIE) physical base address
const RK3588_MMU600_PCIE_BASE: u64 = 0xFC90_0000;
/// RK3588 MMU600 (PHP) physical base address
const RK3588_MMU600_PHP_BASE: u64 = 0xFCB0_0000;
/// RK3588 CRU (Clock & Reset Unit) physical base address
const RK3588_CRU_BASE: u64 = 0xFD7C_0000;

/// RK3588 PMU (Power Management Unit) physical base address
const RK3588_PMU_BASE: u64 = 0xFD8D_0000;
/// Power gate software control register 1 (bit 5 = pd_php_dwn_sftena)
const PMU_PWR_GATE_SFTCON1_OFFSET: usize = 0x8150;
/// Power gate status register 0 (bit 21 = pd_php_dwn_stat)
const PMU_PWR_GATE_STS0_OFFSET: usize = 0x8180;

/// Parent PHP clock gate register (bits 0,5,7,9 for pclk/aclk php root/biu)
const CRU_GATE_CON32_OFFSET: usize = 0x0880;
/// Parent PHP reset register (bits 5,9 for presetn/aresetn php biu)
const CRU_SOFTRST_CON32_OFFSET: usize = 0x0A80;
/// Clock gate register for MMU600 (bits 7-9)
const CRU_GATE_CON34_OFFSET: usize = 0x0888;
/// Soft reset register for MMU600 (bits 7-9)
const CRU_SOFTRST_CON34_OFFSET: usize = 0x0A88;

/// Initialise RK3588 MMU600 clocks and deassert resets.
///
/// The RK3588 MMU600 (ARM SMMU v3) requires clock and reset configuration
/// via the CRU (Clock & Reset Unit) before the hardware responds to register
/// reads. UEFI may not enable these clocks.
///
/// This function checks if the SMMU address matches RK3588's MMU600 addresses
/// and enables the required clocks if so.
///
/// # CRU Register Format (RK3588)
///
/// RK3588 CRU uses a write-mask mechanism:
/// - Bits [31:16]: Write mask (1 = allow write to corresponding bit in [15:0])
/// - Bits [15:0]: Data value
///
/// To write 0 to bits 7-9 (enabling clocks / deasserting resets):
/// - Set mask bits 23-25 (=7+16, 8+16, 9+16)
/// - Set data bits 7-9 to 0
///
/// # Safety
///
/// Caller must ensure the CRU physical address is valid and can be mapped.
unsafe fn init_rk3588_mmu_clocks(smmu_phys: u64) {
    // Check if this is an RK3588 MMU600
    let is_rk3588_mmu =
        smmu_phys == RK3588_MMU600_PCIE_BASE || smmu_phys == RK3588_MMU600_PHP_BASE;

    if !is_rk3588_mmu {
        return;
    }

    log::info!("RK3588 MMU600 at {:#x}: enabling power domain and clocks", smmu_phys);

    let pmu_virt = phys_to_virt(RK3588_PMU_BASE);
    let cru_virt = phys_to_virt(RK3588_CRU_BASE);

    // Step 0: Enable PD_PHP power domain
    // SAFETY: PMU is mapped via phys_to_virt and read/write is within register bounds
    unsafe {
        let pwr_sts_ptr = (pmu_virt + PMU_PWR_GATE_STS0_OFFSET as u64) as *const u32;
        let pwr_ctl_ptr = (pmu_virt + PMU_PWR_GATE_SFTCON1_OFFSET as u64) as *mut u32;

        let pwr_sts = core::ptr::read_volatile(pwr_sts_ptr);
        let php_powered_down = (pwr_sts >> 21) & 1 != 0;

        if php_powered_down {
            // Write enable bit 21 (5+16), data bit 5 = 0
            let pwr_on_value: u32 = 1 << 21;
            core::ptr::write_volatile(pwr_ctl_ptr, pwr_on_value);

            core::sync::atomic::fence(Ordering::SeqCst);
            for _ in 0..100000 {
                core::hint::spin_loop();
            }

            let pwr_sts_after = core::ptr::read_volatile(pwr_sts_ptr);
            if (pwr_sts_after >> 21) & 1 != 0 {
                log::warn!("PD_PHP power domain failed to power on!");
            }
        }
    }

    // SAFETY: CRU is mapped via phys_to_virt and read/write is within register bounds
    unsafe {
        // Step 1: Enable parent PHP clocks (bits 0,5,7,9 of CRU_GATE_CON32)
        let gate32_ptr = (cru_virt + CRU_GATE_CON32_OFFSET as u64) as *mut u32;
        let reset32_ptr = (cru_virt + CRU_SOFTRST_CON32_OFFSET as u64) as *mut u32;

        let php_gate_mask: u32 = (1 << 16) | (1 << 21) | (1 << 23) | (1 << 25);
        core::ptr::write_volatile(gate32_ptr, php_gate_mask);

        // Step 2: Deassert parent PHP resets (bits 5,9 of CRU_SOFTRST_CON32)
        let php_reset_mask: u32 = (1 << 21) | (1 << 25);
        core::ptr::write_volatile(reset32_ptr, php_reset_mask);

        core::sync::atomic::fence(Ordering::SeqCst);
        for _ in 0..1000 {
            core::hint::spin_loop();
        }

        // Step 3: Enable MMU600 clocks (bits 7-9 of CRU_GATE_CON34)
        let gate34_ptr = (cru_virt + CRU_GATE_CON34_OFFSET as u64) as *mut u32;
        let reset34_ptr = (cru_virt + CRU_SOFTRST_CON34_OFFSET as u64) as *mut u32;

        let mmu_gate_mask: u32 = 0x0380_0000;
        core::ptr::write_volatile(gate34_ptr, mmu_gate_mask);

        // Step 4: Deassert MMU600 resets (bits 7-9 of CRU_SOFTRST_CON34)
        let mmu_reset_mask: u32 = 0x0380_0000;
        core::ptr::write_volatile(reset34_ptr, mmu_reset_mask);

        core::sync::atomic::fence(Ordering::SeqCst);
        for _ in 0..10000 {
            core::hint::spin_loop();
        }
    }
}

/// Initialise an SMMU instance.
///
/// # Safety
///
/// - Must be called during kernel init
/// - `smmu_phys` must be the physical base address of the SMMU
/// - `smmu_virt` must be a valid kernel-mapped address for the SMMU registers
/// - `index` must be a valid SMMU index (0-3)
pub unsafe fn init(
    smmu_phys: u64,
    smmu_virt: u64,
    index: u8,
) -> Result<(), SmmuError> {
    if index as usize >= MAX_SMMUS {
        return Err(SmmuError::InvalidConfig);
    }

    // RK3588: Enable MMU600 clocks and deassert resets before accessing registers
    // This must be done before any register access as the hardware won't respond
    // without proper clock/reset configuration.
    // SAFETY: Called during kernel init, CRU registers are accessible via phys_to_virt
    unsafe { init_rk3588_mmu_clocks(smmu_phys) };

    let base = NonNull::new(smmu_virt as *mut u8).ok_or(SmmuError::NotAvailable)?;

    // Read identification registers
    // SAFETY: Reading SMMU identification registers.
    let idr0 = unsafe { (base.as_ptr().add(SMMU_IDR0) as *const u32).read_volatile() };
    let idr1 = unsafe { (base.as_ptr().add(SMMU_IDR1) as *const u32).read_volatile() };
    let idr5 = unsafe { (base.as_ptr().add(SMMU_IDR5) as *const u32).read_volatile() };

    // Check if SMMU hardware is responding
    // Reading 0xffffffff typically means the hardware is not clocked/powered
    if idr0 == 0xffffffff || idr1 == 0xffffffff {
        log::warn!(
            "SMMU #{} at {:#x}: hardware not responding (IDR0={:#x} IDR1={:#x})",
            index, smmu_phys, idr0, idr1
        );
        log::warn!("SMMU #{}: clocks may not be enabled - skipping initialization", index);
        // Mark SMMU as not available by not storing an instance
        return Err(SmmuError::NotAvailable);
    }

    // Log detailed SMMU capabilities
    let ttf = (idr0 >> 2) & 0x3;
    let cohacc = (idr0 >> 4) & 0x1;
    let oas = idr5 & 0x7;
    let oas_bits = match oas {
        0 => 32,
        1 => 36,
        2 => 40,
        3 => 42,
        4 => 44,
        5 => 48,
        6 => 52,
        _ => 0,
    };
    log::info!(
        "SMMU capabilities: IDR0={:#010x} IDR5={:#010x} TTF={} COHACC={} OAS={}bit",
        idr0,
        idr5,
        ttf,
        cohacc,
        oas_bits
    );

    // Verify AArch64 translation table format support
    // TTF encoding: 0b00=reserved, 0b01=AArch32 only, 0b10=AArch64 only, 0b11=both
    let supports_aarch64 = ttf == 0b10 || ttf == 0b11;
    if !supports_aarch64 {
        log::error!("SMMU does not support AArch64 page tables (TTF={})", ttf);
        return Err(SmmuError::InvalidConfig);
    }

    // Determine stream table size from IDR1.SIDSIZE
    // Cap at 17 (128K entries = 8MB). On RK3588, each PCIe controller has
    // a unique stream_base (0x0, 0x1000, 0x2000, ...) so pcie2x1l2
    // needs stream IDs up to ~0x5000 requiring log2size >= 15.
    // We cap at 17 (128K entries) for headroom. For SIDSIZE>17,
    // implement 2-level stream tables.
    let sid_size = (idr1 & 0x3F) as u8;
    let strtab_log2size = sid_size.min(17);
    if sid_size > 17 {
        log::warn!(
            "SMMU #{}: SIDSIZE={} but linear stream table capped at 17 (8MB). \
             Streams > 0x1FFFF will GBPA-abort.",
            index, sid_size
        );
    }

    log::info!(
        "SMMU: IDR0={:#x} IDR1={:#x} SIDsize={} TTF={:#x}",
        idr0,
        idr1,
        sid_size,
        ttf
    );

    // Allocate stream table (linear format)
    // ARM IHI 0070: STRTAB_BASE.ADDR must be aligned to the larger of 64 bytes
    // and the total table size. For LOG2SIZE=17, table = 8MB → need 8MB alignment.
    let strtab_entries = 1usize << strtab_log2size;
    let strtab_size = strtab_entries * StreamTableEntry::SIZE;
    let strtab_pages = strtab_size.div_ceil(page::SIZE_4K);
    let strtab_align_pages = strtab_pages.max(1); // alignment in pages
    let strtab_phys =
        alloc_frames_aligned(strtab_pages, strtab_align_pages)
            .ok_or(SmmuError::AllocFailed)?;
    let strtab_virt = phys_to_virt(strtab_phys);

    // Diagnostic: log stream table address and alignment
    m6_pal::console::puts("[SMMU] Stream table: phys=0x");
    put_hex_u64(strtab_phys as u64);
    m6_pal::console::puts(" size=0x");
    put_hex_u64(strtab_size as u64);
    m6_pal::console::puts(" align=");
    let strtab_aligned = (strtab_phys & (strtab_size as u64 - 1)) == 0;
    m6_pal::console::puts(if strtab_aligned { "OK\n" } else { "MISALIGNED!\n" });

    // Allocate command queue
    let cmdq_size = CMDQ_ENTRIES * CommandEntry::SIZE;
    let cmdq_pages = cmdq_size.div_ceil(page::SIZE_4K);
    let cmdq_phys = alloc_frames_zeroed(cmdq_pages).ok_or(SmmuError::AllocFailed)?;
    let cmdq_virt = phys_to_virt(cmdq_phys);

    // Allocate event queue
    let eventq_size = EVENTQ_ENTRIES * EventEntry::SIZE;
    let eventq_pages = eventq_size.div_ceil(page::SIZE_4K);
    let eventq_phys = alloc_frames_zeroed(eventq_pages).ok_or(SmmuError::AllocFailed)?;
    let eventq_virt = phys_to_virt(eventq_phys);

    // Flush zeroed allocations to DRAM so the SMMU (non-coherent bus master) sees zeros.
    // Without this, the SMMU reads stale DRAM content instead of the zeroed data.
    m6_arch::cache::cache_clean_range(strtab_virt, strtab_size);
    m6_arch::cache::cache_clean_range(cmdq_virt, cmdq_size);
    m6_arch::cache::cache_clean_range(eventq_virt, eventq_size);

    // Stream bindings are sparse — entries created on bind_stream only
    let stream_bindings = BTreeMap::new();

    let mut instance = SmmuInstance {
        base,
        base_phys: smmu_phys,
        strtab_phys,
        strtab_virt,
        strtab_log2size,
        oas: oas as u8,
        cmdq: QueueState {
            base_phys: cmdq_phys,
            base_virt: cmdq_virt,
            log2size: CMDQ_ENTRIES.trailing_zeros() as u8,
            prod: 0,
            cons: 0,
        },
        eventq: QueueState {
            base_phys: eventq_phys,
            base_virt: eventq_virt,
            log2size: EVENTQ_ENTRIES.trailing_zeros() as u8,
            prod: 0,
            cons: 0,
        },
        enabled: false,
        index,
        stream_bindings,
    };

    // Configure SMMU registers
    // SAFETY: All register accesses are to the SMMU MMIO region.
    unsafe {
        // Disable SMMU first
        instance.write32(SMMU_CR0, 0);

        // Wait for CR0ACK
        let mut cr0ack_ok = false;
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == 0 {
                cr0ack_ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !cr0ack_ok {
            let ack = instance.read32(SMMU_CR0ACK);
            log::warn!("SMMU #{}: CR0ACK timeout on disable (expected 0, got {:#x})", index, ack);
        }

        // Configure stream table base (linear format)
        // RA=1 (read-allocate hint)
        let strtab_base_val = strtab_phys | (1 << 62);
        instance.write64(SMMU_STRTAB_BASE, strtab_base_val);
        instance.write32(
            SMMU_STRTAB_BASE_CFG,
            strtab_log2size as u32, // LOG2SIZE, FMT=0 (linear)
        );

        // Read back STRTAB_BASE and CFG to verify the register writes took effect
        let rb_base = instance.read64(SMMU_STRTAB_BASE);
        let rb_cfg = instance.read32(SMMU_STRTAB_BASE_CFG);
        m6_pal::console::puts("[SMMU] STRTAB_BASE wrote=0x");
        put_hex_u64(strtab_base_val);
        m6_pal::console::puts(" readback=0x");
        put_hex_u64(rb_base);
        m6_pal::console::puts("\n[SMMU] STRTAB_BASE_CFG wrote=0x");
        put_hex_u32(strtab_log2size as u32);
        m6_pal::console::puts(" readback=0x");
        put_hex_u32(rb_cfg);
        m6_pal::console::puts("\n");

        // Configure command queue
        let cmdq_log2size = instance.cmdq.log2size as u64;
        instance.write64(SMMU_CMDQ_BASE, cmdq_phys | cmdq_log2size);
        instance.write32(SMMU_CMDQ_PROD, 0);
        instance.write32(SMMU_CMDQ_CONS, 0);

        // Configure event queue base. Do NOT sync CONS yet — EVENTQ_PROD is
        // IMPLEMENTATION DEFINED while SMMUEN=0 (reads may return stale values).
        // We sync CONS after SMMU enable when EVENTQ_PROD has a defined value.
        let eventq_log2size = instance.eventq.log2size as u64;
        instance.write64(SMMU_EVENTQ_BASE, eventq_phys | eventq_log2size);

        // Enable command queue and event queue
        let cr0 = CR0_CMDQEN | CR0_EVENTQEN;
        instance.write32(SMMU_CR0, cr0);

        // Wait for CR0ACK
        cr0ack_ok = false;
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == cr0 {
                cr0ack_ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !cr0ack_ok {
            let ack = instance.read32(SMMU_CR0ACK);
            log::warn!("SMMU #{}: CR0ACK timeout on queue enable (expected {:#x}, got {:#x})", index, cr0, ack);
        }

        // Disable global bypass (abort transactions to unconfigured streams)
        instance.write32(SMMU_GBPA, GBPA_ABORT | GBPA_UPDATE);

        // Verify GBPA was accepted (UPDATE bit should self-clear)
        for _ in 0..10000 {
            let gbpa_rb = instance.read32(SMMU_GBPA);
            if gbpa_rb & GBPA_UPDATE == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Enable SMMU
        let cr0 = cr0 | CR0_SMMUEN;
        instance.write32(SMMU_CR0, cr0);

        // Wait for CR0ACK
        cr0ack_ok = false;
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == cr0 {
                cr0ack_ok = true;
                break;
            }
            core::hint::spin_loop();
        }

        // Diagnostic: print final SMMU state after enable
        let final_cr0 = instance.read32(SMMU_CR0);
        let final_cr0ack = instance.read32(SMMU_CR0ACK);
        let final_gbpa = instance.read32(SMMU_GBPA);
        let final_gerror = instance.read32(SMMU_GERROR);
        m6_pal::console::puts("[SMMU] Enabled: CR0=0x");
        put_hex_u32(final_cr0);
        m6_pal::console::puts(" CR0ACK=0x");
        put_hex_u32(final_cr0ack);
        m6_pal::console::puts(" GBPA=0x");
        put_hex_u32(final_gbpa);
        m6_pal::console::puts(" GERROR=0x");
        put_hex_u32(final_gerror);
        m6_pal::console::puts("\n");

        if !cr0ack_ok {
            log::warn!("SMMU #{}: CR0ACK timeout on SMMU enable (expected {:#x}, got {:#x})", index, cr0, final_cr0ack);
        } else {
            log::info!("SMMU #{}: enabled (CR0={:#x} CR0ACK={:#x})", index, cr0, final_cr0ack);
        }

        // Now that SMMUEN=1, EVENTQ_PROD has a defined value. Sync CONS to
        // it so the kernel and hardware agree the queue is empty.
        let hw_eventq_prod = instance.read32(SMMU_EVENTQ_PROD);
        instance.write32(SMMU_EVENTQ_CONS, hw_eventq_prod);
        instance.eventq.prod = hw_eventq_prod;
        instance.eventq.cons = hw_eventq_prod;

        // Enable event queue and global error IRQs in the SMMU hardware.
        // Without this, the SMMU never asserts the event IRQ line even though
        // the GIC handler is registered — faults silently pile up in the queue.
        let irq_ctrl = IRQ_CTRL_EVENTQ_IRQEN | IRQ_CTRL_GERROR_IRQEN;
        instance.write32(SMMU_IRQ_CTRL, irq_ctrl);

        // Wait for IRQ_CTRLACK
        let mut irq_ack_ok = false;
        for _ in 0..10000 {
            if instance.read32(SMMU_IRQ_CTRLACK) == irq_ctrl {
                irq_ack_ok = true;
                break;
            }
            core::hint::spin_loop();
        }
        if !irq_ack_ok {
            let ack = instance.read32(SMMU_IRQ_CTRLACK);
            log::warn!("SMMU #{}: IRQ_CTRLACK timeout (expected {:#x}, got {:#x})", index, irq_ctrl, ack);
        }

        // Check GERROR for any pre-existing errors
        let gerror = instance.read32(SMMU_GERROR);
        let gerrorn = instance.read32(SMMU_GERRORN);
        if gerror != gerrorn {
            log::warn!("SMMU #{}: GERROR={:#x} GERRORN={:#x} (active errors)", index, gerror, gerrorn);
            // Acknowledge all errors
            instance.write32(SMMU_GERRORN, gerror);
        }
    }

    instance.enabled = true;

    // Initialize SMMU_INSTANCES on first call
    if SMMU_INSTANCES.get().is_none() {
        let instances = SmmuInstances {
            instances: [None, None, None, None],
            count: 0,
        };
        SMMU_INSTANCES.call_once(|| IrqSpinMutex::new(instances));
    }

    // Store instance in the appropriate slot
    if let Some(instances_lock) = SMMU_INSTANCES.get() {
        let mut instances = instances_lock.lock();
        if instances.instances[index as usize].is_some() {
            return Err(SmmuError::InvalidConfig); // Already initialised
        }
        instances.instances[index as usize] = Some(instance);
        instances.count += 1;

        log::info!(
            "SMMU #{} initialised @ {:#x}: {} streams, cmdq={} entries, eventq={} entries",
            index,
            smmu_phys,
            1 << strtab_log2size,
            CMDQ_ENTRIES,
            EVENTQ_ENTRIES
        );
    }

    SMMU_AVAILABLE.store(true, Ordering::Release);

    Ok(())
}

/// Check if SMMU is available.
#[inline]
pub fn is_available() -> bool {
    SMMU_AVAILABLE.load(Ordering::Acquire)
}

/// Information about an initialized SMMU for capability creation.
pub struct SmmuInfo {
    /// Physical base address of SMMU registers.
    pub base_phys: u64,
    /// Virtual base address of SMMU registers (kernel-mapped).
    pub base_virt: u64,
    /// Maximum number of stream IDs supported.
    pub max_streams: u32,
    /// SMMU instance index (0 for first SMMU).
    pub index: u8,
}

/// Get information about the first SMMU instance.
///
/// Returns None if no SMMU is initialized.
pub fn get_smmu_info() -> Option<SmmuInfo> {
    get_smmu_info_by_index(0)
}

/// Get information about a specific SMMU instance by index.
///
/// Returns None if no SMMU at that index is initialized.
pub fn get_smmu_info_by_index(index: u8) -> Option<SmmuInfo> {
    if !is_available() {
        return None;
    }

    SMMU_INSTANCES.get().and_then(|instances_lock| {
        let instances = instances_lock.lock();
        instances.instances.get(index as usize)
            .and_then(|opt| opt.as_ref())
            .map(|inst| SmmuInfo {
                base_phys: inst.base_phys,
                base_virt: inst.base.as_ptr() as u64,
                max_streams: 1 << inst.strtab_log2size,
                index: inst.index,
            })
    })
}

/// Get count of initialized SMMU instances.
pub fn get_smmu_count() -> usize {
    if !is_available() {
        return 0;
    }

    SMMU_INSTANCES.get().map_or(0, |instances_lock| {
        let instances = instances_lock.lock();
        instances.count
    })
}

/// Access SMMU with a closure.
pub fn with_smmu<F, R>(index: u8, f: F) -> Result<R, SmmuError>
where
    F: FnOnce(&mut SmmuInstance) -> R,
{
    let mut guard = SMMU_INSTANCES.get().ok_or(SmmuError::NotAvailable)?.lock();

    let instance = guard
        .instances
        .get_mut(index as usize)
        .and_then(|opt| opt.as_mut())
        .ok_or(SmmuError::NotAvailable)?;

    Ok(f(instance))
}

/// Process events from the specified SMMU.
///
/// Returns the number of events processed.
pub fn process_events(smmu_index: u8) -> usize {
    with_smmu(smmu_index, |smmu| smmu.process_events()).unwrap_or(0)
}
