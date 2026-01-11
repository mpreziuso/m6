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

use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, Ordering};

use m6_arch::IrqSpinMutex;
use m6_common::memory::page;
use spin::Once;

use crate::memory::frame::alloc_frames_zeroed;
use crate::memory::translate::phys_to_virt;
use registers::*;

/// Maximum number of SMMUs supported.
const MAX_SMMUS: usize = 4;

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
    #[expect(dead_code)]
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

/// Single SMMU instance state.
pub struct SmmuInstance {
    /// Base virtual address of SMMU registers.
    base: NonNull<u8>,
    /// Physical base address of SMMU registers.
    base_phys: u64,
    /// Physical address of stream table.
    #[expect(dead_code)]
    strtab_phys: u64,
    /// Virtual address of stream table.
    strtab_virt: u64,
    /// Log2 of max stream ID.
    strtab_log2size: u8,
    /// Command queue state.
    cmdq: QueueState,
    /// Event queue state.
    eventq: QueueState,
    /// Whether the SMMU is enabled.
    enabled: bool,
    /// SMMU instance index.
    index: u8,
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

    /// Submit a command to the command queue.
    pub fn submit_cmd(&mut self, cmd: CommandEntry) -> Result<(), SmmuError> {
        let queue_size = 1usize << self.cmdq.log2size;

        // Check for queue full
        // SAFETY: Reading CMDQ_CONS register.
        let cons = unsafe { self.read32(SMMU_CMDQ_CONS) };
        if (self.cmdq.prod.wrapping_sub(cons) as usize) >= queue_size {
            return Err(SmmuError::QueueFull);
        }

        // Write command to queue
        let entry_offset = (self.cmdq.prod as usize % queue_size) * CommandEntry::SIZE;
        let entry_ptr = (self.cmdq.base_virt + entry_offset as u64) as *mut CommandEntry;
        // SAFETY: We own the command queue and the offset is within bounds.
        unsafe { core::ptr::write_volatile(entry_ptr, cmd) };

        // Memory barrier
        core::sync::atomic::fence(Ordering::Release);

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

        // Poll for completion
        for _ in 0..10000 {
            // SAFETY: Reading CMDQ_CONS register.
            let cons = unsafe { self.read32(SMMU_CMDQ_CONS) };
            if cons == self.cmdq.prod {
                return Ok(());
            }
            core::hint::spin_loop();
        }

        Err(SmmuError::Timeout)
    }

    /// Configure a stream table entry.
    pub fn configure_ste(&mut self, stream_id: u32, ste: StreamTableEntry) -> Result<(), SmmuError> {
        let max_streams = 1u32 << self.strtab_log2size;
        if stream_id >= max_streams {
            return Err(SmmuError::InvalidStreamId);
        }

        // Write STE to stream table
        let ste_offset = (stream_id as usize) * StreamTableEntry::SIZE;
        let ste_ptr = (self.strtab_virt + ste_offset as u64) as *mut StreamTableEntry;
        // SAFETY: We own the stream table and the offset is within bounds.
        unsafe { core::ptr::write_volatile(ste_ptr, ste) };

        // Invalidate STE cache
        self.submit_cmd_sync(CommandEntry::cfgi_ste(stream_id, true))
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

    /// Process pending events in the event queue.
    ///
    /// Returns the number of events processed.
    pub fn process_events(&mut self) -> usize {
        let mut processed = 0;
        let queue_size = 1usize << self.eventq.log2size;

        loop {
            // Read hardware producer
            // SAFETY: Reading EVENTQ_PROD register.
            let hw_prod = unsafe { self.read32(SMMU_EVENTQ_PROD) };

            if self.eventq.cons == hw_prod {
                break; // Queue empty
            }

            // Read event entry
            let entry_offset = (self.eventq.cons as usize % queue_size) * EventEntry::SIZE;
            let entry_ptr = (self.eventq.base_virt + entry_offset as u64) as *const EventEntry;
            // SAFETY: We own the event queue and the offset is within bounds.
            let event = unsafe { core::ptr::read_volatile(entry_ptr) };

            // Handle the event
            Self::handle_event(self.index, &event);

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

    /// Handle a single SMMU event.
    fn handle_event(smmu_index: u8, event: &EventEntry) {
        let event_type = event.event_type();
        let stream_id = event.stream_id();
        let address = event.address();

        log::warn!(
            "SMMU{} event: type={:#x} stream={:#x} addr={:#x}",
            smmu_index, event_type, stream_id, address
        );

        if event.is_translation_fault() {
            log::error!(
                "SMMU translation fault: stream={:#x} addr={:#x}",
                stream_id, address
            );
        } else if event.is_permission_fault() {
            log::error!(
                "SMMU permission fault: stream={:#x} addr={:#x}",
                stream_id, address
            );
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

/// Initialise the SMMU subsystem.
///
/// # Safety
///
/// - Must be called once during kernel init
/// - `smmu_phys` must be the physical base address of the SMMU
/// - `smmu_virt` must be a valid kernel-mapped address for the SMMU registers
pub unsafe fn init(smmu_phys: u64, smmu_virt: u64) -> Result<(), SmmuError> {
    let base = NonNull::new(smmu_virt as *mut u8).ok_or(SmmuError::NotAvailable)?;

    // Read identification registers
    // SAFETY: Reading SMMU identification registers.
    let idr0 = unsafe { (base.as_ptr().add(SMMU_IDR0) as *const u32).read_volatile() };
    let idr1 = unsafe { (base.as_ptr().add(SMMU_IDR1) as *const u32).read_volatile() };

    // Verify AArch64 translation table format support
    let ttf = (idr0 >> 2) & 0x3;
    if ttf != 0b10 && ttf != 0b00 {
        log::error!("SMMU does not support AArch64 page tables (TTF={:#x})", ttf);
        return Err(SmmuError::InvalidConfig);
    }

    // Determine stream table size from IDR1.SIDSIZE
    let sid_size = (idr1 & 0x3F) as u8;
    let strtab_log2size = sid_size.min(16); // Cap at 64K streams for sanity

    log::info!(
        "SMMU: IDR0={:#x} IDR1={:#x} SIDsize={} TTF={:#x}",
        idr0, idr1, sid_size, ttf
    );

    // Allocate stream table (linear format)
    let strtab_entries = 1usize << strtab_log2size;
    let strtab_size = strtab_entries * StreamTableEntry::SIZE;
    let strtab_pages = strtab_size.div_ceil(page::SIZE_4K);
    let strtab_phys = alloc_frames_zeroed(strtab_pages).ok_or(SmmuError::AllocFailed)?;
    let strtab_virt = phys_to_virt(strtab_phys);

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

    let mut instance = SmmuInstance {
        base,
        base_phys: smmu_phys,
        strtab_phys,
        strtab_virt,
        strtab_log2size,
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
        index: 0,
    };

    // Configure SMMU registers
    // SAFETY: All register accesses are to the SMMU MMIO region.
    unsafe {
        // Disable SMMU first
        instance.write32(SMMU_CR0, 0);

        // Wait for CR0ACK
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == 0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Configure stream table base (linear format)
        // RA=1 (read-allocate hint)
        instance.write64(SMMU_STRTAB_BASE, strtab_phys | (1 << 62));
        instance.write32(
            SMMU_STRTAB_BASE_CFG,
            strtab_log2size as u32, // LOG2SIZE, FMT=0 (linear)
        );

        // Configure command queue
        let cmdq_log2size = instance.cmdq.log2size as u64;
        instance.write64(SMMU_CMDQ_BASE, cmdq_phys | cmdq_log2size);
        instance.write32(SMMU_CMDQ_PROD, 0);
        instance.write32(SMMU_CMDQ_CONS, 0);

        // Configure event queue
        let eventq_log2size = instance.eventq.log2size as u64;
        instance.write64(SMMU_EVENTQ_BASE, eventq_phys | eventq_log2size);

        // Enable command queue and event queue
        let cr0 = CR0_CMDQEN | CR0_EVENTQEN;
        instance.write32(SMMU_CR0, cr0);

        // Wait for CR0ACK
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == cr0 {
                break;
            }
            core::hint::spin_loop();
        }

        // Disable global bypass (abort transactions to unconfigured streams)
        instance.write32(SMMU_GBPA, GBPA_ABORT | GBPA_UPDATE);

        // Enable SMMU
        let cr0 = cr0 | CR0_SMMUEN;
        instance.write32(SMMU_CR0, cr0);

        // Wait for CR0ACK
        for _ in 0..10000 {
            if instance.read32(SMMU_CR0ACK) == cr0 {
                break;
            }
            core::hint::spin_loop();
        }
    }

    instance.enabled = true;

    // Store instance
    let instances = SmmuInstances {
        instances: [Some(instance), None, None, None],
        count: 1,
    };

    SMMU_INSTANCES.call_once(|| IrqSpinMutex::new(instances));
    SMMU_AVAILABLE.store(true, Ordering::Release);

    log::info!(
        "SMMU initialised: {} streams, cmdq={} entries, eventq={} entries",
        1 << strtab_log2size, CMDQ_ENTRIES, EVENTQ_ENTRIES
    );

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
    if !is_available() {
        return None;
    }

    SMMU_INSTANCES.get().and_then(|instances_lock| {
        let instances = instances_lock.lock();
        instances.instances[0].as_ref().map(|inst| SmmuInfo {
            base_phys: inst.base_phys,
            base_virt: inst.base.as_ptr() as u64,
            max_streams: 1 << inst.strtab_log2size,
            index: inst.index,
        })
    })
}

/// Access SMMU with a closure.
pub fn with_smmu<F, R>(index: u8, f: F) -> Result<R, SmmuError>
where
    F: FnOnce(&mut SmmuInstance) -> R,
{
    let mut guard = SMMU_INSTANCES
        .get()
        .ok_or(SmmuError::NotAvailable)?
        .lock();

    let instance = guard.instances
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
