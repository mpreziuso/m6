//! ARM SMMUv3 monitoring driver
//!
//! This userspace driver monitors the SMMU event queue for DMA faults and
//! provides diagnostic services via IPC. The driver is passive - it does
//! not perform stream binding or IOSpace management, which happen via syscalls.
//!
//! The driver receives IRQ notifications when SMMU events occur and processes
//! the event queue to log faults and track statistics.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

#[path = "../../rt.rs"]
mod rt;

mod ipc;

// Re-use io module from parent crate (for early debug output)
#[path = "../../io.rs"]
mod io;

use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{Ordering, fence};

use m6_arch::smmu::{EventEntry, SMMU_EVENTQ_BASE, SMMU_EVENTQ_CONS, SMMU_EVENTQ_PROD};
use m6_syscall::invoke::{IpcRecvResult, irq_ack, irq_set_handler, map_frame, recv, reply_recv};

// Import console functions from io module
use io::{newline, put_hex, put_u64, puts};

/// Driver CNode radix (log2 of number of slots).
/// Drivers get 1024 slots (2^10).
const CNODE_RADIX: u8 = 10;

/// Convert slot number to CPtr.
#[inline]
const fn cptr(slot: u64) -> u64 {
    slot << (64 - CNODE_RADIX)
}

/// Well-known capability slots for drivers (from device manager).
mod slots {
    pub const ROOT_VSPACE: u64 = 2;
    pub const DEVICE_FRAME: u64 = 10;
    pub const IRQ_HANDLER: u64 = 11;
    pub const SERVICE_EP: u64 = 12;
    pub const NOTIF: u64 = 14;
    pub const INSTANCE_INFO: u64 = 37;
}

/// Base SMMU MMIO virtual address (where DeviceFrame is mapped).
/// Each SMMU instance uses an offset: instance_0 = 0x80000000, instance_1 = 0x80100000, etc.
const SMMU_MMIO_VADDR_BASE: u64 = 0x0000_8000_0000;
const SMMU_MMIO_VADDR_OFFSET: u64 = 0x0010_0000; // 1MB per instance

/// Event queue size (must match kernel configuration).
const EVENTQ_SIZE: usize = 1024;

/// IRQ badge for event queue interrupt.
const IRQ_BADGE_EVENT: u64 = 0x1;

/// Driver state tracking faults and statistics.
struct SmmuState {
    /// Base address of SMMU MMIO.
    mmio_base: u64,
    /// Total number of faults observed.
    total_faults: u64,
    /// Number of claimed streams (not tracked by this driver, always 0).
    stream_count: u32,
    /// Most recent fault info.
    last_fault: Option<FaultInfo>,
}

/// Information about a fault event.
#[derive(Clone, Copy)]
struct FaultInfo {
    fault_type: u8,
    stream_id: u32,
}

impl SmmuState {
    /// Create new SMMU state.
    const fn new(mmio_base: u64) -> Self {
        Self {
            mmio_base,
            total_faults: 0,
            stream_count: 0,
            last_fault: None,
        }
    }

    /// Read a 32-bit SMMU register.
    unsafe fn read_reg(&self, offset: usize) -> u32 {
        // SAFETY: Caller ensures offset is valid within SMMU MMIO region.
        unsafe { read_volatile((self.mmio_base + offset as u64) as *const u32) }
    }

    /// Write a 32-bit SMMU register.
    unsafe fn write_reg(&self, offset: usize, value: u32) {
        // SAFETY: Caller ensures offset is valid within SMMU MMIO region.
        unsafe { write_volatile((self.mmio_base + offset as u64) as *mut u32, value) }
    }

    /// Process all pending events from the event queue.
    fn process_events(&mut self) {
        // SAFETY: Reading SMMU event queue registers.
        let prod = unsafe { self.read_reg(SMMU_EVENTQ_PROD) };
        let cons = unsafe { self.read_reg(SMMU_EVENTQ_CONS) };

        if prod == cons {
            // No events to process
            return;
        }

        // Calculate number of entries to process
        let wrap_mask = (EVENTQ_SIZE - 1) as u32;
        let mut current_cons = cons & wrap_mask;
        let prod_idx = prod & wrap_mask;

        let eventq_base = self.mmio_base + SMMU_EVENTQ_BASE as u64;

        while current_cons != prod_idx {
            // Calculate event entry address
            let event_addr = eventq_base + (current_cons as u64 * EventEntry::SIZE as u64);

            // Read event entry
            // SAFETY: event_addr is within the event queue memory region.
            let event = unsafe {
                let ptr = event_addr as *const EventEntry;
                ptr.read_volatile()
            };

            // Process the event
            self.handle_event(&event);

            // Move to next entry
            current_cons = (current_cons + 1) & wrap_mask;
        }

        // Update consumer index
        fence(Ordering::Release);
        // SAFETY: Writing to SMMU event queue consumer register.
        unsafe {
            self.write_reg(SMMU_EVENTQ_CONS, current_cons);
        }
    }

    /// Handle a single event from the queue.
    fn handle_event(&mut self, event: &EventEntry) {
        self.total_faults += 1;

        let fault_type = event.event_type();
        let stream_id = event.stream_id();
        let address = event.address();

        // Store as last fault
        self.last_fault = Some(FaultInfo {
            fault_type,
            stream_id,
        });

        // Log the fault
        puts("[SMMU] Fault: type=");
        put_hex(fault_type as u64);
        puts(" (");
        puts(event.fault_description());
        puts("), stream=");
        put_hex(stream_id as u64);
        puts(", addr=");
        put_hex(address);
        newline();
    }
}

/// Driver entry point.
///
/// # Safety
///
/// This function must only be called once at program startup. It is the entry point
/// for the SMMU driver and assumes the environment has been properly set up by the
/// bootloader with valid capabilities and memory mappings.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    puts("[SMMU] Driver starting\n");

    // Read instance index from INSTANCE_INFO frame to calculate unique virtual address
    const INSTANCE_INFO_VADDR: u64 = 0x0000_7000_0000;

    // Map instance info frame temporarily to read instance index
    match map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(slots::INSTANCE_INFO),
        INSTANCE_INFO_VADDR,
        0b001, // Read-only
        0,
    ) {
        Ok(_) => {}
        Err(e) => {
            puts("[SMMU] Failed to map instance info: ");
            put_u64(e as u64);
            newline();
            panic!("Cannot determine SMMU instance");
        }
    }

    // Read SMMU instance index (0, 1, 2, or 3)
    // SAFETY: Reading from mapped frame at valid address
    let instance_idx = unsafe {
        core::ptr::read_volatile(INSTANCE_INFO_VADDR as *const u64)
    };

    // Calculate unique virtual address for this SMMU instance
    let smmu_mmio_vaddr = SMMU_MMIO_VADDR_BASE + (instance_idx * SMMU_MMIO_VADDR_OFFSET);

    puts("[SMMU] Instance index: ");
    put_u64(instance_idx);
    puts(", using VADDR ");
    put_hex(smmu_mmio_vaddr);
    newline();

    // Map SMMU MMIO region (read-only for monitoring)
    match map_frame(
        cptr(slots::ROOT_VSPACE),
        cptr(slots::DEVICE_FRAME),
        smmu_mmio_vaddr,
        0b001, // Read-only
        0,
    ) {
        Ok(_) => {
            puts("[SMMU] Mapped MMIO at ");
            put_hex(smmu_mmio_vaddr);
            newline();
        }
        Err(e) => {
            puts("[SMMU] Failed to map MMIO: ");
            put_u64(e as u64);
            newline();
            panic!("Cannot continue without MMIO access");
        }
    }

    // Initialise driver state
    let mut state = SmmuState::new(smmu_mmio_vaddr);

    // Set up IRQ handler for event queue interrupt
    match irq_set_handler(
        cptr(slots::IRQ_HANDLER),
        cptr(slots::NOTIF),
        IRQ_BADGE_EVENT,
    ) {
        Ok(_) => {
            puts("[SMMU] IRQ handler configured (badge=");
            put_hex(IRQ_BADGE_EVENT);
            puts(")\n");
        }
        Err(e) => {
            puts("[SMMU] Failed to set up IRQ handler: ");
            put_u64(e as u64);
            newline();
            // Continue anyway - we can still handle IPC requests without IRQ
        }
    }

    puts("[SMMU] Driver ready, entering service loop\n");

    // Enter service loop
    service_loop(&mut state);
}

/// Main service loop - handles both IRQ notifications and IPC requests.
fn service_loop(state: &mut SmmuState) -> ! {
    let mut last_response: u64 = 0;
    let mut first_message = true;

    loop {
        let result = if first_message {
            first_message = false;
            recv(cptr(slots::SERVICE_EP))
        } else {
            reply_recv(cptr(slots::SERVICE_EP), last_response, 0, 0, 0)
        };

        match result {
            Ok(ipc_result) => {
                // Check if this is an IRQ notification
                if ipc_result.badge == IRQ_BADGE_EVENT {
                    // Process event queue
                    state.process_events();

                    // Acknowledge IRQ to re-enable
                    if let Err(e) = irq_ack(cptr(slots::IRQ_HANDLER)) {
                        puts("[SMMU] Failed to ack IRQ: ");
                        put_u64(e as u64);
                        newline();
                    }

                    // Don't send reply for IRQ notification
                    first_message = true;
                } else {
                    // Handle IPC request
                    last_response = handle_request(state, &ipc_result);
                }
            }
            Err(err) => {
                puts("[SMMU] IPC error: ");
                put_u64(err as u64);
                newline();
                last_response = ipc::response::ERR_INVALID_REQUEST;
            }
        }
    }
}

/// Handle an IPC request from a client.
fn handle_request(state: &SmmuState, ipc: &IpcRecvResult) -> u64 {
    match ipc.label {
        ipc::request::HEALTH_CHECK => {
            // Health check - always OK if we're running
            ipc::response::OK
        }

        ipc::request::GET_STREAM_COUNT => {
            // Return stream count (always 0 - we don't track streams)
            state.stream_count as u64
        }

        ipc::request::GET_FAULT_COUNT => {
            // Return total fault count
            state.total_faults
        }

        ipc::request::GET_LAST_FAULT => {
            // Return last fault info
            if let Some(fault) = state.last_fault {
                // Pack fault info into registers
                // x0: fault_type, x1: stream_id, x2: address_low, x3: address_high
                // Note: We can only return via last_response in this simple loop
                // For full info, would need ipc_send with multiple registers
                (fault.fault_type as u64) | ((fault.stream_id as u64) << 32)
            } else {
                ipc::response::ERR_NO_FAULT
            }
        }

        _ => ipc::response::ERR_INVALID_REQUEST,
    }
}

// Panic handler is provided by m6-std
