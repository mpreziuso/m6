//! M6 Init Process
//!
//! The initial userspace process that receives all system capabilities
//! from the kernel and bootstraps the rest of the system.

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]

mod elf;
mod io;
pub mod process;

use core::panic::PanicInfo;
use m6_syscall::{
    invoke::sched_yield,
    UserBootInfo, USER_BOOT_INFO_ADDR, USER_BOOT_INFO_MAGIC, USER_BOOT_INFO_VERSION,
};
use process::{slots, SpawnConfig, InitialCap};

/// First free slot for dynamic allocation
const FIRST_FREE_SLOT: u64 = 64;

/// Entry point - called by kernel with UserBootInfo address in x0.
///
/// # Safety
///
/// This function must be called only once as the entry point, with a valid
/// UserBootInfo pointer passed in x0.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start() -> ! {
    // The kernel passes UserBootInfo address in x0
    // We use a fixed address since the kernel maps it there
    let boot_info = unsafe { &*(USER_BOOT_INFO_ADDR as *const UserBootInfo) };

    // Validate boot info
    if boot_info.magic != USER_BOOT_INFO_MAGIC {
        io::puts("[init] ERROR: Invalid boot info magic!\n");
        loop {
            sched_yield();
        }
    }

    if boot_info.version != USER_BOOT_INFO_VERSION {
        io::puts("[init] ERROR: Boot info version mismatch!\n");
        loop {
            sched_yield();
        }
    }

    // Print banner
    io::puts("\n");
    io::puts("\x1b[32m"); // Green
    io::puts("[init] M6 Init starting\n");
    io::puts("\x1b[0m");  // Reset

    // Print platform info
    io::puts("[init] Platform ID: ");
    io::put_u64(boot_info.platform_id as u64);
    match boot_info.platform_id {
        1 => io::puts(" (QEMU ARM Virtual Machine)"),
        2 => io::puts(" (Radxa Rock 5B+)"),
        _ => io::puts(" (Unknown)"),
    }
    io::newline();

    // Print memory info
    io::puts("[init] Memory: ");
    io::put_u64(boot_info.free_memory / (1024 * 1024));
    io::puts(" MiB free / ");
    io::put_u64(boot_info.total_memory / (1024 * 1024));
    io::puts(" MiB total\n");

    // Print CPU info
    io::puts("[init] CPUs: ");
    io::put_u64(boot_info.cpu_count as u64);
    io::newline();

    // Print CNode info
    io::puts("[init] CNode radix: ");
    io::put_u64(boot_info.cnode_radix as u64);
    io::puts(" (");
    io::put_u64(1 << boot_info.cnode_radix);
    io::puts(" slots)\n");

    // Print untyped info
    if boot_info.untyped_count > 0 {
        io::puts("[init] Untyped regions: ");
        io::put_u64(boot_info.untyped_count as u64);
        io::puts(", first at ");
        io::put_hex(boot_info.untyped_phys_base[0]);
        io::puts(" (");
        io::put_u64(1u64 << boot_info.untyped_size_bits[0]);
        io::puts(" bytes)\n");
    }

    // Print DTB info
    if boot_info.has_dtb() {
        io::puts("[init] DTB mapped at ");
        io::put_hex(boot_info.dtb_vaddr);
        io::puts(" (");
        io::put_u64(boot_info.dtb_size);
        io::puts(" bytes)\n");
    }

    // Print initrd info
    if boot_info.has_initrd() {
        io::puts("[init] Initrd mapped at ");
        io::put_hex(boot_info.initrd_vaddr);
        io::puts(" (");
        io::put_u64(boot_info.initrd_size);
        io::puts(" bytes)\n");

        // List initrd contents
        list_initrd(boot_info);
    }

    // Spawn device-mgr
    if boot_info.has_initrd() && boot_info.untyped_count > 0 {
        spawn_device_mgr(boot_info);
    } else {
        io::puts("[init] Cannot spawn device-mgr: missing initrd or untyped memory\n");
    }

    io::puts("[init] Complete\n");

    // Init has nothing more to do
    // In a real system, init would block on a notification waiting for shutdown/reboot signals
    // For now, we just yield forever to let the idle task run
    loop {
        sched_yield();
    }
}

/// List files in the initrd TAR archive.
fn list_initrd(boot_info: &UserBootInfo) {
    // SAFETY: Kernel guarantees initrd is mapped at this address
    let initrd = unsafe {
        core::slice::from_raw_parts(
            boot_info.initrd_vaddr as *const u8,
            boot_info.initrd_size as usize,
        )
    };

    let archive = match tar_no_std::TarArchiveRef::new(initrd) {
        Ok(a) => a,
        Err(_) => {
            io::puts("[init] Failed to parse initrd TAR\n");
            return;
        }
    };

    io::puts("[init] Initrd contents:\n");
    for entry in archive.entries() {
        if let Ok(name) = entry.filename().as_str() {
            io::puts("  - ");
            io::puts(name);
            io::puts(" (");
            io::put_u64(entry.size() as u64);
            io::puts(" bytes)\n");
        }
    }
}

/// Find a file in the initrd and return its data.
fn find_in_initrd<'a>(boot_info: &UserBootInfo, name: &str) -> Option<&'a [u8]> {
    // SAFETY: Kernel guarantees initrd is mapped at this address
    let initrd = unsafe {
        core::slice::from_raw_parts(
            boot_info.initrd_vaddr as *const u8,
            boot_info.initrd_size as usize,
        )
    };

    let archive = tar_no_std::TarArchiveRef::new(initrd).ok()?;

    for entry in archive.entries() {
        if entry.filename().as_str() == Ok(name) {
            return Some(entry.data());
        }
    }
    None
}

/// DevMgrBootInfo magic and version (must match device_mgr/boot_info.rs)
const DEV_MGR_BOOT_INFO_MAGIC: u64 = 0x54_4F_4F_42_4D_56_45_44;
const DEV_MGR_BOOT_INFO_VERSION: u32 = 1;

/// Addresses where we map data into device-mgr's VSpace
const DEVMGR_BOOT_INFO_ADDR: u64 = 0x0000_1000_0000; // 256MB mark
const DEVMGR_DTB_ADDR: u64 = 0x0000_1001_0000;       // Just after boot info
const DEVMGR_INITRD_ADDR: u64 = 0x0000_2000_0000;    // 512MB mark

/// Maximum number of device untyped regions to pass to device-mgr
const MAX_DEVICE_UNTYPED: usize = 8;

/// First device untyped slot in device-mgr's CSpace
const DEVMGR_FIRST_DEVICE_UNTYPED: u64 = 20;

/// DevMgrBootInfo structure layout (must match device_mgr/boot_info.rs)
#[repr(C)]
struct DevMgrBootInfoLayout {
    magic: u64,
    version: u32,
    cnode_radix: u8,
    device_untyped_count: u8,
    _reserved: [u8; 2],
    dtb_vaddr: u64,
    dtb_size: u64,
    initrd_vaddr: u64,
    initrd_size: u64,
    device_untyped_phys: [u64; MAX_DEVICE_UNTYPED],
    device_untyped_size_bits: [u8; MAX_DEVICE_UNTYPED],
}

/// Spawn the device manager process.
fn spawn_device_mgr(boot_info: &UserBootInfo) {
    io::puts("[init] Spawning device-mgr...\n");

    // Find device-mgr binary
    let elf_data = match find_in_initrd(boot_info, "device-mgr") {
        Some(data) => data,
        None => {
            io::puts("[init] ERROR: device-mgr not found in initrd\n");
            return;
        }
    };
    io::puts("[init] Found device-mgr: ");
    io::put_u64(elf_data.len() as u64);
    io::puts(" bytes\n");

    // Find device untypeds from boot_info
    let mut device_untyped_slots: [u64; MAX_DEVICE_UNTYPED] = [0; MAX_DEVICE_UNTYPED];
    let mut device_untyped_phys: [u64; MAX_DEVICE_UNTYPED] = [0; MAX_DEVICE_UNTYPED];
    let mut device_untyped_size_bits: [u8; MAX_DEVICE_UNTYPED] = [0; MAX_DEVICE_UNTYPED];
    let mut device_untyped_count = 0usize;

    for i in 0..boot_info.untyped_count as usize {
        if boot_info.untyped_is_device(i) && device_untyped_count < MAX_DEVICE_UNTYPED {
            let slot = slots::FIRST_UNTYPED + i as u64;
            device_untyped_slots[device_untyped_count] = slot;
            device_untyped_phys[device_untyped_count] = boot_info.untyped_phys_base[i];
            device_untyped_size_bits[device_untyped_count] = boot_info.untyped_size_bits[i];

            io::puts("[init] Device untyped ");
            io::put_u64(device_untyped_count as u64);
            io::puts(": slot ");
            io::put_u64(slot);
            io::puts(" phys ");
            io::put_hex(boot_info.untyped_phys_base[i]);
            io::puts(" size 2^");
            io::put_u64(boot_info.untyped_size_bits[i] as u64);
            io::newline();

            device_untyped_count += 1;
        }
    }

    io::puts("[init] Found ");
    io::put_u64(device_untyped_count as u64);
    io::puts(" device untypeds\n");

    // Create registry endpoint for device-mgr
    let registry_ep_slot = FIRST_FREE_SLOT;
    let radix = boot_info.cnode_radix as u8;
    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, radix);

    io::puts("[init] Creating registry endpoint at slot ");
    io::put_u64(registry_ep_slot);
    io::newline();

    if let Err(e) = m6_syscall::invoke::retype(
        cptr(slots::FIRST_UNTYPED),
        11, // ObjectType::Endpoint
        0,  // size_bits (not used for endpoints)
        cptr(slots::ROOT_CNODE),
        registry_ep_slot,
        1,  // count - create one endpoint
    ) {
        io::puts("[init] ERROR: Failed to create registry endpoint: ");
        io::put_hex(e as u64);
        io::newline();
        return;
    }

    io::puts("[init] Registry endpoint created successfully\n");

    // Build initial capabilities list including device untypeds
    // Max 16 initial caps: 3 standard + up to 8 device untypeds + some margin
    let mut initial_caps_storage: [InitialCap; 16] = [InitialCap { src_slot: 0, dst_slot: 0 }; 16];
    let mut cap_idx = 0;

    // Standard caps
    initial_caps_storage[cap_idx] = InitialCap { src_slot: registry_ep_slot, dst_slot: 12 };
    cap_idx += 1;
    initial_caps_storage[cap_idx] = InitialCap { src_slot: slots::IRQ_CONTROL, dst_slot: 14 };
    cap_idx += 1;
    initial_caps_storage[cap_idx] = InitialCap { src_slot: slots::FIRST_UNTYPED, dst_slot: 15 };
    cap_idx += 1;
    initial_caps_storage[cap_idx] = InitialCap { src_slot: slots::ASID_POOL, dst_slot: 16 };
    cap_idx += 1;

    // Device untypeds at slots 20+
    for i in 0..device_untyped_count {
        initial_caps_storage[cap_idx] = InitialCap {
            src_slot: device_untyped_slots[i],
            dst_slot: DEVMGR_FIRST_DEVICE_UNTYPED + i as u64,
        };
        cap_idx += 1;
    }

    let initial_caps = &initial_caps_storage[..cap_idx];

    // Configure spawn - don't resume yet, we need to map additional data
    let config = SpawnConfig {
        elf_data,
        root_cnode: slots::ROOT_CNODE,
        cnode_radix: boot_info.cnode_radix as u8,
        ram_untyped: slots::FIRST_UNTYPED,
        asid_pool: slots::ASID_POOL,
        next_free_slot: FIRST_FREE_SLOT + 1, // +1 for the endpoint we just created
        initial_caps,
        x0: DEVMGR_BOOT_INFO_ADDR, // Will point to boot info
        resume: false, // Don't resume yet
    };

    let result = match process::spawn_process(&config) {
        Ok(r) => r,
        Err(e) => {
            io::puts("[init] \x1b[31mFailed to spawn device-mgr: ");
            print_spawn_error(e);
            io::puts("\x1b[0m\n");
            return;
        }
    };

    let radix = boot_info.cnode_radix as u8;
    let mut next_slot = result.next_free_slot;
    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, radix);

    // Ensure page tables exist for our mapping regions
    // Boot info region (at 256MB)
    if let Err(_) = process::ensure_child_page_tables(
        slots::ROOT_CNODE,
        radix,
        result.vspace_slot,
        slots::FIRST_UNTYPED,
        &mut next_slot,
        DEVMGR_BOOT_INFO_ADDR,
        DEVMGR_DTB_ADDR + boot_info.dtb_size,
    ) {
        io::puts("[init] ERROR: Failed to create page tables for boot info region\n");
        return;
    }

    // Initrd region (at 512MB) - may need separate page tables
    if boot_info.has_initrd() {
        if let Err(_) = process::ensure_child_page_tables(
            slots::ROOT_CNODE,
            radix,
            result.vspace_slot,
            slots::FIRST_UNTYPED,
            &mut next_slot,
            DEVMGR_INITRD_ADDR,
            DEVMGR_INITRD_ADDR + boot_info.initrd_size,
        ) {
            io::puts("[init] ERROR: Failed to create page tables for initrd region\n");
            return;
        }
    }

    // Create boot info structure
    let dev_boot_info = DevMgrBootInfoLayout {
        magic: DEV_MGR_BOOT_INFO_MAGIC,
        version: DEV_MGR_BOOT_INFO_VERSION,
        cnode_radix: 12, // Device-mgr's CNode has radix 12 (set in spawn_process)
        device_untyped_count: device_untyped_count as u8,
        _reserved: [0; 2],
        dtb_vaddr: if boot_info.has_dtb() { DEVMGR_DTB_ADDR } else { 0 },
        dtb_size: boot_info.dtb_size,
        initrd_vaddr: if boot_info.has_initrd() { DEVMGR_INITRD_ADDR } else { 0 },
        initrd_size: boot_info.initrd_size,
        device_untyped_phys,
        device_untyped_size_bits,
    };

    // Map boot info, DTB, and initrd into device-mgr's VSpace
    let boot_info_bytes = unsafe {
        core::slice::from_raw_parts(
            &dev_boot_info as *const _ as *const u8,
            core::mem::size_of::<DevMgrBootInfoLayout>(),
        )
    };
    if let Err(_) = process::map_data_to_child(
        slots::ROOT_CNODE,
        radix,
        result.vspace_slot,
        slots::FIRST_UNTYPED,
        &mut next_slot,
        DEVMGR_BOOT_INFO_ADDR,
        boot_info_bytes,
        process::MapRights::R,
    ) {
        io::puts("[init] ERROR: Failed to map boot info\n");
        return;
    }

    if boot_info.has_dtb() {
        let dtb_data = unsafe {
            core::slice::from_raw_parts(
                boot_info.dtb_vaddr as *const u8,
                boot_info.dtb_size as usize,
            )
        };
        if let Err(_) = process::map_data_to_child(
            slots::ROOT_CNODE,
            radix,
            result.vspace_slot,
            slots::FIRST_UNTYPED,
            &mut next_slot,
            DEVMGR_DTB_ADDR,
            dtb_data,
            process::MapRights::R,
        ) {
            io::puts("[init] ERROR: Failed to map DTB\n");
            return;
        }
    }

    if boot_info.has_initrd() {
        let initrd_data = unsafe {
            core::slice::from_raw_parts(
                boot_info.initrd_vaddr as *const u8,
                boot_info.initrd_size as usize,
            )
        };
        if let Err(_) = process::map_data_to_child(
            slots::ROOT_CNODE,
            radix,
            result.vspace_slot,
            slots::FIRST_UNTYPED,
            &mut next_slot,
            DEVMGR_INITRD_ADDR,
            initrd_data,
            process::MapRights::R,
        ) {
            io::puts("[init] ERROR: Failed to map initrd\n");
            return;
        }
    }

    // Resume device-mgr TCB
    if let Err(e) = m6_syscall::invoke::tcb_resume(cptr(result.tcb_slot)) {
        io::puts("[init] ERROR: Failed to resume device-mgr: ");
        io::put_hex(e as u64);
        io::newline();
        return;
    }

    io::puts("[init] \x1b[32mdevice-mgr spawned successfully\x1b[0m\n");
    io::puts("[init]   TCB slot: ");
    io::put_u64(result.tcb_slot);
    io::puts(", ASID: ");
    io::put_u64(result.asid);
    io::newline();

    // Request UART driver via ENSURE
    // This triggers device-mgr to spawn the PL011 driver
    request_uart_driver(registry_ep_slot, radix);
}

/// Request the UART driver from device-mgr.
///
/// Sends an ENSURE request for the PL011 UART device. Once capability
/// transfer is fully implemented, this would receive the driver's service
/// endpoint and initialise io::init_console() with it.
fn request_uart_driver(registry_ep: u64, radix: u8) {
    io::puts("[init] Requesting UART driver from device-mgr...\n");

    let cptr = |slot: u64| m6_syscall::slot_to_cptr(slot, radix);

    // Send ENSURE request
    // x0 = ENSURE label (0x0001)
    // Currently device-mgr uses placeholder logic that finds first unbound device
    const ENSURE: u64 = 0x0001;

    // Use the Call syscall for proper RPC semantics
    // Call sends the request and blocks waiting for the reply
    match m6_syscall::invoke::call(cptr(registry_ep), ENSURE, 0, 0, 0) {
        Ok(result) => {
            // Response code is in label (x0) - reply_recv puts it in x1,
            // kernel extracts to msg[0], then delivers to receiver's x0
            let response = result.label;
            io::puts("[init] ENSURE response: ");
            io::put_hex(response);
            io::newline();

            if response == 0 {
                io::puts("[init] UART driver spawned successfully\n");
                // TODO: Once capability transfer is implemented, we would:
                // 1. Receive the driver's endpoint capability from IPC buffer
                // 2. Call io::init_console(uart_endpoint_slot) to enable IPC console
            } else {
                io::puts("[init] ENSURE failed with code: ");
                io::put_u64(response);
                io::newline();
            }
        }
        Err(e) => {
            io::puts("[init] Call to device-mgr failed: ");
            io::put_u64(e as u64);
            io::newline();
        }
    }
}

fn print_spawn_error(e: process::SpawnError) {
    match e {
        process::SpawnError::InvalidElf(_) => io::puts("invalid ELF"),
        process::SpawnError::OutOfMemory => io::puts("out of memory"),
        process::SpawnError::RetypeFailed(_) => io::puts("retype failed"),
        process::SpawnError::AsidAssignFailed(_) => io::puts("ASID assign failed"),
        process::SpawnError::TcbConfigureFailed(_) => io::puts("TCB config failed"),
        process::SpawnError::TcbWriteRegistersFailed(_) => io::puts("TCB write regs failed"),
        process::SpawnError::TcbResumeFailed(_) => io::puts("TCB resume failed"),
        process::SpawnError::FrameMapFailed(_) => io::puts("frame map failed"),
        process::SpawnError::PageTableMapFailed(_) => io::puts("page table map failed"),
        process::SpawnError::CapCopyFailed(_) => io::puts("cap copy failed"),
        process::SpawnError::InvalidAddress => io::puts("invalid address"),
        process::SpawnError::NoSlots => io::puts("no slots"),
    }
}

/// Panic handler - print message and loop forever.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    io::puts("\n\x1b[31m*** INIT PANIC ***\x1b[0m\n");
    if let Some(location) = info.location() {
        io::puts("  at ");
        io::puts(location.file());
        io::puts(":");
        io::put_u64(location.line() as u64);
        io::newline();
    }
    if let Some(msg) = info.message().as_str() {
        io::puts("  ");
        io::puts(msg);
        io::newline();
    }
    loop {
        sched_yield();
    }
}
