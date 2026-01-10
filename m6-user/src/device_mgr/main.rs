//! M6 Device Manager
//!
//! Userspace service responsible for:
//! - Enumerating devices from the device tree blob (DTB)
//! - Matching devices to driver binaries
//! - Spawning driver processes with appropriate capabilities
//! - Providing a registry service for clients to discover and access drivers
//!
//! The device manager receives:
//! - DTB Frame capability containing the device tree
//! - InitRD Frame capability containing driver binaries
//! - Registry endpoint for client requests
//! - Supervisor notification for reporting driver deaths

#![no_std]
#![no_main]
#![deny(unsafe_op_in_unsafe_fn)]
#![allow(dead_code)]

mod boot_info;
mod dtb;
mod ipc;
mod manifest;
mod registry;
mod slots;
mod spawn;

// Re-use io module from parent crate
#[path = "../io.rs"]
mod io;

use core::panic::PanicInfo;
use m6_syscall::invoke::{recv, sched_yield, send, signal};

use boot_info::DevMgrBootInfo;
use registry::{DeviceState, Registry};
use spawn::{DeviceInfo, DriverSpawnConfig};

/// Static storage for boot info pointer (set at startup)
static mut BOOT_INFO: *const DevMgrBootInfo = core::ptr::null();

/// Entry point for device manager.
///
/// # Safety
///
/// Must be called only once as the entry point. Init must have provided
/// the required capabilities in the well-known slots and a valid
/// DevMgrBootInfo pointer in x0.
#[unsafe(no_mangle)]
#[unsafe(link_section = ".text.entry")]
pub unsafe extern "C" fn _start(boot_info_addr: u64) -> ! {
    io::puts("\n\x1b[34m[device-mgr] Starting device manager\x1b[0m\n");

    // Store boot info pointer
    unsafe {
        BOOT_INFO = boot_info_addr as *const DevMgrBootInfo;
    }

    // Validate boot info
    let boot_info = unsafe { &*BOOT_INFO };
    if !boot_info.is_valid() {
        io::puts("[device-mgr] ERROR: Invalid boot info!\n");
        loop {
            sched_yield();
        }
    }

    io::puts("[device-mgr] Boot info valid, DTB at ");
    io::put_hex(boot_info.dtb_vaddr);
    io::puts(" (");
    io::put_u64(boot_info.dtb_size);
    io::puts(" bytes)\n");

    // Initialise registry
    let mut registry = Registry::new(slots::FIRST_FREE_SLOT);

    // Parse DTB and enumerate devices
    match init_dtb(&mut registry, boot_info) {
        Ok(count) => {
            io::puts("[device-mgr] Enumerated ");
            io::put_u64(count as u64);
            io::puts(" devices\n");

            // Print enumerated devices
            for i in 0..registry.device_count {
                let device = &registry.devices[i];
                io::puts("  - ");
                io::puts(device.path_str());
                io::puts(" [");
                io::puts(device.compatible_str());
                io::puts("] @ ");
                io::put_hex(device.phys_base);
                if device.irq != 0 {
                    io::puts(" IRQ ");
                    io::put_u64(device.irq as u64);
                }
                io::newline();
            }
        }
        Err(e) => {
            io::puts("[device-mgr] ERROR: Failed to parse DTB: ");
            io::puts(e);
            io::newline();
        }
    }

    // Enter main service loop
    io::puts("[device-mgr] Entering service loop\n");
    service_loop(&mut registry);
}

/// Initialise DTB parsing and enumerate devices.
fn init_dtb(registry: &mut Registry, boot_info: &DevMgrBootInfo) -> Result<usize, &'static str> {
    if !boot_info.has_dtb() {
        return Err("No DTB available");
    }

    // SAFETY: Init must have mapped the DTB frame before spawning us
    let dtb_data = unsafe { boot_info.dtb_slice() }.ok_or("DTB slice failed")?;

    dtb::enumerate_devices(dtb_data, registry)
}

/// Get the initrd data slice.
fn get_initrd() -> Option<&'static [u8]> {
    // SAFETY: We validated boot info at startup
    let boot_info = unsafe { &*BOOT_INFO };
    if !boot_info.has_initrd() {
        return None;
    }
    unsafe { boot_info.initrd_slice() }
}

/// Main service loop - handles client requests.
fn service_loop(registry: &mut Registry) -> ! {
    loop {
        // Wait for request on registry endpoint
        match recv(slots::REGISTRY_EP) {
            Ok(result) => {
                let sender_badge = result as u64;

                // Read message label from registers (simplified)
                // In a real implementation, this would come from the IPC message
                let label = 0u64;

                // Handle the request
                let response = handle_request(registry, sender_badge, label);

                // Reply to the sender
                let _ = send(slots::REGISTRY_EP, response, 0, 0, 0);
            }
            Err(_) => {
                // Error receiving - yield and try again
                sched_yield();
            }
        }
    }
}

/// Handle an incoming IPC request.
fn handle_request(registry: &mut Registry, badge: u64, label: u64) -> u64 {
    match label {
        ipc::request::ENSURE => handle_ensure(registry, badge),
        ipc::request::SUBSCRIBE => handle_subscribe(registry, badge),
        ipc::request::UNSUBSCRIBE => handle_unsubscribe(registry, badge),
        ipc::request::LIST_DEVICES => handle_list_devices(registry),
        ipc::request::GET_DEVICE_INFO => handle_get_device_info(registry, badge),
        ipc::request::RESTART_DECISION => handle_restart_decision(registry, badge),
        _ => ipc::response::ERR_INVALID_REQUEST,
    }
}

/// Handle ensure() request - spawn or return existing driver endpoint.
///
/// This is the main entry point for clients to get access to a device driver.
/// The request is idempotent: if the driver is already running, we just return
/// the existing endpoint.
fn handle_ensure(registry: &mut Registry, _badge: u64) -> u64 {
    // In a real implementation:
    // 1. Read device path from IPC buffer / shared memory
    // 2. Look up device in registry
    // For now, we use a placeholder device path

    // Placeholder: try to find first unbound device
    let device_idx = match find_first_unbound_device(registry) {
        Some(idx) => idx,
        None => return ipc::response::ERR_DEVICE_NOT_FOUND,
    };

    let device = &registry.devices[device_idx];

    // Check current state
    match device.state {
        DeviceState::Running => {
            // Driver already running - mint endpoint to client
            let driver_idx = device.driver_idx;
            if driver_idx < registry.driver_count {
                // In real impl: mint endpoint cap to client via IPC buffer
                return ipc::response::OK;
            }
            ipc::response::ERR_DEVICE_NOT_FOUND
        }
        DeviceState::Starting => {
            // Driver starting - client should retry
            ipc::response::ERR_DRIVER_STARTING
        }
        DeviceState::Dead => {
            // Driver dead - waiting for supervisor decision
            ipc::response::ERR_DRIVER_DEAD
        }
        DeviceState::Unbound => {
            // Need to spawn driver
            spawn_driver_for_device(registry, device_idx)
        }
    }
}

/// Find first unbound device in the registry.
fn find_first_unbound_device(registry: &Registry) -> Option<usize> {
    for i in 0..registry.device_count {
        if registry.devices[i].state == DeviceState::Unbound {
            return Some(i);
        }
    }
    None
}

/// Spawn a driver for a specific device.
fn spawn_driver_for_device(registry: &mut Registry, device_idx: usize) -> u64 {
    // Copy compatible string to avoid borrow issues
    let mut compat_buf = [0u8; 64];
    let compat_len;
    {
        let device = &registry.devices[device_idx];
        compat_len = device.compatible_len;
        compat_buf[..compat_len].copy_from_slice(&device.compatible[..compat_len]);
    }
    let compat = core::str::from_utf8(&compat_buf[..compat_len]).unwrap_or("");

    // Find driver in manifest
    let manifest_entry = match manifest::find_driver(compat) {
        Some(m) => m,
        None => {
            io::puts("[device-mgr] No driver for: ");
            io::puts(compat);
            io::newline();
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    // Find driver binary in initrd
    let initrd = match get_initrd() {
        Some(data) => data,
        None => {
            io::puts("[device-mgr] No initrd available\n");
            return ipc::response::ERR_NO_DRIVER;
        }
    };
    let archive = match tar_no_std::TarArchiveRef::new(initrd) {
        Ok(a) => a,
        Err(_) => {
            io::puts("[device-mgr] Failed to parse initrd TAR\n");
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    let elf_data = match archive
        .entries()
        .find(|e| e.filename().as_str() == Ok(manifest_entry.binary_name))
    {
        Some(entry) => entry.data(),
        None => {
            io::puts("[device-mgr] Driver binary not found: ");
            io::puts(manifest_entry.binary_name);
            io::newline();
            return ipc::response::ERR_NO_DRIVER;
        }
    };

    // Copy device info before modifying registry
    let device_info = DeviceInfo::from_entry(&registry.devices[device_idx]);

    // Mark device as starting
    registry.devices[device_idx].state = DeviceState::Starting;

    // Spawn the driver
    let config = DriverSpawnConfig {
        elf_data,
        device_info,
        device_idx,
        manifest: manifest_entry,
    };
    let spawn_result = spawn::spawn_driver(&config, registry);

    match spawn_result {
        Ok(result) => {
            // Update device state
            registry.devices[device_idx].state = DeviceState::Running;
            registry.devices[device_idx].driver_idx = result.driver_idx;

            io::puts("[device-mgr] Spawned driver for: ");
            io::puts(compat);
            io::newline();

            ipc::response::OK
        }
        Err(e) => {
            // Reset device state
            registry.devices[device_idx].state = DeviceState::Unbound;

            io::puts("[device-mgr] Failed to spawn driver: ");
            match e {
                spawn::SpawnError::InvalidElf(_) => io::puts("invalid ELF"),
                spawn::SpawnError::OutOfMemory => io::puts("out of memory"),
                spawn::SpawnError::RetypeFailed(_) => io::puts("retype failed"),
                spawn::SpawnError::TcbConfigureFailed(_) => io::puts("TCB config failed"),
                _ => io::puts("unknown error"),
            }
            io::newline();

            ipc::response::ERR_SPAWN_FAILED
        }
    }
}

/// Handle subscribe() request.
fn handle_subscribe(registry: &mut Registry, _badge: u64) -> u64 {
    // Find free subscription slot
    let sub_idx = match registry.find_free_subscription() {
        Some(idx) => idx,
        None => return ipc::response::ERR_ALREADY_SUBSCRIBED,
    };

    // In real impl: read notification cap from IPC buffer and store
    registry.subscriptions[sub_idx].active = true;
    registry.subscriptions[sub_idx].event_mask = ipc::event::ALL;

    // Return subscription ID
    sub_idx as u64
}

/// Handle unsubscribe() request.
fn handle_unsubscribe(registry: &mut Registry, _badge: u64) -> u64 {
    // In real impl: read subscription_id from message registers
    let subscription_id = 0usize; // placeholder

    if subscription_id >= registry::MAX_SUBSCRIPTIONS {
        return ipc::response::ERR_INVALID_SUBSCRIPTION;
    }

    if !registry.subscriptions[subscription_id].active {
        return ipc::response::ERR_INVALID_SUBSCRIPTION;
    }

    registry.subscriptions[subscription_id].active = false;
    ipc::response::OK
}

/// Handle list_devices() request.
fn handle_list_devices(registry: &Registry) -> u64 {
    // In real impl: write device list to IPC buffer
    // Return count in x1
    registry.device_count as u64
}

/// Handle get_device_info() request.
fn handle_get_device_info(_registry: &Registry, _badge: u64) -> u64 {
    // In real impl: read device path from IPC buffer, find device, return info
    // For now just return error
    ipc::response::ERR_DEVICE_NOT_FOUND
}

/// Handle restart_decision() from supervisor.
fn handle_restart_decision(_registry: &mut Registry, _badge: u64) -> u64 {
    // In real impl: read driver_id and action from message registers
    // action: 0 = don't restart, 1 = restart

    // For now, just acknowledge
    ipc::response::OK
}

/// Handle driver death detection.
///
/// Called when we receive a fault notification for a driver.
fn handle_driver_death(registry: &mut Registry, fault_badge: u64) {
    let driver_idx = ipc::badge::driver_index_from_badge(fault_badge) as usize;

    if driver_idx >= registry.driver_count {
        return;
    }

    io::puts("[device-mgr] Driver died: index ");
    io::put_u64(driver_idx as u64);
    io::newline();

    // Mark driver as dead
    registry.mark_driver_dead(driver_idx);

    // Notify supervisor
    let _ = signal(slots::SUPERVISOR_NOTIF);

    // Notify subscribed clients
    for sub in &registry.subscriptions {
        if sub.active && (sub.event_mask & ipc::event::DRIVER_DIED) != 0 {
            let _ = signal(sub.notification_slot);
        }
    }
}

/// Panic handler.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    io::puts("\n\x1b[31m*** DEVICE-MGR PANIC ***\x1b[0m\n");
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
