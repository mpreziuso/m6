//! IPC Buffer for extended syscall arguments
//!
//! The IPC buffer is a per-thread shared memory region for passing extended
//! arguments to syscalls that need more than 6 registers worth of data.
//!
//! # Usage
//!
//! - CapMint uses the IPC buffer to pass rights, badge, and depth values
//! - Future IPC extensions may use it for capability transfer
//!
//! # Memory Layout
//!
//! The IPC buffer is mapped at a fixed virtual address per thread.
//! It must be page-aligned and fit within a single 4KB page.

/// Virtual address where the IPC buffer is mapped.
///
/// This is in the upper part of user address space, in the IPC buffer region.
/// Must match `layout::IPC_BUFFER_BASE` in the kernel.
pub const IPC_BUFFER_ADDR: u64 = 0x0000_7FFF_C000_0000;

/// Size of the IPC buffer (one 4KB page).
pub const IPC_BUFFER_SIZE: usize = 4096;

/// IPC buffer structure.
///
/// This is the shared memory region between kernel and userspace for
/// extended syscall arguments.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpcBuffer {
    /// Capability badges or extra capability slots for IPC.
    /// Used for capability transfer in Send/Recv operations.
    pub caps_or_badges: [u64; 4],

    /// Number of extra capabilities to send.
    pub extra_caps: u8,

    /// Number of extra capabilities to receive.
    pub recv_extra_caps: u8,

    /// Padding for alignment.
    _pad0: [u8; 6],

    /// Extended arguments for CapMint syscall.
    pub mint_args: MintArgs,

    /// Reserved for future use.
    _reserved: [u8; 4016],
}

/// Extended arguments for the CapMint syscall.
///
/// These are read from the IPC buffer since CapMint needs more
/// arguments than can fit in 6 registers.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MintArgs {
    /// Depth bits for resolving the destination CNode.
    pub dest_depth: u8,

    /// Depth bits for resolving the source CNode.
    pub src_depth: u8,

    /// New rights for the minted capability.
    /// Must be a subset of the source capability's rights.
    pub new_rights: u8,

    /// Whether to set a badge on the minted capability.
    /// 0 = don't set badge, 1 = set badge from `badge_value`.
    pub set_badge: u8,

    /// Padding for alignment.
    _pad: [u8; 4],

    /// Badge value to set on the minted capability.
    /// Only used if `set_badge` is non-zero.
    pub badge_value: u64,
}

impl Default for IpcBuffer {
    fn default() -> Self {
        Self {
            caps_or_badges: [0; 4],
            extra_caps: 0,
            recv_extra_caps: 0,
            _pad0: [0; 6],
            mint_args: MintArgs::default(),
            _reserved: [0; 4016],
        }
    }
}

impl IpcBuffer {
    /// Create a new zeroed IPC buffer.
    pub const fn new() -> Self {
        Self {
            caps_or_badges: [0; 4],
            extra_caps: 0,
            recv_extra_caps: 0,
            _pad0: [0; 6],
            mint_args: MintArgs {
                dest_depth: 0,
                src_depth: 0,
                new_rights: 0,
                set_badge: 0,
                _pad: [0; 4],
                badge_value: 0,
            },
            _reserved: [0; 4016],
        }
    }

    /// Get a reference to the IPC buffer at the standard address.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The IPC buffer page is mapped at `IPC_BUFFER_ADDR`
    /// - No other code is mutably accessing the buffer
    #[cfg(feature = "userspace")]
    pub unsafe fn get() -> &'static Self {
        // SAFETY: Caller guarantees the buffer is mapped and accessible.
        unsafe { &*(IPC_BUFFER_ADDR as *const Self) }
    }

    /// Get a mutable reference to the IPC buffer at the standard address.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The IPC buffer page is mapped at `IPC_BUFFER_ADDR`
    /// - No other code is accessing the buffer
    #[cfg(feature = "userspace")]
    pub unsafe fn get_mut() -> &'static mut Self {
        // SAFETY: Caller guarantees the buffer is mapped and accessible.
        unsafe { &mut *(IPC_BUFFER_ADDR as *mut Self) }
    }
}

impl MintArgs {
    /// Create new mint arguments.
    pub const fn new(
        dest_depth: u8,
        src_depth: u8,
        new_rights: u8,
        badge: Option<u64>,
    ) -> Self {
        let (set_badge, badge_value) = match badge {
            Some(b) => (1, b),
            None => (0, 0),
        };

        Self {
            dest_depth,
            src_depth,
            new_rights,
            set_badge,
            _pad: [0; 4],
            badge_value,
        }
    }

    /// Check if a badge should be set.
    pub const fn should_set_badge(&self) -> bool {
        self.set_badge != 0
    }

    /// Get the badge value if one should be set.
    pub const fn badge(&self) -> Option<u64> {
        if self.set_badge != 0 {
            Some(self.badge_value)
        } else {
            None
        }
    }
}

// Ensure the IPC buffer fits in a single page
const _: () = assert!(
    core::mem::size_of::<IpcBuffer>() <= IPC_BUFFER_SIZE,
    "IpcBuffer must fit in a single page"
);

// Ensure proper alignment
const _: () = assert!(
    core::mem::align_of::<IpcBuffer>() <= 8,
    "IpcBuffer must have reasonable alignment"
);
