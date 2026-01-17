//! UEFI GOP (Graphics Output Protocol) Framebuffer Initialisation
//!
//! This module provides functions to initialise and query the UEFI GOP
//! for framebuffer information. The framebuffer can be used for early
//! kernel console output before proper display drivers are loaded.

use m6_common::boot::FramebufferInfo;
use uefi::boot::{self, OpenProtocolAttributes, OpenProtocolParams};
use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};

/// Attempt to initialise GOP and retrieve framebuffer information.
///
/// Returns `Some(FramebufferInfo)` with physical address populated if GOP
/// is available. The `virt_base` field will be 0 and must be set by the
/// caller after mapping the framebuffer into kernel address space.
///
/// Returns `None` if GOP is not available (headless system).
pub fn init_gop() -> Option<FramebufferInfo> {
    // Try to get GOP handle - may not be available on headless systems
    let gop_handle = match boot::get_handle_for_protocol::<GraphicsOutput>() {
        Ok(handle) => handle,
        Err(_) => {
            log::debug!("GOP protocol not available");
            return None;
        }
    };

    // Open GOP with non-exclusive access - UEFI firmware also uses the
    // framebuffer for its own display, so we must not request exclusive access.
    // SAFETY: We're using GetProtocol which doesn't track usage, but we only
    // read the framebuffer info and don't modify anything until after
    // exit_boot_services when UEFI is no longer using it.
    let mut gop = match unsafe {
        boot::open_protocol::<GraphicsOutput>(
            OpenProtocolParams {
                handle: gop_handle,
                agent: boot::image_handle(),
                controller: None,
            },
            OpenProtocolAttributes::GetProtocol,
        )
    } {
        Ok(gop) => gop,
        Err(e) => {
            log::warn!("Failed to open GOP protocol: {:?}", e);
            return None;
        }
    };

    let mode = gop.current_mode_info();
    let (width, height) = mode.resolution();
    let stride = mode.stride();

    // Get framebuffer physical address and size
    let mut fb = gop.frame_buffer();
    let fb_base = fb.as_mut_ptr() as u64;
    let fb_size = fb.size() as u64;

    // Determine pixel format and RGB positions
    let (bpp, red_pos, red_size, green_pos, green_size, blue_pos, blue_size) =
        match mode.pixel_format() {
            PixelFormat::Rgb => (32, 0, 8, 8, 8, 16, 8),
            PixelFormat::Bgr => (32, 16, 8, 8, 8, 0, 8),
            PixelFormat::Bitmask => {
                // Bitmask format requires parsing pixel_bitmask() - treat as BGR
                log::warn!("GOP Bitmask pixel format - assuming BGR");
                (32, 16, 8, 8, 8, 0, 8)
            }
            PixelFormat::BltOnly => {
                // BltOnly means no direct framebuffer access
                log::warn!("GOP BltOnly mode - no direct framebuffer access");
                return None;
            }
        };

    log::info!(
        "GOP: {}x{} @ {:#x}, {} bytes, stride={}, format={:?}",
        width,
        height,
        fb_base,
        fb_size,
        stride,
        mode.pixel_format()
    );

    Some(FramebufferInfo {
        base: fb_base,
        virt_base: 0, // To be set after mapping
        size: fb_size,
        width: width as u32,
        height: height as u32,
        stride: (stride * 4) as u32, // stride is in pixels, convert to bytes (4 bytes per pixel)
        bpp,
        red_position: red_pos,
        red_size,
        green_position: green_pos,
        green_size,
        blue_position: blue_pos,
        blue_size,
        _reserved: [0; 2],
    })
}
