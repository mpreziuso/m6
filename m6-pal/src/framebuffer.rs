//! Framebuffer Display Driver
//!
//! Provides a DrawTarget implementation for embedded-graphics to render
//! graphics primitives to the GOP framebuffer.

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::Rgb888,
    Pixel,
};

/// Framebuffer configuration from BootInfo
#[derive(Clone, Copy, Debug)]
pub struct FramebufferConfig {
    /// Virtual base address (kernel-mapped)
    pub base: u64,
    /// Width in pixels
    pub width: u32,
    /// Height in pixels
    pub height: u32,
    /// Stride in bytes per row
    pub stride: u32,
    /// Bits per pixel (expected to be 32)
    pub bpp: u32,
    /// True if pixel format is BGR (blue at position 0)
    pub is_bgr: bool,
}

impl FramebufferConfig {
    /// Check if this config represents a valid framebuffer
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.base != 0 && self.width > 0 && self.height > 0 && self.stride > 0
    }
}

/// Framebuffer display implementing embedded-graphics DrawTarget
pub struct FramebufferDisplay {
    config: FramebufferConfig,
}

impl FramebufferDisplay {
    /// Create a new framebuffer display
    ///
    /// # Safety
    /// The caller must ensure:
    /// - `config.base` points to a valid, mapped framebuffer region
    /// - The framebuffer region is at least `config.stride * config.height` bytes
    /// - No other code writes to the framebuffer concurrently
    pub unsafe fn new(config: FramebufferConfig) -> Self {
        Self { config }
    }

    /// Get the framebuffer configuration
    pub fn config(&self) -> &FramebufferConfig {
        &self.config
    }

    /// Clear the entire framebuffer to a colour
    pub fn clear_color(&mut self, color: Rgb888) {
        let pixel = self.color_to_pixel(color);
        let base = self.config.base as *mut u32;
        let stride_pixels = self.config.stride / 4;

        for y in 0..self.config.height {
            for x in 0..self.config.width {
                let offset = (y * stride_pixels + x) as usize;
                // SAFETY: We're within bounds of the framebuffer
                unsafe {
                    base.add(offset).write_volatile(pixel);
                }
            }
        }
    }

    /// Convert an Rgb888 colour to the native pixel format
    #[inline]
    fn color_to_pixel(&self, color: Rgb888) -> u32 {
        use embedded_graphics::pixelcolor::RgbColor;
        if self.config.is_bgr {
            (color.b() as u32) | ((color.g() as u32) << 8) | ((color.r() as u32) << 16)
        } else {
            (color.r() as u32) | ((color.g() as u32) << 8) | ((color.b() as u32) << 16)
        }
    }

    /// Write a single pixel at the given coordinates
    #[inline]
    fn write_pixel(&mut self, x: u32, y: u32, color: Rgb888) {
        if x >= self.config.width || y >= self.config.height {
            return;
        }

        let pixel = self.color_to_pixel(color);
        let stride_pixels = self.config.stride / 4;
        let offset = (y * stride_pixels + x) as usize;
        let base = self.config.base as *mut u32;

        // SAFETY: We've bounds-checked x and y
        unsafe {
            base.add(offset).write_volatile(pixel);
        }
    }
}

impl OriginDimensions for FramebufferDisplay {
    fn size(&self) -> Size {
        Size::new(self.config.width, self.config.height)
    }
}

impl DrawTarget for FramebufferDisplay {
    type Color = Rgb888;
    type Error = core::convert::Infallible;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(coord, color) in pixels {
            // embedded-graphics uses i32 for coordinates
            if coord.x >= 0 && coord.y >= 0 {
                self.write_pixel(coord.x as u32, coord.y as u32, color);
            }
        }
        Ok(())
    }

    fn clear(&mut self, color: Self::Color) -> Result<(), Self::Error> {
        self.clear_color(color);
        Ok(())
    }
}
