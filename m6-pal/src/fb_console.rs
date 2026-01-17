//! Framebuffer Console
//!
//! Text console implementation using embedded-graphics for rendering
//! monospace text to the framebuffer.

use core::fmt::{self, Write};

use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::Point,
    mono_font::{ascii::FONT_8X13, MonoTextStyle},
    pixelcolor::{Rgb888, RgbColor},
    text::Text,
    Drawable,
};
use spin::mutex::SpinMutex;

use crate::framebuffer::{FramebufferConfig, FramebufferDisplay};

/// Font dimensions
const CHAR_WIDTH: u32 = 8;
const CHAR_HEIGHT: u32 = 13;

/// Padding from screen edges
const PADDING_X: u32 = 4;
const PADDING_Y: u32 = 4;

/// Default text colour (white)
const TEXT_COLOR: Rgb888 = Rgb888::new(255, 255, 255);
/// Default background colour (black)
const BG_COLOR: Rgb888 = Rgb888::new(0, 0, 0);

/// Framebuffer console state
struct FbConsoleInner {
    display: Option<FramebufferDisplay>,
    cursor_col: u32,
    cursor_row: u32,
    cols: u32,
    rows: u32,
    text_style: MonoTextStyle<'static, Rgb888>,
}

impl FbConsoleInner {
    const fn new() -> Self {
        Self {
            display: None,
            cursor_col: 0,
            cursor_row: 0,
            cols: 0,
            rows: 0,
            text_style: MonoTextStyle::new(&FONT_8X13, TEXT_COLOR),
        }
    }

    fn init(&mut self, config: FramebufferConfig) {
        if !config.is_valid() {
            return;
        }

        // Calculate usable area
        let usable_width = config.width.saturating_sub(PADDING_X * 2);
        let usable_height = config.height.saturating_sub(PADDING_Y * 2);

        self.cols = usable_width / CHAR_WIDTH;
        self.rows = usable_height / CHAR_HEIGHT;

        // SAFETY: Config has been validated as having a valid base address
        // and the framebuffer is mapped by the bootloader
        let mut display = unsafe { FramebufferDisplay::new(config) };

        // Clear the screen to background colour
        let _ = display.clear(BG_COLOR);

        self.display = Some(display);
        self.cursor_col = 0;
        self.cursor_row = 0;
    }

    fn is_available(&self) -> bool {
        self.display.is_some()
    }

    fn putc(&mut self, c: u8) {
        let display = match self.display.as_mut() {
            Some(d) => d,
            None => return,
        };

        match c {
            b'\n' => {
                self.cursor_col = 0;
                self.cursor_row += 1;
                if self.cursor_row >= self.rows {
                    self.scroll();
                }
            }
            b'\r' => {
                self.cursor_col = 0;
            }
            b'\t' => {
                // Tab to next 8-column boundary
                let next_tab = ((self.cursor_col / 8) + 1) * 8;
                self.cursor_col = next_tab.min(self.cols - 1);
            }
            c if c >= 0x20 && c < 0x7F => {
                // Printable ASCII
                let x = PADDING_X + self.cursor_col * CHAR_WIDTH;
                let y = PADDING_Y + self.cursor_row * CHAR_HEIGHT + CHAR_HEIGHT;

                // Create a single-character string
                let char_buf = [c];
                let s = core::str::from_utf8(&char_buf).unwrap_or("?");

                // Draw the character
                let _ = Text::new(s, Point::new(x as i32, y as i32), self.text_style)
                    .draw(display);

                self.cursor_col += 1;
                if self.cursor_col >= self.cols {
                    self.cursor_col = 0;
                    self.cursor_row += 1;
                    if self.cursor_row >= self.rows {
                        self.scroll();
                    }
                }
            }
            _ => {
                // Ignore non-printable characters
            }
        }
    }

    fn puts(&mut self, s: &str) {
        for c in s.bytes() {
            self.putc(c);
        }
    }

    fn scroll(&mut self) {
        let display = match self.display.as_mut() {
            Some(d) => d,
            None => return,
        };

        let config = display.config();
        let base = config.base as *mut u32;
        let stride_pixels = config.stride / 4;

        // Move all rows up by one character height
        let scroll_pixels = CHAR_HEIGHT;
        let copy_height = config.height - PADDING_Y * 2 - scroll_pixels;

        // Copy pixels up
        for y in 0..copy_height {
            let src_y = PADDING_Y + scroll_pixels + y;
            let dst_y = PADDING_Y + y;

            for x in 0..config.width {
                let src_offset = (src_y * stride_pixels + x) as usize;
                let dst_offset = (dst_y * stride_pixels + x) as usize;

                // SAFETY: We're within bounds of the framebuffer
                unsafe {
                    let pixel = base.add(src_offset).read_volatile();
                    base.add(dst_offset).write_volatile(pixel);
                }
            }
        }

        // Clear the last row
        let clear_start_y = PADDING_Y + copy_height;
        let bg_pixel = if config.is_bgr {
            (BG_COLOR.b() as u32) | ((BG_COLOR.g() as u32) << 8) | ((BG_COLOR.r() as u32) << 16)
        } else {
            (BG_COLOR.r() as u32) | ((BG_COLOR.g() as u32) << 8) | ((BG_COLOR.b() as u32) << 16)
        };

        for y in clear_start_y..config.height - PADDING_Y {
            for x in 0..config.width {
                let offset = (y * stride_pixels + x) as usize;
                // SAFETY: We're within bounds of the framebuffer
                unsafe {
                    base.add(offset).write_volatile(bg_pixel);
                }
            }
        }

        // Keep cursor on last row
        self.cursor_row = self.rows.saturating_sub(1);
    }
}

impl Write for FbConsoleInner {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.puts(s);
        Ok(())
    }
}

/// Global framebuffer console instance
static FB_CONSOLE: SpinMutex<FbConsoleInner> = SpinMutex::new(FbConsoleInner::new());

/// Initialise the framebuffer console
pub fn init(config: FramebufferConfig) {
    let mut console = FB_CONSOLE.lock();
    console.init(config);
}

/// Check if framebuffer console is available
pub fn is_available() -> bool {
    let console = FB_CONSOLE.lock();
    console.is_available()
}

/// Print a string to the framebuffer console
pub fn puts(s: &str) {
    let mut console = FB_CONSOLE.lock();
    console.puts(s);
}

/// Print a character to the framebuffer console
pub fn putc(c: u8) {
    let mut console = FB_CONSOLE.lock();
    console.putc(c);
}

/// Framebuffer console writer for fmt::Write
pub struct FbConsoleWriter;

impl Write for FbConsoleWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        puts(s);
        Ok(())
    }
}
