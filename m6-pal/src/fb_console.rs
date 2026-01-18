//! Framebuffer Console
//!
//! Text console implementation using embedded-graphics for rendering
//! monospace text to the framebuffer.
//!
//! Uses a text buffer approach: characters are stored in RAM and the
//! framebuffer is write-only. This avoids slow framebuffer reads during
//! scrolling.

use core::fmt::{self, Write};

use embedded_graphics::{
    Drawable,
    draw_target::DrawTarget,
    geometry::Point,
    mono_font::{MonoTextStyle, MonoTextStyleBuilder, ascii::FONT_8X13},
    pixelcolor::Rgb888,
    text::Text,
};
use spin::mutex::SpinMutex;

use crate::framebuffer::{FramebufferConfig, FramebufferDisplay};

/// Font dimensions
const CHAR_WIDTH: u32 = 8;
const CHAR_HEIGHT: u32 = 13;

/// Padding from screen edges
const PADDING_X: u32 = 4;
const PADDING_Y: u32 = 4;

/// Maximum console dimensions
const MAX_COLS: usize = 240;
const MAX_ROWS: usize = 90;

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
    /// Text style with background for drawing characters that clear their cell
    text_style: MonoTextStyle<'static, Rgb888>,
    /// Text buffer in RAM - avoids reading from framebuffer during scroll
    text_buffer: [[u8; MAX_COLS]; MAX_ROWS],
}

impl FbConsoleInner {
    const fn new() -> Self {
        Self {
            display: None,
            cursor_col: 0,
            cursor_row: 0,
            cols: 0,
            rows: 0,
            text_style: MonoTextStyleBuilder::new()
                .font(&FONT_8X13)
                .text_color(TEXT_COLOR)
                .background_color(BG_COLOR)
                .build(),
            text_buffer: [[b' '; MAX_COLS]; MAX_ROWS],
        }
    }

    fn init(&mut self, config: FramebufferConfig) {
        if !config.is_valid() {
            return;
        }

        // Calculate usable area
        let usable_width = config.width.saturating_sub(PADDING_X * 2);
        let usable_height = config.height.saturating_sub(PADDING_Y * 2);

        self.cols = (usable_width / CHAR_WIDTH).min(MAX_COLS as u32);
        self.rows = (usable_height / CHAR_HEIGHT).min(MAX_ROWS as u32);

        // SAFETY: Config has been validated as having a valid base address
        // and the framebuffer is mapped by the bootloader
        let mut display = unsafe { FramebufferDisplay::new(config) };

        // Clear the screen to background colour
        let _ = display.clear(BG_COLOR);

        self.display = Some(display);
        self.cursor_col = 0;
        self.cursor_row = 0;

        // Clear text buffer
        for row in self.text_buffer.iter_mut() {
            row.fill(b' ');
        }
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
            c if (0x20..0x7F).contains(&c) => {
                // Store in text buffer
                let row = self.cursor_row as usize;
                let col = self.cursor_col as usize;
                if row < MAX_ROWS && col < MAX_COLS {
                    self.text_buffer[row][col] = c;
                }

                // Printable ASCII - draw with background to clear cell
                let x = PADDING_X + self.cursor_col * CHAR_WIDTH;
                let y = PADDING_Y + self.cursor_row * CHAR_HEIGHT + CHAR_HEIGHT;

                // Create a single-character string
                let char_buf = [c];
                let s = core::str::from_utf8(&char_buf).unwrap_or("?");

                // Draw the character with background (clears the cell)
                let _ = Text::new(s, Point::new(x as i32, y as i32), self.text_style).draw(display);

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

        let rows = self.rows as usize;
        let cols = self.cols as usize;

        // Step 1: Shift text buffer up in RAM (fast memory operation)
        for row in 1..rows {
            if row < MAX_ROWS {
                // Copy row data up
                let src_row = self.text_buffer[row];
                self.text_buffer[row - 1] = src_row;
            }
        }

        // Clear the last row in the text buffer
        if rows > 0 && rows <= MAX_ROWS {
            self.text_buffer[rows - 1].fill(b' ');
        }

        // Get framebuffer info for clearing trailing areas
        let config = display.config();
        let base = config.base as *mut u8;
        let stride_bytes = config.stride as usize;
        let bytes_per_pixel = 4usize; // 32bpp
        let fb_height = config.height;

        // Step 2: Clear all rows (cell + descender area)
        // Do this in one pass before drawing to avoid clear/draw overlap issues
        let row_width_bytes = cols * (CHAR_WIDTH as usize) * bytes_per_pixel;
        for row in 0..rows {
            let text_y_start = PADDING_Y + (row as u32) * CHAR_HEIGHT;
            let text_y_end = text_y_start + CHAR_HEIGHT;
            let clear_y_end = (text_y_end + 3).min(fb_height);

            // SAFETY: We're writing within framebuffer bounds
            unsafe {
                for py in text_y_start..clear_y_end {
                    let row_ptr = base
                        .add((py as usize) * stride_bytes + (PADDING_X as usize) * bytes_per_pixel);
                    core::ptr::write_bytes(row_ptr, 0, row_width_bytes);
                }
            }
        }

        // Step 3: Draw all text
        for row in 0..rows {
            let row_data = &self.text_buffer[row][..cols.min(MAX_COLS)];

            // Find last non-space character
            let last_char = row_data
                .iter()
                .rposition(|&c| c != b' ')
                .map(|pos| pos + 1)
                .unwrap_or(0);

            if last_char > 0 {
                let x = PADDING_X;
                let y = PADDING_Y + (row as u32) * CHAR_HEIGHT + CHAR_HEIGHT;

                if let Ok(s) = core::str::from_utf8(&row_data[..last_char]) {
                    let _ =
                        Text::new(s, Point::new(x as i32, y as i32), self.text_style).draw(display);
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
