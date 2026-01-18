//! Block device implementation for embedded-sdmmc.
//!
//! Implements the BlockDevice trait to communicate with the virtio-blk
//! driver via IPC.

#![allow(dead_code)]

use embedded_sdmmc::BlockDevice;
use m6_syscall::invoke::{call, ipc_set_send_caps};

/// Sector size in bytes
pub const SECTOR_SIZE: usize = 512;

/// VirtIO block driver request codes
mod blk_request {
    pub const READ_SECTOR: u64 = 0x0001;
    pub const WRITE_SECTOR: u64 = 0x0002;
    pub const GET_INFO: u64 = 0x0003;
    pub const FLUSH: u64 = 0x0004;
}

/// VirtIO block driver response codes
mod blk_response {
    pub const OK: u64 = 0;
}

/// Block device error type
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockError {
    /// IPC communication error
    IpcError,
    /// I/O error from device
    IoError,
    /// Device not ready
    NotReady,
}

/// Block device wrapper for virtio-blk via IPC.
pub struct IpcBlockDevice {
    /// Endpoint capability to virtio-blk driver
    blk_ep: u64,
    /// Frame capability slot for data transfer
    data_frame_slot: u64,
    /// Virtual address where data frame is mapped
    data_vaddr: u64,
    /// Total number of blocks
    block_count: u64,
}

impl IpcBlockDevice {
    /// Create a new block device wrapper.
    ///
    /// # Arguments
    ///
    /// * `blk_ep` - Endpoint capability (CPtr) to virtio-blk driver
    /// * `data_frame_slot` - Frame slot number for data transfer
    /// * `data_vaddr` - Virtual address where data frame is mapped
    pub const fn new(blk_ep: u64, data_frame_slot: u64, data_vaddr: u64) -> Self {
        Self {
            blk_ep,
            data_frame_slot,
            data_vaddr,
            block_count: 0,
        }
    }

    /// Initialise the block device by querying device info.
    pub fn init(&mut self) -> Result<(), BlockError> {
        // Send GET_INFO to virtio-blk
        let reply =
            call(self.blk_ep, blk_request::GET_INFO, 0, 0, 0).map_err(|_| BlockError::IpcError)?;

        if reply.label != blk_response::OK {
            return Err(BlockError::IoError);
        }

        self.block_count = reply.msg[0];
        Ok(())
    }

    /// Get total number of blocks.
    pub fn block_count(&self) -> u64 {
        self.block_count
    }

    /// Sync all pending writes to the device.
    pub fn sync(&self) -> Result<(), BlockError> {
        let reply =
            call(self.blk_ep, blk_request::FLUSH, 0, 0, 0).map_err(|_| BlockError::IpcError)?;

        // FLUSH may return ERR_UNSUPPORTED (4) if not implemented
        if reply.label & 0xFFFF != blk_response::OK && reply.label & 0xFFFF != 4 {
            return Err(BlockError::IoError);
        }

        Ok(())
    }
}

impl BlockDevice for IpcBlockDevice {
    type Error = BlockError;

    fn read(
        &self,
        blocks: &mut [embedded_sdmmc::Block],
        start_block_idx: embedded_sdmmc::BlockIdx,
        _reason: &str,
    ) -> Result<(), Self::Error> {
        let start = start_block_idx.0 as u64;

        for (i, block) in blocks.iter_mut().enumerate() {
            let sector = start + i as u64;

            // Set up capability transfer for data frame
            // SAFETY: IPC buffer is mapped at fixed address
            unsafe {
                ipc_set_send_caps(&[self.data_frame_slot]);
            }

            // Send READ_SECTOR to virtio-blk
            let reply = call(self.blk_ep, blk_request::READ_SECTOR, sector, 1, 0)
                .map_err(|_| BlockError::IpcError)?;

            if reply.label & 0xFFFF != blk_response::OK {
                return Err(BlockError::IoError);
            }

            // Copy data from mapped frame to block
            // SAFETY: data_vaddr points to our mapped frame
            unsafe {
                let src = self.data_vaddr as *const u8;
                core::ptr::copy_nonoverlapping(src, block.contents.as_mut_ptr(), SECTOR_SIZE);
            }
        }

        Ok(())
    }

    fn write(
        &self,
        blocks: &[embedded_sdmmc::Block],
        start_block_idx: embedded_sdmmc::BlockIdx,
    ) -> Result<(), Self::Error> {
        let start = start_block_idx.0 as u64;

        for (i, block) in blocks.iter().enumerate() {
            let sector = start + i as u64;

            // Copy data to mapped frame
            // SAFETY: data_vaddr points to our mapped frame
            unsafe {
                let dst = self.data_vaddr as *mut u8;
                core::ptr::copy_nonoverlapping(block.contents.as_ptr(), dst, SECTOR_SIZE);
            }

            // Set up capability transfer
            // SAFETY: IPC buffer is mapped at fixed address
            unsafe {
                ipc_set_send_caps(&[self.data_frame_slot]);
            }

            // Send WRITE_SECTOR to virtio-blk
            let reply = call(self.blk_ep, blk_request::WRITE_SECTOR, sector, 1, 0)
                .map_err(|_| BlockError::IpcError)?;

            if reply.label & 0xFFFF != blk_response::OK {
                return Err(BlockError::IoError);
            }
        }

        Ok(())
    }

    fn num_blocks(&self) -> Result<embedded_sdmmc::BlockCount, Self::Error> {
        Ok(embedded_sdmmc::BlockCount(self.block_count as u32))
    }
}
