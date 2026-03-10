//! FAT32 volume formatter.
//!
//! Writes the minimal FAT32 on-disk structure to an unformatted block device.
//! Does not mount — caller handles mounting separately.

use super::block::{BlockError, IpcBlockDevice, SECTOR_SIZE};

const RESERVED_SECTORS: u32 = 32;
const NUM_FATS: u8 = 2;

/// Sectors per cluster based on total block count (512-byte sectors).
fn sectors_per_cluster(block_count: u64) -> u8 {
    if block_count < 16_384_000 {
        8
    } else if block_count < 33_554_432 {
        16
    } else if block_count < 67_108_864 {
        32
    } else {
        64
    }
}

/// Compute FAT size in sectors using the Microsoft FAT32 spec formula.
fn compute_fat_size(block_count: u64, spc: u8) -> u32 {
    // TmpVal1 = DskSize - ResvdSecCnt
    // TmpVal2 = (256 * SecPerClus + NumFATs) / 2  [FAT32 variant]
    // FATSz   = ceil(TmpVal1 / TmpVal2)
    let tmp1 = block_count.saturating_sub(RESERVED_SECTORS as u64);
    let tmp2 = 128u64 * spc as u64 + 1;
    ((tmp1 + tmp2 - 1) / tmp2) as u32
}

fn le16(buf: &mut [u8; SECTOR_SIZE], off: usize, val: u16) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
}

fn le32(buf: &mut [u8; SECTOR_SIZE], off: usize, val: u32) {
    buf[off] = val as u8;
    buf[off + 1] = (val >> 8) as u8;
    buf[off + 2] = (val >> 16) as u8;
    buf[off + 3] = (val >> 24) as u8;
}

fn build_boot_sector(block_count: u64, spc: u8, fat_size: u32) -> [u8; SECTOR_SIZE] {
    let mut s = [0u8; SECTOR_SIZE];

    // jmpBoot
    s[0] = 0xEB;
    s[1] = 0x58;
    s[2] = 0x90;
    // oemName
    s[3..11].copy_from_slice(b"MSDOS5.0");
    // bytesPerSector = 512
    le16(&mut s, 11, 512);
    // sectorsPerCluster
    s[13] = spc;
    // reservedSectors
    le16(&mut s, 14, RESERVED_SECTORS as u16);
    // numFATs
    s[16] = NUM_FATS;
    // rootEntryCount = 0 (FAT32)
    le16(&mut s, 17, 0);
    // totalSectors16 = 0 (FAT32 uses totalSectors32)
    le16(&mut s, 19, 0);
    // media = fixed disk
    s[21] = 0xF8;
    // fatSize16 = 0 (FAT32 uses fatSize32)
    le16(&mut s, 22, 0);
    // sectorsPerTrack
    le16(&mut s, 24, 63);
    // numHeads
    le16(&mut s, 26, 255);
    // hiddenSectors
    le32(&mut s, 28, 0);
    // totalSectors32
    le32(&mut s, 32, block_count as u32);

    // -- FAT32 extended BPB (offset 36) --
    // fatSize32
    le32(&mut s, 36, fat_size);
    // extFlags
    le16(&mut s, 40, 0);
    // fsVersion
    le16(&mut s, 42, 0);
    // rootCluster = 2
    le32(&mut s, 44, 2);
    // fsInfo sector = 1
    le16(&mut s, 48, 1);
    // backupBootSector = 6
    le16(&mut s, 50, 6);
    // reserved (52..64) = 0 (already)
    // driveNumber
    s[64] = 0x80;
    // reserved1 = 0 (s[65])
    // bootSignature
    s[66] = 0x29;
    // volumeId (arbitrary)
    le32(&mut s, 67, 0x12345678);
    // volumeLabel
    s[71..82].copy_from_slice(b"NO NAME    ");
    // fsType
    s[82..90].copy_from_slice(b"FAT32   ");

    // -- MBR partition table (offset 446) --
    // embedded-sdmmc's open_volume() reads sector 0 as an MBR and inspects the
    // partition table. With a pure superfloppy (no partition table), it sees
    // type=0x00 and rejects the volume. We embed a single partition entry
    // covering the whole disk, starting at LBA 0, so the FAT32 VBR at sector 0
    // also serves as the partition's boot record. The BPB fields (offset 0-89)
    // and the partition table (offset 446-509) occupy distinct regions of the
    // 512-byte sector and do not overlap.
    //
    // Partition entry 0 (offset 446, 16 bytes):
    //   status         = 0x80 (active/bootable)
    //   CHS start      = 0x00 0x01 0x01 (conventional LBA-mode placeholder)
    //   type           = 0x0C (FAT32 with LBA addressing)
    //   CHS end        = 0xFE 0xFF 0xFF (LBA-only placeholder)
    //   LBA start      = 0
    //   LBA size       = block_count
    s[446] = 0x80;
    s[447] = 0x00;
    s[448] = 0x01;
    s[449] = 0x01;
    s[450] = 0x0C;
    s[451] = 0xFE;
    s[452] = 0xFF;
    s[453] = 0xFF;
    le32(&mut s, 454, 0);
    le32(&mut s, 458, block_count as u32);
    // Partition entries 1-3 remain zero (unused)

    // Sector signature (serves as both MBR and FAT32 VBR signature)
    s[510] = 0x55;
    s[511] = 0xAA;

    s
}

fn build_fsinfo() -> [u8; SECTOR_SIZE] {
    let mut s = [0u8; SECTOR_SIZE];

    // leadSig
    le32(&mut s, 0, 0x41615252);
    // reserved1[480] = 0 (already)
    // strucSig
    le32(&mut s, 484, 0x61417272);
    // freeCount = unknown
    le32(&mut s, 488, 0xFFFFFFFF);
    // nxtFree = 3 (first usable cluster after root dir)
    le32(&mut s, 492, 3);
    // reserved2[12] = 0 (already)
    // trailSig = 0xAA550000
    le32(&mut s, 508, 0xAA550000);

    s
}

fn build_fat_first_sector() -> [u8; SECTOR_SIZE] {
    let mut s = [0u8; SECTOR_SIZE];

    // FAT[0] = media byte | 0xFFFFFF00
    le32(&mut s, 0, 0xF8FFFFFF);
    // FAT[1] = end-of-chain for cluster 1
    le32(&mut s, 4, 0xFFFFFFFF);
    // FAT[2] = end-of-chain for root directory cluster
    le32(&mut s, 8, 0x0FFFFFFF);

    s
}

/// Write a FAT32 filesystem structure to the block device.
///
/// Writes boot sector, FSInfo, backup boot sector, FAT1, and FAT2 first sectors,
/// then flushes. Does not mount the volume.
pub fn format_volume(blk: &IpcBlockDevice) -> Result<(), BlockError> {
    let block_count = blk.block_count();
    let spc = sectors_per_cluster(block_count);
    let fat_size = compute_fat_size(block_count, spc);

    log::debug!(
        "Formatting FAT32: {} MiB, spc={}, fat_sectors={}",
        block_count / 2048,
        spc,
        fat_size
    );

    let boot = build_boot_sector(block_count, spc, fat_size);
    let fsinfo = build_fsinfo();
    let fat = build_fat_first_sector();

    // Sector 0: boot sector
    blk.write_raw_sector(0, &boot)?;
    // Sector 1: FSInfo
    blk.write_raw_sector(1, &fsinfo)?;
    // Sector 6: backup boot sector
    blk.write_raw_sector(6, &boot)?;
    // FAT1 first sector
    blk.write_raw_sector(RESERVED_SECTORS as u64, &fat)?;
    // FAT2 first sector
    blk.write_raw_sector(RESERVED_SECTORS as u64 + fat_size as u64, &fat)?;

    blk.sync()?;

    log::debug!("Format complete");
    Ok(())
}
