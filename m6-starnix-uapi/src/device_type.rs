// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2021 The Fuchsia Authors. BSD license.

use core::fmt;
use core::ops::Range;

pub const MEM_MAJOR: u32 = 1;
pub const TTY_MAJOR: u32 = 4;
pub const TTY_ALT_MAJOR: u32 = 5;
pub const LOOP_MAJOR: u32 = 7;
pub const MISC_MAJOR: u32 = 10;
pub const INPUT_MAJOR: u32 = 13;
pub const FB_MAJOR: u32 = 29;

// These minor device numbers in the MISC major device appear to be dynamically allocated.
pub const MISC_DYNANIC_MINOR_RANGE: Range<u32> = 52..128;

pub const DYN_MAJOR_RANGE: Range<u32> = 234..252;

pub const MMC_BLOCK_DEVICE_MAJOR: u32 = 179;

pub const ZRAM_MAJOR: u32 = 252;
pub const DEVICE_MAPPER_MAJOR: u32 = 254;
pub const BLOCK_EXTENDED_MAJOR: u32 = 259;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DeviceType(u64);

impl DeviceType {
    pub const NONE: DeviceType = DeviceType(0);

    // MEM
    pub const NULL: DeviceType = DeviceType::new(MEM_MAJOR, 3);
    pub const ZERO: DeviceType = DeviceType::new(MEM_MAJOR, 5);
    pub const FULL: DeviceType = DeviceType::new(MEM_MAJOR, 7);
    pub const RANDOM: DeviceType = DeviceType::new(MEM_MAJOR, 8);
    pub const URANDOM: DeviceType = DeviceType::new(MEM_MAJOR, 9);
    pub const KMSG: DeviceType = DeviceType::new(MEM_MAJOR, 11);

    // TTY_ALT
    pub const TTY: DeviceType = DeviceType::new(TTY_ALT_MAJOR, 0);
    pub const PTMX: DeviceType = DeviceType::new(TTY_ALT_MAJOR, 2);

    // MISC
    pub const HW_RANDOM: DeviceType = DeviceType::new(MISC_MAJOR, 183);
    pub const UINPUT: DeviceType = DeviceType::new(MISC_MAJOR, 223);
    pub const FUSE: DeviceType = DeviceType::new(MISC_MAJOR, 229);
    pub const DEVICE_MAPPER: DeviceType = DeviceType::new(MISC_MAJOR, 236);
    pub const LOOP_CONTROL: DeviceType = DeviceType::new(MISC_MAJOR, 237);

    // Frame buffer
    pub const FB0: DeviceType = DeviceType::new(FB_MAJOR, 0);

    // TUN
    pub const TUN: DeviceType = DeviceType::new(MISC_MAJOR, 200);

    // Block Devices
    pub const MMCBLK0: DeviceType = DeviceType::new(MMC_BLOCK_DEVICE_MAJOR, 0);

    pub const fn new(major: u32, minor: u32) -> DeviceType {
        // This encoding is part of the Linux UAPI. The encoded value is
        // returned to userspace in the stat struct.
        // See <https://man7.org/linux/man-pages/man3/makedev.3.html>.
        DeviceType(
            (((major & 0xfffff000) as u64) << 32)
                | (((major & 0xfff) as u64) << 8)
                | (((minor & 0xffffff00) as u64) << 12)
                | ((minor & 0xff) as u64),
        )
    }

    pub const fn new_range(major: u32, minor: Range<u32>) -> Range<DeviceType> {
        Self::new(major, minor.start)..Self::new(major, minor.end)
    }

    pub const fn from_bits(dev: u64) -> DeviceType {
        DeviceType(dev)
    }

    pub const fn bits(&self) -> u64 {
        self.0
    }

    pub fn next_minor(&self) -> Option<DeviceType> {
        self.minor()
            .checked_add(1)
            .map(|minor| DeviceType::new(self.major(), minor))
    }

    pub const fn major(&self) -> u32 {
        ((self.0 >> 32 & 0xfffff000) | ((self.0 >> 8) & 0xfff)) as u32
    }

    pub const fn minor(&self) -> u32 {
        ((self.0 >> 12 & 0xffffff00) | (self.0 & 0xff)) as u32
    }
}

impl fmt::Display for DeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}:{}", self.major(), self.minor())
    }
}

impl core::cmp::PartialOrd for DeviceType {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl core::cmp::Ord for DeviceType {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.major(), self.minor()).cmp(&(other.major(), other.minor()))
    }
}
