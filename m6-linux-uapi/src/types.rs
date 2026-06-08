// Forked from Fuchsia's linux_uapi, adapted for no_std.
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

pub type c_void = core::ffi::c_void;

// char is unsigned on ARM64
pub type c_char = u8;

pub type c_schar = i8;
pub type c_uchar = u8;
pub type c_short = i16;
pub type c_ushort = u16;
pub type c_int = i32;
pub type c_uint = u32;
pub type c_long = i64;
pub type c_ulong = u64;
pub type c_longlong = i64;
pub type c_ulonglong = u64;

// 32-bit ARM type aliases (for arch32 interop)
#[allow(dead_code)]
pub mod arch32 {
    pub type c_char = u8;
    pub type c_schar = i8;
    pub type c_uchar = u8;
    pub type c_short = i16;
    pub type c_ushort = u16;
    pub type c_int = i32;
    pub type c_uint = u32;
    pub type c_long = i32;
    pub type c_ulong = u32;
    pub type c_longlong = i64;
    pub type c_ulonglong = u64;
}
