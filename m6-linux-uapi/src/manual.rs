// Forked from Fuchsia's linux_uapi, adapted for no_std.
// Original: Copyright 2024 The Fuchsia Authors. BSD license.

use crate::{__IncompleteArrayField, __u8, __u32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[repr(C)]
#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct fscrypt_key_specifier {
    pub type_: __u32,
    pub __reserved: __u32,
    pub u: fscrypt_key_specifier__bindgen_ty_1,
}

#[repr(C)]
#[derive(Copy, Clone, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub union fscrypt_key_specifier__bindgen_ty_1 {
    pub __reserved: [__u8; 32usize],
    pub descriptor: fscrypt_descriptor,
    pub identifier: fscrypt_identifier,
}

#[repr(C)]
#[derive(Copy, Clone, Default, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct fscrypt_descriptor {
    pub value: [__u8; 8usize],
    pub __bindgen_padding_0: [u8; 24usize],
}

#[repr(C)]
#[derive(Copy, Clone, Default, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct fscrypt_identifier {
    pub value: [__u8; 16usize],
    pub __bindgen_padding_0: [u8; 16usize],
}

impl Default for fscrypt_key_specifier__bindgen_ty_1 {
    fn default() -> Self {
        let mut s = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: this is what bindgen would generate — zeroing a repr(C) union
        unsafe {
            core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

impl Default for fscrypt_key_specifier {
    fn default() -> Self {
        let mut s = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: this is what bindgen would generate — zeroing a repr(C) struct
        unsafe {
            core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

#[repr(C)]
#[derive(Clone, FromBytes, Immutable, KnownLayout, IntoBytes)]
pub struct fscrypt_add_key_arg {
    pub key_spec: fscrypt_key_specifier,
    pub raw_size: __u32,
    pub key_id: __u32,
    pub __reserved: [__u32; 7usize],
    pub __flags: __u32,
    pub raw: __IncompleteArrayField<__u8>,
}

impl Default for fscrypt_add_key_arg {
    fn default() -> Self {
        let mut s = core::mem::MaybeUninit::<Self>::uninit();
        // SAFETY: this is what bindgen would generate — zeroing a repr(C) struct
        unsafe {
            core::ptr::write_bytes(s.as_mut_ptr(), 0, 1);
            s.assume_init()
        }
    }
}

crate::check_same_layout! {
    crate::statfs64 = crate::statfs {
        f_type => f_type,
        f_bsize => f_bsize,
        f_blocks => f_blocks,
        f_bfree => f_bfree,
        f_bavail => f_bavail,
        f_files => f_files,
        f_ffree => f_ffree,
        f_fsid => f_fsid,
        f_namelen => f_namelen,
        f_frsize => f_frsize,
        f_flags => f_flags,
    }
}

macro_rules! impl_debug {
    {} => {};
    {
        ,
        $($token:tt)*
    } => {
        impl_debug! { $($token)* }
    };
    {
        $name:ident
        $($token:tt)*
    } => {
        impl core::fmt::Debug for crate::$name {
            fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                fmt.debug_struct(core::any::type_name::<Self>()).finish()
            }
        }
        impl core::fmt::Debug for crate::arch32::$name {
            fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
                fmt.debug_struct(core::any::type_name::<Self>()).finish()
            }
        }
        impl_debug! { $($token)* }
    };
}

impl_debug! {
    fuse_open_out__bindgen_ty_1,
    fuse_in_header__bindgen_ty_1,
}

// -- arch32 (32-bit ABI) ↔ 64-bit struct conversions.
//
// Upstream linux_uapi generates these in its build; the M6 hand-port invokes the
// `arch_translate_data!` macro for the structs the syscall layer marshals via
// `MappingMultiArchUserRef`. Integer-only/nested-struct conversions are listed
// here; pointer-bearing structs (iovec, sigaltstack, …) additionally need the
// uaddr↔uaddr32 primitives and are added with those.
crate::arch_translate_data! {
    BidiFrom<timespec> {
        tv_sec,
        tv_nsec,
    }
    BidiFrom<timeval> {
        tv_sec,
        tv_usec,
    }
    BidiFrom<itimerspec> {
        it_interval,
        it_value,
    }
    BidiFrom<itimerval> {
        it_interval,
        it_value,
    }
    BidiFrom<rusage> {
        ru_utime,
        ru_stime,
        ru_maxrss,
        ru_ixrss,
        ru_idrss,
        ru_isrss,
        ru_minflt,
        ru_majflt,
        ru_nswap,
        ru_inblock,
        ru_oublock,
        ru_msgsnd,
        ru_msgrcv,
        ru_nsignals,
        ru_nvcsw,
        ru_nivcsw,
    }
    BidiFrom<sock_filter> {
        code,
        jt,
        jf,
        k,
    }
    BidiFrom<flock> {
        l_type,
        l_whence,
        l_start,
        l_len,
        l_pid,
    }
    BidiFrom<flock64> {
        l_type,
        l_whence,
        l_start,
        l_len,
        l_pid,
    }
    BidiFrom<__kernel_fsid_t> {
        val,
    }
    BidiFrom<sigaltstack> {
        ss_sp,
        ss_flags,
        ss_size,
    }
    BidiFrom<__kernel_sigaction> {
        sa_handler,
        sa_mask,
        sa_flags,
        sa_restorer,
    }
    // cmsg_len is size_t (u64 on 64-bit, u32 on arch32); cmsg_level/cmsg_type are
    // c_uint on both. The 64→32 direction narrows cmsg_len fallibly (TryFrom);
    // 32→64 widens infallibly. Used by MappingMultiArchUserRef<cmsghdr, …>.
    BidiFrom<cmsghdr> {
        cmsg_len,
        cmsg_level,
        cmsg_type,
    }
    // ucred is pid/uid/gid (all u32 on both ABIs) — a plain symmetric conversion.
    BidiFrom<ucred> {
        pid,
        uid,
        gid,
    }
}

// iovec lacks a `Default` derive (so the `..Default::default()` macro form can't
// be used); both fields are listed explicitly here. iov_base uses the existing
// uaddr↔uaddr32 conversions; iov_len is size_t (u64↔u32).
impl From<crate::arch32::iovec> for crate::iovec {
    fn from(src: crate::arch32::iovec) -> Self {
        Self { iov_base: src.iov_base.into(), iov_len: src.iov_len.into() }
    }
}

impl TryFrom<crate::iovec> for crate::arch32::iovec {
    type Error = ();
    fn try_from(src: crate::iovec) -> Result<Self, ()> {
        Ok(Self {
            iov_base: src.iov_base.try_into().map_err(|_| ())?,
            iov_len: src.iov_len.try_into().map_err(|_| ())?,
        })
    }
}

// rlimit's rlim_t is u64 on 64-bit, u32 on arch32. Upstream uses infallible
// `From` (not TryFrom) here, saturating to the 32-bit "infinity" (u32::MAX) on
// overflow. Hand-written (not via the macro) so it doesn't collide with the
// blanket `TryFrom`-from-`From`.
impl From<crate::arch32::rlimit> for crate::rlimit {
    fn from(src: crate::arch32::rlimit) -> Self {
        Self { rlim_cur: src.rlim_cur.into(), rlim_max: src.rlim_max.into() }
    }
}

impl From<crate::rlimit> for crate::arch32::rlimit {
    fn from(src: crate::rlimit) -> Self {
        let clamp = |v: u64| -> u32 { v.try_into().unwrap_or(u32::MAX) };
        Self { rlim_cur: clamp(src.rlim_cur), rlim_max: clamp(src.rlim_max) }
    }
}

// -- Explicit-field 64↔arch32 struct conversions.
//
// These structs reorder/rename fields (or only need the write/64→32 direction)
// so they can't go through the field-name-symmetric `arch_translate_data!`.
// Ported from upstream linux_uapi `arm_manual.rs`.
crate::translate_data! {
    // `stat` (64-bit) → `arch32::stat64`. The 32-bit ABI splits the inode
    // number across `st_ino` (the canonical 64-bit field) and the legacy
    // `__st_ino` (saturating to 0 on overflow, matching upstream).
    TryFrom<crate::stat> for crate::arch32::stat64 {
        st_dev = st_dev;
        __st_ino = st_ino(0);
        st_mode = st_mode;
        st_nlink = st_nlink;
        st_uid = st_uid;
        st_gid = st_gid;
        st_rdev = st_rdev;
        st_size = st_size;
        st_blksize = st_blksize;
        st_blocks = st_blocks;
        st_atime = st_atime;
        st_atime_nsec = st_atime_nsec;
        st_mtime = st_mtime;
        st_mtime_nsec = st_mtime_nsec;
        st_ctime = st_ctime;
        st_ctime_nsec = st_ctime_nsec;
        st_ino = st_ino;
        ..Default::default()
    }

    // `statfs` (64-bit) → `arch32::statfs` (all-u32 fields; narrowing).
    TryFrom<crate::statfs> for crate::arch32::statfs {
        f_type = f_type;
        f_bsize = f_bsize;
        f_blocks = f_blocks;
        f_bfree = f_bfree;
        f_bavail = f_bavail;
        f_files = f_files;
        f_ffree = f_ffree;
        f_fsid = f_fsid;
        f_namelen = f_namelen;
        f_frsize = f_frsize;
        f_flags = f_flags;
        ..Default::default()
    }

    // `statfs` (64-bit) → `arch32::statfs64` (64-bit block counts, u32 metadata).
    TryFrom<crate::statfs> for crate::arch32::statfs64 {
        f_type = f_type;
        f_bsize = f_bsize;
        f_blocks = f_blocks;
        f_bfree = f_bfree;
        f_bavail = f_bavail;
        f_files = f_files;
        f_ffree = f_ffree;
        f_fsid = f_fsid;
        f_namelen = f_namelen;
        f_frsize = f_frsize;
        f_flags = f_flags;
        ..Default::default()
    }

    // `arch32::sigaction64` ↔ `__kernel_sigaction` (identical field set, but the
    // arch32 variant carries a `sigset64_t` mask, so the mask must convert).
    BidiTryFrom<crate::arch32::sigaction64, crate::__kernel_sigaction> {
        sa_handler = sa_handler;
        sa_mask = sa_mask;
        sa_flags = sa_flags;
        sa_restorer = sa_restorer;
    }
}

// -- sigset conversions.
//
// 64-bit `sigset_t` is `{ sig: [u64; 1] }`; the arch32 signal mask is a bare
// `u32` (arch32 `sigset_t`), and the arch32 "64-bit-compat" mask is
// `arch32::sigset64_t { sig: [u32; 1] }`. These are used by the
// `__kernel_sigaction`/`sigaction64` conversions above and by the arch32
// signal-frame marshalling.
impl TryFrom<crate::sigset_t> for u32 {
    type Error = ();
    fn try_from(sigset: crate::sigset_t) -> Result<Self, ()> {
        sigset.sig[0].try_into().map_err(|_| ())
    }
}

impl From<u32> for crate::sigset_t {
    fn from(sigset: u32) -> Self {
        crate::sigset_t { sig: [sigset.into()] }
    }
}

impl From<crate::arch32::sigset64_t> for crate::sigset_t {
    fn from(sigset: crate::arch32::sigset64_t) -> Self {
        Self { sig: [sigset.sig[0].into()] }
    }
}

impl From<crate::sigset_t> for crate::arch32::sigset64_t {
    fn from(sigset: crate::sigset_t) -> Self {
        Self { sig: [sigset.sig[0] as u32] }
    }
}

// -- sigval (a union; convert by the single opaque blob member).
//
// 64-bit `sigval` is an 8-byte opaque blob; arch32 `sigval` is a `u32`.
impl From<crate::arch32::sigval> for crate::sigval {
    fn from(sigval: crate::arch32::sigval) -> Self {
        // SAFETY: the union has a single field, so any bit-pattern is valid.
        let blob = unsafe { sigval._bindgen_opaque_blob };
        let blob_as_u64: u64 = blob.into();
        Self { _bindgen_opaque_blob: zerocopy::transmute!(blob_as_u64) }
    }
}

impl TryFrom<crate::sigval> for crate::arch32::sigval {
    type Error = ();
    fn try_from(sigval: crate::sigval) -> Result<Self, ()> {
        // SAFETY: the union has a single field, so any bit-pattern is valid.
        let blob = unsafe { sigval._bindgen_opaque_blob };
        let blob_as_u64: u64 = zerocopy::transmute!(blob);
        Ok(Self { _bindgen_opaque_blob: blob_as_u64.try_into().map_err(|_| ())? })
    }
}

// -- sigevent (pointer-bearing union member; convert by the active notify kind).
impl From<crate::arch32::sigevent> for crate::sigevent {
    fn from(sigevent: crate::arch32::sigevent) -> Self {
        let mut _sigev_un = crate::sigevent__bindgen_ty_1::default();
        match sigevent.sigev_notify as u32 {
            // SAFETY: the union member read matches the `sigev_notify` tag.
            crate::SIGEV_THREAD_ID => unsafe {
                _sigev_un._tid = sigevent._sigev_un._tid.into();
            },
            // SAFETY: the union member read matches the `sigev_notify` tag.
            crate::SIGEV_THREAD => unsafe {
                _sigev_un._sigev_thread = crate::sigevent__bindgen_ty_1__bindgen_ty_1 {
                    _function: sigevent._sigev_un._sigev_thread._function.into(),
                    _attribute: sigevent._sigev_un._sigev_thread._attribute.into(),
                };
            },
            _ => {}
        }
        Self {
            sigev_value: sigevent.sigev_value.into(),
            sigev_signo: sigevent.sigev_signo.into(),
            sigev_notify: sigevent.sigev_notify.into(),
            _sigev_un,
        }
    }
}

impl TryFrom<crate::sigevent> for crate::arch32::sigevent {
    type Error = ();
    fn try_from(sigevent: crate::sigevent) -> Result<Self, ()> {
        let mut _sigev_un = crate::arch32::sigevent__bindgen_ty_1::default();
        match sigevent.sigev_notify as u32 {
            // SAFETY: the union member read matches the `sigev_notify` tag.
            crate::SIGEV_THREAD_ID => unsafe {
                _sigev_un._tid = sigevent._sigev_un._tid.try_into().map_err(|_| ())?;
            },
            // SAFETY: the union member read matches the `sigev_notify` tag.
            crate::SIGEV_THREAD => unsafe {
                _sigev_un._sigev_thread = crate::arch32::sigevent__bindgen_ty_1__bindgen_ty_1 {
                    _function: sigevent
                        ._sigev_un
                        ._sigev_thread
                        ._function
                        .try_into()
                        .map_err(|_| ())?,
                    _attribute: sigevent
                        ._sigev_un
                        ._sigev_thread
                        ._attribute
                        .try_into()
                        .map_err(|_| ())?,
                };
            },
            _ => {}
        }
        Ok(Self {
            sigev_value: sigevent.sigev_value.try_into().map_err(|_| ())?,
            sigev_signo: sigevent.sigev_signo.try_into().map_err(|_| ())?,
            sigev_notify: sigevent.sigev_notify.try_into().map_err(|_| ())?,
            _sigev_un,
        })
    }
}

// -- sysinfo (has padding + an incomplete-array tail; field-by-field).
impl From<crate::arch32::sysinfo> for crate::sysinfo {
    fn from(sysinfo: crate::arch32::sysinfo) -> Self {
        Self {
            uptime: sysinfo.uptime.into(),
            loads: sysinfo.loads.map(u64::from),
            totalram: sysinfo.totalram.into(),
            freeram: sysinfo.freeram.into(),
            sharedram: sysinfo.sharedram.into(),
            bufferram: sysinfo.bufferram.into(),
            totalswap: sysinfo.totalswap.into(),
            freeswap: sysinfo.freeswap.into(),
            procs: sysinfo.procs,
            pad: sysinfo.pad,
            totalhigh: sysinfo.totalhigh.into(),
            freehigh: sysinfo.freehigh.into(),
            mem_unit: sysinfo.mem_unit,
            ..Default::default()
        }
    }
}

impl TryFrom<crate::sysinfo> for crate::arch32::sysinfo {
    type Error = ();
    fn try_from(sysinfo: crate::sysinfo) -> Result<Self, ()> {
        let [v1, v2, v3] = sysinfo.loads;
        let loads = [
            u32::try_from(v1).map_err(|_| ())?,
            u32::try_from(v2).map_err(|_| ())?,
            u32::try_from(v3).map_err(|_| ())?,
        ];
        Ok(Self {
            uptime: sysinfo.uptime.try_into().map_err(|_| ())?,
            loads,
            totalram: sysinfo.totalram.try_into().map_err(|_| ())?,
            freeram: sysinfo.freeram.try_into().map_err(|_| ())?,
            sharedram: sysinfo.sharedram.try_into().map_err(|_| ())?,
            bufferram: sysinfo.bufferram.try_into().map_err(|_| ())?,
            totalswap: sysinfo.totalswap.try_into().map_err(|_| ())?,
            freeswap: sysinfo.freeswap.try_into().map_err(|_| ())?,
            procs: sysinfo.procs,
            pad: sysinfo.pad,
            totalhigh: sysinfo.totalhigh.try_into().map_err(|_| ())?,
            freehigh: sysinfo.freehigh.try_into().map_err(|_| ())?,
            mem_unit: sysinfo.mem_unit,
            ..Default::default()
        })
    }
}
