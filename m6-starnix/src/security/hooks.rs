// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// TODO(https://github.com/rust-lang/rust/issues/39371): remove
#![allow(non_upper_case_globals)]

//! Permissive LSM hook layer.
//!
//! M6 enforces a capability-based security model and never loads an SELinux
//! policy, so every hook here returns its "allowed" default. The signatures are
//! preserved verbatim so that the rest of the kernel can call them unchanged.
//! Discretionary (POSIX) capability checks and YAMA ptrace restrictions are
//! still applied via `common_cap` and `yama`, since those are policy-independent.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use super::{
    Auditable, BinderConnectionState, FileObjectState, FileSystemState, KernelState,
    ResolvedElfState, common_cap, yama,
};
use crate::mm_ref::{Mapping, MappingOptions, ProtectionFlags};
use crate::task::{CurrentTask, Kernel, Task};
use crate::vfs::fs_args::MountParams;
use crate::vfs::{
    DirEntryHandle, FileHandle, FileObject, FileSystem, FileSystemHandle, FileSystemOps, FsNode,
    FsStr, FsString, Mount, NamespaceNode, OutputBuffer, ValueOrSize, XattrOp,
};
#[cfg(feature = "fuchsia")] use ebpf::MapFlags;
use linux_uapi::{
    perf_type_id, perf_type_id_PERF_TYPE_BREAKPOINT, perf_type_id_PERF_TYPE_HARDWARE,
    perf_type_id_PERF_TYPE_HW_CACHE, perf_type_id_PERF_TYPE_RAW, perf_type_id_PERF_TYPE_SOFTWARE,
    perf_type_id_PERF_TYPE_TRACEPOINT,
};
use starnix_sync::{FileOpsCore, LockEqualOrBefore, Locked, Unlocked};
use starnix_types::ownership::TempRef;
use starnix_uapi::auth::{Credentials, PtraceAccessMode};
use starnix_uapi::device_type::DeviceType;
use starnix_uapi::errors::Errno;
use starnix_uapi::file_mode::{Access, FileMode};
use starnix_uapi::mount_flags::MountFlags;
use starnix_uapi::open_flags::OpenFlags;
use starnix_uapi::selinux::TaskAttrs;
use starnix_uapi::signals::Signal;
use starnix_uapi::syslog::SyslogAction;
use starnix_uapi::unmount_flags::UnmountFlags;
use starnix_uapi::user_address::UserAddress;
#[cfg(feature = "fuchsia")] use starnix_uapi::bpf_cmd;
use starnix_uapi::{error, rlimit};
use m6_starnix_std::ops::Range;
use m6_starnix_std::sync::Arc;
use syncio::zxio_node_attr_has_t;
use zerocopy::FromBytes;

// -- Placeholder SELinux types
//
// The real SELinux policy engine (`selinux` crate) was never forked. These
// trivial stand-ins preserve the signatures of hooks that historically referred
// to the policy engine. They carry no state and are never inspected.

/// Stub for the SELinux mount options associated with a filesystem.
#[derive(Clone, Debug, Default)]
pub struct FileSystemMountOptions;

/// Stub for the SELinux policy server handle.
#[derive(Debug, Default)]
pub struct SecurityServer;

/// Stub for an SELinux administration-API permission.
#[derive(Clone, Copy, Debug)]
pub enum SecurityPermission {
    /// Placeholder variant; the permissive layer never checks permissions.
    None,
}

/// Used to return an extended attribute name and value to apply to a [`crate::vfs::FsNode`].
pub struct FsNodeSecurityXattr {
    pub name: &'static FsStr,
    pub value: FsString,
}

macro_rules! track_hook_duration {
    ($cname:literal) => {
        starnix_logging::trace_duration!(
            starnix_logging::CATEGORY_STARNIX_SECURITY,
            $cname
        );
    };
}

bitflags::bitflags! {
    /// The flags about which permissions should be checked when opening an FsNode. Used in the
    /// `fs_node_permission()` hook.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PermissionFlags: u32 {
        const EXEC = 1 as u32;
        const WRITE = 2 as u32;
        const READ = 4 as u32;
        const APPEND = 8 as u32;

        // Internal flag used to indicate that the check is being made on behalf of userspace e.g.
        // via the `access()` syscall.
        const ACCESS = 16 as u32;

        // TODO: https://fxbug.dev/455782510 - Remove this once all fs_node_permission() calls are
        // enforced.
        const FOR_OPEN = 32 as u32;
    }
}

impl PermissionFlags {
    pub fn as_access(&self) -> Access {
        let mut access = Access::empty();
        if self.contains(PermissionFlags::READ) {
            access |= Access::READ;
        }
        if self.contains(PermissionFlags::WRITE) {
            // `APPEND` only modifies the behaviour of `WRITE` if set, so it is sufficient to only
            // consider whether `WRITE` is set, to calculate the `Access` flags.
            access |= Access::WRITE;
        }
        if self.contains(PermissionFlags::EXEC) {
            access |= Access::EXEC;
        }
        access
    }
}

impl From<Access> for PermissionFlags {
    fn from(access: Access) -> Self {
        // Note that `Access` doesn't have an `append` bit.
        let mut permissions = PermissionFlags::empty();
        if access.contains(Access::READ) {
            permissions |= PermissionFlags::READ;
        }
        if access.contains(Access::WRITE) {
            permissions |= PermissionFlags::WRITE;
        }
        if access.contains(Access::EXEC) {
            permissions |= PermissionFlags::EXEC;
        }
        permissions
    }
}

impl From<ProtectionFlags> for PermissionFlags {
    fn from(protection_flags: ProtectionFlags) -> Self {
        let mut flags = PermissionFlags::empty();
        if protection_flags.contains(ProtectionFlags::READ) {
            flags |= PermissionFlags::READ;
        }
        if protection_flags.contains(ProtectionFlags::WRITE) {
            flags |= PermissionFlags::WRITE;
        }
        if protection_flags.contains(ProtectionFlags::EXEC) {
            flags |= PermissionFlags::EXEC;
        }
        flags
    }
}

impl From<OpenFlags> for PermissionFlags {
    fn from(flags: OpenFlags) -> Self {
        let mut permissions = PermissionFlags::empty();
        if flags.can_read() {
            permissions |= PermissionFlags::READ;
        }
        if flags.can_write() {
            permissions |= PermissionFlags::WRITE;
            if flags.contains(OpenFlags::APPEND) {
                permissions |= PermissionFlags::APPEND;
            }
        }
        permissions
    }
}

#[cfg(feature = "fuchsia")]
impl From<MapFlags> for PermissionFlags {
    fn from(bpf_flags: MapFlags) -> Self {
        if bpf_flags.contains(MapFlags::SyscallReadOnly) {
            PermissionFlags::READ
        } else if bpf_flags.contains(MapFlags::SyscallWriteOnly) {
            PermissionFlags::WRITE
        } else {
            PermissionFlags::READ | PermissionFlags::WRITE
        }
    }
}

/// The flags about the PerfEvent types.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PerfEventType {
    Hardware,
    Software,
    Tracepoint,
    Raw,
    HwCache,
    Breakpoint,
}

// TODO(https://github.com/rust-lang/rust/issues/39371): remove
#[allow(non_upper_case_globals)]
impl TryFrom<perf_type_id> for PerfEventType {
    type Error = Errno;

    fn try_from(type_id: perf_type_id) -> Result<Self, Errno> {
        match type_id {
            perf_type_id_PERF_TYPE_HARDWARE => Ok(Self::Hardware),
            perf_type_id_PERF_TYPE_SOFTWARE => Ok(Self::Software),
            perf_type_id_PERF_TYPE_TRACEPOINT => Ok(Self::Tracepoint),
            perf_type_id_PERF_TYPE_RAW => Ok(Self::Raw),
            perf_type_id_PERF_TYPE_HW_CACHE => Ok(Self::HwCache),
            perf_type_id_PERF_TYPE_BREAKPOINT => Ok(Self::Breakpoint),
            _ => {
                return error!(ENOTSUP);
            }
        }
    }
}

/// The target task type. Used in the `check_perf_event_open_access` LSM hook.
pub enum TargetTaskType<'a> {
    /// Monitor all tasks/activities.
    AllTasks,
    /// Only monitor the current task.
    CurrentTask,
    /// Only monitor a specific task.
    Task(&'a Task),
}

/// Returns the security state structure for the kernel.
///
/// M6 has no LSM policy engine, so the returned state is always empty.
pub fn kernel_init_security(
    _enabled: bool,
    _options: String,
    _exceptions: Vec<String>,
    _inspect_node: &fuchsia_inspect::Node,
) -> KernelState {
    track_hook_duration!("security.hooks.kernel_init_security");
    KernelState
}

/// Checks whether the given `current_task` can become the binder context manager.
/// Corresponds to the `binder_set_context_mgr` hook.
pub fn binder_set_context_mgr(_current_task: &CurrentTask) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.binder_set_context_mgr");
    Ok(())
}

/// Checks whether the given `current_task` can perform a transaction to `target_task`.
/// Corresponds to the `binder_transaction` hook.
pub fn binder_transaction(
    _current_task: &CurrentTask,
    _target_task: &Task,
    _connection_state: &BinderConnectionState,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.binder_transaction");
    Ok(())
}

/// Checks whether the given `current_task` can transfer Binder objects to `target_task`.
/// Corresponds to the `binder_transfer_binder` hook.
pub fn binder_transfer_binder(
    _current_task: &CurrentTask,
    _target_task: &Task,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.binder_transfer_binder");
    Ok(())
}

/// Checks whether the given `receiving_task` can receive `file` in a Binder transaction.
/// Corresponds to the `binder_transfer_file` hook.
pub fn binder_transfer_file(
    _current_task: &CurrentTask,
    _receiving_task: &Task,
    _file: &FileObject,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.binder_transfer_file");
    Ok(())
}

/// Returns the serialized Security Context associated with the specified state.
/// If the state's SID cannot be resolved then None is returned.
pub fn binder_get_context(
    _current_task: &CurrentTask,
    _connection_state: &BinderConnectionState,
) -> Option<Vec<u8>> {
    track_hook_duration!("security.hooks.binder_get_context");
    None
}

/// Consumes the mount options from the supplied `MountParams` and returns the security mount
/// options for the given `MountParams`.
/// Corresponds to the `sb_eat_lsm_opts` hook.
pub fn sb_eat_lsm_opts(
    _kernel: &Kernel,
    _mount_params: &mut MountParams,
) -> Result<FileSystemMountOptions, Errno> {
    track_hook_duration!("security.hooks.sb_eat_lsm_opts");
    Ok(FileSystemMountOptions::default())
}

/// Returns security state to associate with a filesystem based on the supplied mount options.
/// This sits somewhere between `fs_context_parse_param()` and `sb_set_mnt_opts()` in function.
pub fn file_system_init_security(
    _mount_options: &FileSystemMountOptions,
    _ops: &dyn FileSystemOps,
) -> Result<FileSystemState, Errno> {
    track_hook_duration!("security.hooks.file_system_init_security");
    Ok(FileSystemState::default())
}

/// Gives the hooks subsystem an opportunity to note that the new `file_system` needs labeling.
// TODO: https://fxbug.dev/366405587 - Merge this logic into `file_system_resolve_security()` and
// remove this extra hook.
pub fn file_system_post_init_security(_kernel: &Kernel, _file_system: &FileSystemHandle) {
    track_hook_duration!("security.hooks.file_system_post_init_security");
}

/// Resolves the labeling scheme and arguments for the `file_system`, based on the loaded policy.
pub fn file_system_resolve_security<L>(
    _locked: &mut Locked<L>,
    _current_task: &CurrentTask,
    _file_system: &FileSystemHandle,
) -> Result<(), Errno>
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.file_system_resolve_security");
    Ok(())
}

/// Checks whether the `current_task` is allowed to mmap `file` or memory using the given
/// [`ProtectionFlags`] and [`MappingOptions`].
/// Corresponds to the `mmap_file()` LSM hook.
pub fn mmap_file(
    _current_task: &CurrentTask,
    _file: Option<&FileHandle>,
    _protection_flags: ProtectionFlags,
    _options: MappingOptions,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.mmap_file");
    Ok(())
}

/// Checks whether `current_task` is allowed to request setting the memory protection of
/// `mapping` to `prot`.
/// Corresponds to the `file_mprotect` LSM hook.
pub fn file_mprotect(
    _current_task: &CurrentTask,
    _range: &Range<UserAddress>,
    _mapping: &Mapping,
    _prot: ProtectionFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.file_mprotect");
    Ok(())
}

/// Checks whether the `current_task` has the specified `permission_flags` to the `file`.
/// Corresponds to the `file_permission()` LSM hook.
pub fn file_permission(
    _current_task: &CurrentTask,
    _file: &FileObject,
    _permission_flags: PermissionFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.file_permission");
    Ok(())
}

/// Called by the VFS to initialize the security state for an `FsNode` that is being linked at
/// `dir_entry`.
/// Corresponds to the `d_instantiate()` LSM hook.
pub fn fs_node_init_with_dentry<L>(
    _locked: &mut Locked<L>,
    _current_task: &CurrentTask,
    _dir_entry: &DirEntryHandle,
) -> Result<(), Errno>
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.fs_node_init_with_dentry");
    Ok(())
}

pub fn fs_node_init_with_dentry_no_xattr(
    _current_task: &CurrentTask,
    _dir_entry: &DirEntryHandle,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.fs_node_init_with_dentry_no_xattr");
    Ok(())
}

// Temporary work-around for lack of a `CurrentTask` during creation of `DirEntry`s for some initial
// file-systems.
// TODO: https://fxbug.dev/455771186 - Clean up with-DirEntry initialization and remove this.
pub fn fs_node_init_with_dentry_deferred(_kernel: &Kernel, _dir_entry: &DirEntryHandle) {
    track_hook_duration!("security.hooks.fs_node_init_with_dentry_no_xattr");
}

/// Applies the given label to the given node without checking any permissions.
/// Corresponds to the `inode_notifysecctx` LSM hook.
pub fn fs_node_notify_security_context(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
    _context: &FsStr,
) -> Result<(), Errno> {
    // With no LSM enabled there is no security context to notify.
    error!(ENOTSUP)
}

/// Called by file-system implementations when creating the `FsNode` for a new file.
/// Corresponds to the `inode_init_security()` LSM hook.
pub fn fs_node_init_on_create(
    _current_task: &CurrentTask,
    _new_node: &FsNode,
    _parent: &FsNode,
    _name: &FsStr,
) -> Result<Option<FsNodeSecurityXattr>, Errno> {
    track_hook_duration!("security.hooks.fs_node_init_on_create");
    Ok(None)
}

/// Called by specialist file-system implementations before creating a new `FsNode`, to obtain the
/// SID with which the code will be labeled, in advance.
/// Corresponds to the `dentry_create_files_as()` LSM hook.
pub fn dentry_create_files_as(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _new_node_mode: FileMode,
    _new_node_name: &FsStr,
    _new_creds: &mut Credentials,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.dentry_create_files_as");
    Ok(())
}

/// Called on creation of anonymous [`crate::vfs::FsNode`]s.
/// Corresponds to the `inode_init_security_anon()` LSM hook.
pub fn fs_node_init_anon(
    _current_task: &CurrentTask,
    _new_node: &FsNode,
    _node_type: &str,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.fs_node_init_anon");
    Ok(())
}

/// Validate that `current_task` has permission to create a regular file in the `parent` directory.
/// Corresponds to the `inode_create()` LSM hook.
pub fn check_fs_node_create_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _mode: FileMode,
    _name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_create_access");
    Ok(())
}

/// Validate that `current_task` has permission to create a symlink.
/// Corresponds to the `inode_symlink()` LSM hook.
pub fn check_fs_node_symlink_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _name: &FsStr,
    _old_path: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_symlink_access");
    Ok(())
}

/// Validate that `current_task` has permission to create a new directory.
/// Corresponds to the `inode_mkdir()` LSM hook.
pub fn check_fs_node_mkdir_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _mode: FileMode,
    _name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_mkdir_access");
    Ok(())
}

/// Validate that `current_task` has permission to create a new special file, socket or pipe.
/// Corresponds to the `inode_mknod()` LSM hook.
pub fn check_fs_node_mknod_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    mode: FileMode,
    _name: &FsStr,
    _device_id: DeviceType,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_mknod_access");
    assert!(!mode.is_reg());
    Ok(())
}

/// Validate that `current_task` has the permission to create a new hard link to a file.
/// Corresponds to the `inode_link()` LSM hook.
pub fn check_fs_node_link_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _child: &FsNode,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_link_access");
    Ok(())
}

/// Validate that `current_task` has the permission to remove a hard link to a file.
/// Corresponds to the `inode_unlink()` LSM hook.
pub fn check_fs_node_unlink_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _child: &FsNode,
    _name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_unlink_access");
    Ok(())
}

/// Validate that `current_task` has the permission to remove a directory.
/// Corresponds to the `inode_rmdir()` LSM hook.
pub fn check_fs_node_rmdir_access(
    _current_task: &CurrentTask,
    _parent: &FsNode,
    _child: &FsNode,
    _name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_rmdir_access");
    Ok(())
}

/// Checks whether the `current_task` can rename the file or directory `moving_node`.
/// Corresponds to the `inode_rename()` LSM hook.
pub fn check_fs_node_rename_access(
    _current_task: &CurrentTask,
    _old_parent: &FsNode,
    _moving_node: &FsNode,
    _new_parent: &FsNode,
    _replaced_node: Option<&FsNode>,
    _old_basename: &FsStr,
    _new_basename: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_rename_access");
    Ok(())
}

/// Checks whether the `current_task` can read the symbolic link in `fs_node`.
/// Corresponds to the `inode_readlink()` LSM hook.
pub fn check_fs_node_read_link_access(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_read_link_access");
    Ok(())
}

/// Checks whether the `current_task` can access an inode.
/// Corresponds to the `inode_permission()` LSM hook.
pub fn fs_node_permission(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
    _permission_flags: PermissionFlags,
    _audit_context: Auditable<'_>,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.fs_node_permission");
    Ok(())
}

/// Returns whether the `current_task` can receive `file` via a socket IPC.
/// Corresponds to the `file_receive()` LSM hook.
pub fn file_receive(_current_task: &CurrentTask, _file: &FileObject) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.file_receive");
    Ok(())
}

/// Returns the security state for a new file object created by `current_task`.
/// Corresponds to the `file_alloc_security()` LSM hook.
pub fn file_alloc_security(_current_task: &CurrentTask) -> FileObjectState {
    track_hook_duration!("security.hooks.file_alloc_security");
    FileObjectState::default()
}

/// Returns the security context to be assigned to a BinderConnection, based on the task that
/// creates it.
pub fn binder_connection_alloc(_current_task: &CurrentTask) -> BinderConnectionState {
    track_hook_duration!("security.hooks.binder_connection_alloc");
    BinderConnectionState::default()
}

/// Returns whether `current_task` can issue an ioctl to `file`.
/// Corresponds to the `file_ioctl()` LSM hook.
pub fn check_file_ioctl_access(
    _current_task: &CurrentTask,
    _file: &FileObject,
    _request: u32,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_file_ioctl_access");
    Ok(())
}

/// Updates the supplied `new_creds` with the necessary FS and LSM credentials to correctly label
/// a new `FsNode` on copy-up, to match the existing `fs_node`.
/// Corresponds to the `security_inode_copy_up()` LSM hook.
pub fn fs_node_copy_up(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
    _fs: &FileSystem,
    _new_creds: &mut Credentials,
) {
}

/// This hook is called by the `flock` syscall. Returns whether `current_task` can perform
/// a lock operation on the given file.
/// Corresponds to the `file_lock()` LSM hook.
pub fn check_file_lock_access(_current_task: &CurrentTask, _file: &FileObject) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_file_lock_access");
    Ok(())
}

/// Returns whether `current_task` has the permissions to execute this fcntl syscall.
/// Corresponds to the `file_fcntl()` LSM hook.
pub fn check_file_fcntl_access(
    _current_task: &CurrentTask,
    _file: &FileObject,
    _fcntl_cmd: u32,
    _fcntl_arg: u64,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_file_fcntl_access");
    Ok(())
}

/// Checks whether `current_task` can set attributes on `node`.
/// Corresponds to the `inode_setattr()` LSM hook.
pub fn check_fs_node_setattr_access(
    _current_task: &CurrentTask,
    _node: &FsNode,
    _attributes: &zxio_node_attr_has_t,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_setattr_access");
    Ok(())
}

/// Return the default initial `TaskAttrs` for kernel tasks.
/// Corresponds to the `task_alloc()` LSM hook, in the special case when current_task is null.
pub fn task_alloc_for_kernel() -> TaskAttrs {
    track_hook_duration!("security.hooks.task_alloc_for_kernel");
    TaskAttrs::for_kernel()
}

/// Labels an [`crate::vfs::FsNode`] so its security attributes track those of `task`.
/// Corresponds to the `task_to_inode` LSM hook.
pub fn task_to_fs_node(
    _current_task: &CurrentTask,
    _task: &TempRef<'_, Task>,
    _fs_node: &FsNode,
) {
    track_hook_duration!("security.hooks.task_to_fs_node");
}

/// Returns `TaskAttrs` for a new `Task`, based on that of the provided `context`.
pub fn task_for_context(_task: &Task, _context: &FsStr) -> Result<TaskAttrs, Errno> {
    track_hook_duration!("security.hooks.task_for_context");
    Ok(TaskAttrs::for_selinux_disabled())
}

/// Returns true if there exits a `dontaudit` rule for `current_task` access to `fs_node`.
pub fn has_dontaudit_access(_current_task: &CurrentTask, _fs_node: &FsNode) -> bool {
    track_hook_duration!("security.hooks.has_dontaudit_access");
    false
}

/// Returns true if a task has the specified `capability`.
/// Corresponds to the `capable()` LSM hook invoked with a no-audit flag set.
pub fn is_task_capable_noaudit(
    current_task: &CurrentTask,
    capability: starnix_uapi::auth::Capabilities,
) -> bool {
    track_hook_duration!("security.hooks.is_task_capable_noaudit");
    // Discretionary POSIX capability check still applies; there is no LSM overlay.
    common_cap::capable(current_task, capability).is_ok()
}

/// Checks if a task has the specified `capability`.
/// Corresponds to the `capable()` LSM hook.
pub fn check_task_capable(
    current_task: &CurrentTask,
    capability: starnix_uapi::auth::Capabilities,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_task_capable");
    common_cap::capable(current_task, capability)
}

/// Checks if creating a task is allowed.
/// Corresponds to the `task_alloc()` LSM hook.
pub fn check_task_create_access(_current_task: &CurrentTask) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_task_create_access");
    Ok(())
}

/// Checks if exec is allowed and if so, checks permissions related to the transition (if any)
/// from the pre-exec security context to the post-exec context.
/// Corresponds to the `bprm_creds_for_exec()` LSM hook.
pub fn bprm_creds_for_exec(
    _current_task: &CurrentTask,
    _executable: &NamespaceNode,
) -> Result<ResolvedElfState, Errno> {
    track_hook_duration!("security.hooks.bprm_creds_for_exec");
    Ok(ResolvedElfState::default())
}

/// Updates the security thread group state on exec.
/// Corresponds to the `exec_binprm` function described in the SELinux Notebook.
pub fn exec_binprm(
    _locked: &mut Locked<Unlocked>,
    _current_task: &CurrentTask,
    _elf_security_state: &ResolvedElfState,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.exec_binprm");
    Ok(())
}

/// Checks if `source` may exercise the "getsched" permission on `target`.
/// Corresponds to the `task_getscheduler()` LSM hook.
pub fn check_getsched_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_getsched_access");
    Ok(())
}

/// Checks if setsched is allowed.
/// Corresponds to the `task_setscheduler()` LSM hook.
pub fn check_setsched_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_setsched_access");
    Ok(())
}

/// Checks if getpgid is allowed.
/// Corresponds to the `task_getpgid()` LSM hook.
pub fn check_getpgid_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_getpgid_access");
    Ok(())
}

/// Checks if setpgid is allowed.
/// Corresponds to the `task_setpgid()` LSM hook.
pub fn check_setpgid_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_setpgid_access");
    Ok(())
}

/// Called when the current task queries the session Id of the `target` task.
/// Corresponds to the `task_getsid()` LSM hook.
pub fn check_task_getsid(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_task_getsid");
    Ok(())
}

/// Called when the current task queries the Linux capabilities of the `target` task.
/// Corresponds to the `capget()` LSM hook.
pub fn check_getcap_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_getcap_access");
    Ok(())
}

/// Called when the current task attempts to set the Linux capabilities of the `target` task.
/// Corresponds to the `capset()` LSM hook.
pub fn check_setcap_access(_source: &CurrentTask, _target: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_setcap_access");
    Ok(())
}

/// Checks if sending a signal is allowed.
/// Corresponds to the `task_kill()` LSM hook.
pub fn check_signal_access(
    _source: &CurrentTask,
    _target: &Task,
    _signal: Signal,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_signal_access");
    Ok(())
}

/// Checks if a particular syslog action is allowed.
/// Corresponds to the `task_syslog()` LSM hook.
pub fn check_syslog_access(_source: &CurrentTask, _action: SyslogAction) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_syslog_access");
    Ok(())
}

/// Checks whether the `parent_tracer_task` is allowed to trace the `current_task`.
/// Corresponds to the `ptrace_traceme()` LSM hook.
pub fn ptrace_traceme(current_task: &CurrentTask, parent_tracer_task: &Task) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.ptrace_traceme");
    yama::ptrace_traceme(current_task, parent_tracer_task)?;
    common_cap::ptrace_traceme(current_task, parent_tracer_task)
}

/// Checks whether the current `current_task` is allowed to trace `tracee_task`.
/// Corresponds to the `ptrace_access_check()` LSM hook.
pub fn ptrace_access_check(
    current_task: &CurrentTask,
    tracee_task: &Task,
    mode: PtraceAccessMode,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.ptrace_access_check");
    yama::ptrace_access_check(current_task, tracee_task, mode)?;
    common_cap::ptrace_access_check(current_task, tracee_task, mode)
}

/// Called when the current task calls prlimit on a different task.
/// Corresponds to the `task_prlimit()` LSM hook.
pub fn task_prlimit(
    _source: &CurrentTask,
    _target: &Task,
    _check_get_rlimit: bool,
    _check_set_rlimit: bool,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.task_prlimit");
    Ok(())
}

/// Called before `source` sets the resource limits of `target`.
/// Corresponds to the `security_task_setrlimit` hook.
pub fn task_setrlimit(
    _source: &CurrentTask,
    _target: &Task,
    _old_limit: rlimit,
    _new_limit: rlimit,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.task_setrlimit");
    Ok(())
}

/// Check permission before mounting `fs`.
/// Corresponds to the `sb_kern_mount()` LSM hook.
pub fn sb_kern_mount(_current_task: &CurrentTask, _fs: &FileSystem) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_kern_mount");
    Ok(())
}

/// Check permission before mounting to `path`.
/// Corresponds to the `sb_mount()` LSM hook.
pub fn sb_mount(
    _current_task: &CurrentTask,
    _path: &NamespaceNode,
    _flags: MountFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_mount");
    Ok(())
}

/// Checks permission before remounting `mount` with `new_mount_params`.
/// Corresponds to the `sb_remount()` LSM hook.
pub fn sb_remount(
    _current_task: &CurrentTask,
    _mount: &Mount,
    _new_mount_options: FileSystemMountOptions,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_remount");
    Ok(())
}

/// Writes the LSM mount options of `mount` into `buf`.
/// Corresponds to the `sb_show_options` LSM hook.
pub fn sb_show_options(
    _kernel: &Kernel,
    _buf: &mut impl OutputBuffer,
    _mount: &Mount,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_show_options");
    Ok(())
}

/// Checks if `current_task` has the permission to get the filesystem statistics of `fs`.
/// Corresponds to the `sb_statfs()` LSM hook.
pub fn sb_statfs(_current_task: &CurrentTask, _fs: &FileSystem) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_statfs");
    Ok(())
}

/// Checks if `current_task` has the permission to unmount the filesystem mounted on `node`.
/// Corresponds to the `sb_umount()` LSM hook.
pub fn sb_umount(
    _current_task: &CurrentTask,
    _node: &NamespaceNode,
    _flags: UnmountFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.sb_umount");
    Ok(())
}

/// Checks if `current_task` has the permission to read file attributes for `fs_node`.
/// Corresponds to the `inode_getattr()` hook.
pub fn check_fs_node_getattr_access(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_getattr_access");
    Ok(())
}

/// Returns true if the security subsystem should skip capability checks on access to the named
/// attribute, false otherwise.
pub fn fs_node_xattr_skipcap(_current_task: &CurrentTask, _name: &FsStr) -> bool {
    false
}

/// Partially corresponds to the `inode_setxattr()` LSM hook.
pub fn check_fs_node_setxattr_access(
    current_task: &CurrentTask,
    fs_node: &FsNode,
    name: &FsStr,
    value: &FsStr,
    op: XattrOp,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_setxattr_access");
    common_cap::fs_node_setxattr(current_task, fs_node, name, value, op)
}

/// Corresponds to the `inode_getxattr()` LSM hook.
pub fn check_fs_node_getxattr_access(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
    _name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_getxattr_access");
    Ok(())
}

/// Corresponds to the `inode_listxattr()` LSM hook.
pub fn check_fs_node_listxattr_access(
    _current_task: &CurrentTask,
    _fs_node: &FsNode,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_listxattr_access");
    Ok(())
}

/// Corresponds to the `inode_removexattr()` LSM hook.
pub fn check_fs_node_removexattr_access(
    current_task: &CurrentTask,
    fs_node: &FsNode,
    name: &FsStr,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_fs_node_removexattr_access");
    common_cap::fs_node_removexattr(current_task, fs_node, name)
}

/// If SELinux is enabled and `fs_node` is in a filesystem without xattr support, returns the xattr
/// name for the security label associated with inode. Otherwise returns None.
/// Corresponds to the `inode_listsecurity()` LSM hook.
pub fn fs_node_listsecurity(_current_task: &CurrentTask, _fs_node: &FsNode) -> Option<FsString> {
    track_hook_duration!("security.hooks.fs_node_listsecurity");
    None
}

/// Returns the value of the specified "security.*" attribute for `fs_node`.
/// With no LSM enabled the call is delegated to the [`crate::vfs::FsNodeOps`].
/// Corresponds to the `inode_getsecurity()` LSM hook.
pub fn fs_node_getsecurity<L>(
    locked: &mut Locked<L>,
    current_task: &CurrentTask,
    fs_node: &FsNode,
    name: &FsStr,
    max_size: usize,
) -> Result<ValueOrSize<FsString>, Errno>
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.fs_node_getsecurity");
    fs_node.ops().get_xattr(
        locked.cast_locked::<FileOpsCore>(),
        fs_node,
        current_task,
        name,
        max_size,
    )
}

/// Called when an extended attribute with "security."-prefixed `name` is being set.
/// With no LSM enabled the call is delegated to the [`crate::vfs::FsNodeOps`].
/// Partially corresponds to the `inode_setsecurity()` and `inode_post_setxattr()` LSM hooks.
pub fn fs_node_setsecurity<L>(
    locked: &mut Locked<L>,
    current_task: &CurrentTask,
    fs_node: &FsNode,
    name: &FsStr,
    value: &FsStr,
    op: XattrOp,
) -> Result<(), Errno>
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.fs_node_setsecurity");
    fs_node.ops().set_xattr(
        locked.cast_locked::<FileOpsCore>(),
        fs_node,
        current_task,
        name,
        value,
        op,
    )
}

/// Identifies one of the Security Context attributes associated with a task.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProcAttr {
    Current,
    Exec,
    FsCreate,
    KeyCreate,
    Previous,
    SockCreate,
}

/// Returns the Security Context associated with the `name`ed entry for the specified `target` task.
/// Corresponds to the `getprocattr()` LSM hook.
pub fn get_procattr(
    _current_task: &CurrentTask,
    _target: &Task,
    _attr: ProcAttr,
) -> Result<Vec<u8>, Errno> {
    track_hook_duration!("security.hooks.get_procattr");
    // With no LSM enabled there are no values to return.
    error!(EINVAL)
}

/// Sets the Security Context associated with the `name`ed entry for the current task.
/// Corresponds to the `setprocattr()` LSM hook.
pub fn set_procattr(
    _current_task: &CurrentTask,
    _attr: ProcAttr,
    _context: &[u8],
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.set_procattr");
    // With no LSM enabled no writes are accepted.
    error!(EINVAL)
}

/// Returns true if SELinux is enabled on the kernel for this task.
pub fn fs_is_xattr_labeled(_fs: FileSystemHandle) -> bool {
    false
}

/// Marks the credentials as being used for an internal operation. All security permission checks
/// will be skipped on this task.
pub fn creds_start_internal_operation(current_task: &CurrentTask) -> Arc<Credentials> {
    track_hook_duration!("security.hooks.creds_start_internal_operation");
    let mut creds = Credentials::clone(&current_task.current_creds());
    creds.security_state.internal_operation = true;
    creds.into()
}

// -- bpf hooks (gated)
//
// The upstream `bpf` subsystem (maps, programs) was not forked; these hooks
// reference types from `crate::bpf` that only exist under the `fuchsia` feature.
// Their only callers live in that same gated code.

/// Returns the security context to be assigned to a BPF map object.
/// Corresponds to the `bpf_map_alloc_security()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn bpf_map_alloc(_current_task: &CurrentTask) -> super::BpfMapState {
    track_hook_duration!("security.hooks.bpf_map_alloc");
    super::BpfMapState::default()
}

/// Returns the security context to be assigned to a BPF program object.
/// Corresponds to the `bpf_prog_alloc_security()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn bpf_prog_alloc(_current_task: &CurrentTask) -> super::BpfProgState {
    track_hook_duration!("security.hooks.bpf_prog_alloc");
    super::BpfProgState::default()
}

/// Checks whether `current_task` can perform the given bpf `cmd`.
/// Corresponds to the `bpf()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_bpf_access<Attr: FromBytes>(
    _current_task: &CurrentTask,
    _cmd: bpf_cmd,
    _attr: &Attr,
    _attr_size: u32,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_bpf_access");
    Ok(())
}

/// Checks whether `current_task` can create a bpf_map.
/// Corresponds to the `bpf_map()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_bpf_map_access(
    _current_task: &CurrentTask,
    _bpf_map: &crate::bpf::BpfMap,
    _flags: PermissionFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_bpf_map_access");
    Ok(())
}

/// Checks whether `current_task` can create a bpf_program.
/// Corresponds to the `bpf_prog()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_bpf_prog_access(
    _current_task: &CurrentTask,
    _bpf_program: &crate::bpf::program::Program,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_bpf_prog_access");
    Ok(())
}

// -- perf hooks (gated)
//
// The upstream `perf` subsystem was not forked; these hooks reference
// `crate::perf::PerfEventFile`, which only exists under the `fuchsia` feature.

/// Checks whether `current_task` may monitor the given target task(s).
/// Corresponds to the `perf_event_open` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_perf_event_open_access(
    _current_task: &CurrentTask,
    _target_task_type: TargetTaskType<'_>,
    _attr: &linux_uapi::perf_event_attr,
    _event_type: PerfEventType,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_perf_event_open_access");
    Ok(())
}

/// Returns the security context to be assigned to a PerfEventFileState.
/// Corresponds to the `perf_event_alloc` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn perf_event_alloc(_current_task: &CurrentTask) -> super::PerfEventState {
    track_hook_duration!("security.hooks.perf_event_alloc");
    super::PerfEventState::default()
}

/// Checks whether `current_task` may read the given `perf_event_file`.
/// Corresponds to the `perf_event_read` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_perf_event_read_access(
    _current_task: &CurrentTask,
    _perf_event_file: &crate::perf::PerfEventFile,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_perf_event_read_access");
    Ok(())
}

/// Checks whether `current_task` may write to the given `perf_event_file`.
/// Corresponds to the `perf_event_write` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_perf_event_write_access(
    _current_task: &CurrentTask,
    _perf_event_file: &crate::perf::PerfEventFile,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_perf_event_write_access");
    Ok(())
}

// -- socket hooks (gated)
//
// `crate::vfs::socket` is only compiled under the `fuchsia` feature, and the
// only callers of these hooks live there.

/// Sets the peer security context for each socket in the pair.
/// Corresponds to the `socket_socketpair()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn socket_socketpair(
    _current_task: &CurrentTask,
    _left: crate::vfs::DowncastedFile<'_, crate::vfs::socket::SocketFile>,
    _right: crate::vfs::DowncastedFile<'_, crate::vfs::socket::SocketFile>,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.socket_socketpair");
    Ok(())
}

/// Checks if creating a socket is allowed.
/// Corresponds to the `socket_create()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_create_access<L>(
    _locked: &mut Locked<L>,
    _current_task: &CurrentTask,
    _domain: crate::vfs::socket::SocketDomain,
    _socket_type: crate::vfs::socket::SocketType,
    _protocol: crate::vfs::socket::SocketProtocol,
    _kernel_private: bool,
) -> Result<(), Errno>
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.socket_create");
    Ok(())
}

/// Computes and updates the socket security class associated with a new socket.
/// Corresponds to the `socket_post_create()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn socket_post_create(_current_task: &CurrentTask, _socket: &crate::vfs::socket::Socket) {
    track_hook_duration!("security.hooks.socket_post_create");
}

/// Checks if the `current_task` is allowed to perform a bind operation for this `socket`.
/// Corresponds to the `socket_bind()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_bind_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _socket_address: &crate::vfs::socket::SocketAddress,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_bind_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to initiate a connection with `socket`.
/// Corresponds to the `socket_connect()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_connect_access(
    _current_task: &CurrentTask,
    _socket: crate::vfs::DowncastedFile<'_, crate::vfs::socket::SocketFile>,
    _socket_peer: &crate::vfs::socket::SocketPeer,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_connect_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to listen on `socket`.
/// Corresponds to the `socket_listen()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_listen_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _backlog: i32,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_listen_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to accept connections on `listening_socket`.
/// Corresponds to the `socket_accept()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn socket_accept(
    _current_task: &CurrentTask,
    _listening_socket: crate::vfs::DowncastedFile<'_, crate::vfs::socket::SocketFile>,
    _accepted_socket: crate::vfs::DowncastedFile<'_, crate::vfs::socket::SocketFile>,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_getname_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to get socket options on `socket`.
/// Corresponds to the `socket_getsockopt()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_getsockopt_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _level: u32,
    _optname: u32,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_getsockopt_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to set socket options on `socket`.
/// Corresponds to the `socket_setsockopt()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_setsockopt_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _level: u32,
    _optname: u32,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_setsockopt_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to send a message on `socket`.
/// Corresponds to the `socket_sendmsg()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_sendmsg_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_sendmsg_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to receive a message on `socket`.
/// Corresponds to the `socket_recvmsg()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_recvmsg_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_recvmsg_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to get the local name of `socket`.
/// Corresponds to the `socket_getsockname()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_getsockname_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_getname_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to get the remote name of `socket`.
/// Corresponds to the `socket_getpeername()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_getpeername_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_getname_access");
    Ok(())
}

/// Checks if the `current_task` is allowed to shutdown `socket`.
/// Corresponds to the `socket_shutdown()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_socket_shutdown_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _how: crate::vfs::socket::SocketShutdownFlags,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_socket_shutdown_access");
    Ok(())
}

/// Returns the Security Context with which the socket's peer is labeled.
/// Corresponds to the `socket_getpeersec_stream()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn socket_getpeersec_stream(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Result<Vec<u8>, Errno> {
    track_hook_duration!("security.hooks.socket_getpeersec_stream");
    Ok(Vec::default())
}

/// Returns the Security Context with which the socket is labeled, for `SCM_SECURITY` data.
/// Corresponds to the `socket_getpeersec_dgram()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn socket_getpeersec_dgram(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
) -> Vec<u8> {
    track_hook_duration!("security.hooks.socket_getpeersec_dgram");
    Vec::default()
}

/// Checks if the Unix domain `sending_socket` may send a message to `receiving_socket`.
/// Corresponds to the `unix_may_send()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn unix_may_send(
    _current_task: &CurrentTask,
    _sending_socket: &crate::vfs::socket::Socket,
    _receiving_socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.unix_may_send");
    Ok(())
}

/// Checks if the Unix domain `client_socket` may connect to `listening_socket`.
/// Corresponds to the `unix_stream_connect()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn unix_stream_connect(
    _current_task: &CurrentTask,
    _client_socket: &crate::vfs::socket::Socket,
    _listening_socket: &crate::vfs::socket::Socket,
    _server_socket: &crate::vfs::socket::Socket,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.unix_stream_connect");
    Ok(())
}

/// Checks if the `current_task` may send a message of `message_type` on the Netlink `socket`.
/// Corresponds to the `netlink_send()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_netlink_send_access(
    _current_task: &CurrentTask,
    _socket: &crate::vfs::socket::Socket,
    _message_type: u16,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_netlink_send_access");
    Ok(())
}

/// Checks if the `current_task` may create a new TUN device.
/// Corresponds to the `tun_dev_create()` LSM hook.
#[cfg(feature = "fuchsia")]
pub fn check_tun_dev_create_access(_current_task: &CurrentTask) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.check_tun_dev_create_access");
    Ok(())
}

// -- selinuxfs hooks (gated)
//
// The "selinuxfs" pseudo-filesystem was not forked. These hooks only have
// callers within that module, and reference the placeholder policy types.

/// Stashes a reference to the selinuxfs null file for later use.
#[cfg(feature = "fuchsia")]
pub fn selinuxfs_init_null(_current_task: &CurrentTask, _null_fs_node: &FileHandle) {}

/// Called by the "selinuxfs" when a policy has been successfully loaded.
#[cfg(feature = "fuchsia")]
pub fn selinuxfs_policy_loaded<L>(_locked: &mut Locked<L>, _current_task: &CurrentTask)
where
    L: LockEqualOrBefore<FileOpsCore>,
{
    track_hook_duration!("security.hooks.selinuxfs_policy_loaded");
}

/// Used by the "selinuxfs" module to access the SELinux administration API, if enabled.
#[cfg(feature = "fuchsia")]
pub fn selinuxfs_get_admin_api(_current_task: &CurrentTask) -> Option<Arc<SecurityServer>> {
    None
}

/// Used by the "selinuxfs" module to perform checks on SELinux API file accesses.
#[cfg(feature = "fuchsia")]
pub fn selinuxfs_check_access(
    _current_task: &CurrentTask,
    _permission: SecurityPermission,
) -> Result<(), Errno> {
    track_hook_duration!("security.hooks.selinuxfs_check_access");
    Ok(())
}
