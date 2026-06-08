//! M4 first-light bootstrap — run a Linux ELF via the **forked Starnix core**.
//!
//! This is the faithful path the roadmap targets (as opposed to the native
//! `run_linux_binary` bring-up scaffolding): it builds a real Starnix
//! `Kernel` + init `CurrentTask` with a tmpfs root, makes the ELF a VFS file,
//! `exec`s it through the forked loader, wires stdio to the M6 console, and runs
//! the restricted-mode dispatch loop ([`syscall_loop::run_starnix_task_loop`]).
//!
//! The caller (`svc_starnix`) provides the M6 capability environment (an untyped
//! pool, the root CNode, an ASID pool, and a bound state frame) via
//! [`StarnixBootConfig`].

#![allow(clippy::too_many_arguments)]

use m6_starnix_std::boxed::Box;
use m6_starnix_std::sync::Arc;
use m6_starnix_std::vec::Vec;

use starnix_sync::Unlocked;
use starnix_task_command::TaskCommand;
use starnix_types::ownership::TempRef;
use starnix_uapi::auth::FsCred;
use starnix_uapi::errors::Errno;
use starnix_uapi::file_mode::FileMode;
use starnix_uapi::open_flags::OpenFlags;
use starnix_uapi::{errno, error};

use crate::task::{CurrentTask, Kernel, KernelFeatures};
use crate::task::limits::SystemLimits;
use crate::vfs::buffers::{InputBuffer, OutputBuffer, VecInputBuffer};
use crate::vfs::InputBufferExt;
use crate::vfs::{
    Anon, FdFlags, FdNumber, FileHandle, FileObject, FileOps, FsContext, FsNodeInfo, FsString,
    LookupContext, Namespace,
    fileops_impl_noop_sync, fileops_impl_seekless,
};
use starnix_uapi::device_type::DeviceType;
use crate::fs::tmpfs::TmpFs;
use crate::syscall_loop::{self, StateFrame};

/// The M6 capability environment for a forked-Starnix Linux process.
pub struct StarnixBootConfig {
    /// CNode slot of the untyped capability to allocate frames/page-tables from.
    pub untyped_slot: u64,
    /// CNode slot of the (self) root CNode.
    pub root_cnode_slot: u64,
    /// CNode slot of the ASID pool.
    pub asid_pool_slot: u64,
    /// CNode radix (log2 of the number of slots).
    pub cnode_radix: u8,
    /// First CNode slot the Starnix allocator may use for fresh objects.
    pub first_free_slot: u64,
    /// Virtual address where the restricted-mode state frame is mapped in the
    /// supervisor's (svc_starnix's) own VSpace.
    pub state_frame_vaddr: u64,
    /// CNode slot of the state-frame Frame capability.
    pub state_frame_slot: u64,
}

// -- Console: a FileOps whose writes go to the M6 debug console (the UART).

struct StarnixConsole;

impl FileOps for StarnixConsole {
    fileops_impl_seekless!();
    fileops_impl_noop_sync!();

    fn write(
        &self,
        _locked: &mut starnix_sync::Locked<starnix_sync::FileOpsCore>,
        _file: &FileObject,
        _current_task: &CurrentTask,
        _offset: usize,
        data: &mut dyn InputBuffer,
    ) -> Result<usize, Errno> {
        let bytes = data.read_to_vec_limited(data.available())?;
        if let Ok(s) = core::str::from_utf8(&bytes) {
            m6_syscall::invoke::debug_puts(s);
        } else {
            // Non-UTF8 output: emit byte-wise via a tiny stack buffer.
            for &b in &bytes {
                let buf = [b];
                if let Ok(s) = core::str::from_utf8(&buf) {
                    m6_syscall::invoke::debug_puts(s);
                }
            }
        }
        Ok(bytes.len())
    }

    fn read(
        &self,
        _locked: &mut starnix_sync::Locked<starnix_sync::FileOpsCore>,
        _file: &FileObject,
        _current_task: &CurrentTask,
        _offset: usize,
        _data: &mut dyn OutputBuffer,
    ) -> Result<usize, Errno> {
        Ok(0)
    }

    fn to_handle(
        &self,
        _file: &FileObject,
        _current_task: &CurrentTask,
    ) -> Result<Option<zx::NullableHandle>, Errno> {
        Ok(None)
    }
}

fn new_console_file(
    locked: &mut starnix_sync::Locked<Unlocked>,
    current_task: &CurrentTask,
) -> FileHandle {
    Anon::new_private_file_extended(
        locked,
        current_task,
        Box::new(StarnixConsole),
        OpenFlags::RDWR,
        "[m6:console]",
        FsNodeInfo::new(FileMode::from_bits(0o666), FsCred::root()),
    )
}

// -- tmpfs pre-population (so `ls /` has something to enumerate)

/// Create a directory at an absolute path on the (current) root tmpfs.
fn mkdir(
    locked: &mut starnix_sync::Locked<Unlocked>,
    current_task: &CurrentTask,
    path: &[u8],
) -> Result<(), Errno> {
    let (parent, basename) = current_task.lookup_parent_at(
        locked,
        &mut LookupContext::default(),
        FdNumber::AT_FDCWD,
        path.into(),
    )?;
    parent.create_node(
        locked,
        current_task,
        basename,
        FileMode::from_bits(0o755).with_type(FileMode::IFDIR),
        DeviceType::NONE,
    )?;
    Ok(())
}

/// Create a character-device node at an absolute path on the root tmpfs. Opening
/// it routes through the device registry to the ops registered by
/// [`mem_device_init`](crate::device::mem::mem_device_init).
fn mknod_char(
    locked: &mut starnix_sync::Locked<Unlocked>,
    current_task: &CurrentTask,
    path: &[u8],
    dev: DeviceType,
) -> Result<(), Errno> {
    let (parent, basename) = current_task.lookup_parent_at(
        locked,
        &mut LookupContext::default(),
        FdNumber::AT_FDCWD,
        path.into(),
    )?;
    parent.create_node(
        locked,
        current_task,
        basename,
        FileMode::from_bits(0o666).with_type(FileMode::IFCHR),
        dev,
    )?;
    Ok(())
}

/// Create a regular file with `content` at an absolute path on the root tmpfs.
/// Write `content` to `path`, creating any missing parent directories first
/// (`mkdir -p` semantics). `path` must be absolute (leading `/`).
fn lay_down_file(
    locked: &mut starnix_sync::Locked<Unlocked>,
    current_task: &CurrentTask,
    path: &[u8],
    content: &[u8],
) -> Result<(), Errno> {
    // Create each parent component in turn, ignoring "already exists".
    let mut prefix: Vec<u8> = Vec::with_capacity(path.len());
    let mut start = 0;
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }
    // Walk components except the final (basename) one.
    let mut i = start;
    let mut last_sep = start;
    while i < path.len() {
        if path[i] == b'/' {
            // Component path[last_sep..i] is a directory to ensure.
            prefix.clear();
            prefix.extend_from_slice(&path[..i]);
            if let Err(e) = mkdir(locked, current_task, &prefix) {
                // EEXIST is fine; anything else is a real failure.
                if e != errno!(EEXIST) {
                    return Err(e);
                }
            }
            // Skip consecutive separators.
            while i < path.len() && path[i] == b'/' {
                i += 1;
            }
            last_sep = i;
            continue;
        }
        i += 1;
    }
    let _ = last_sep;
    write_file(locked, current_task, path, content)
}

fn write_file(
    locked: &mut starnix_sync::Locked<Unlocked>,
    current_task: &CurrentTask,
    path: &[u8],
    content: &[u8],
) -> Result<(), Errno> {
    let file = current_task.open_file_at(
        locked,
        FdNumber::AT_FDCWD,
        path.into(),
        OpenFlags::CREAT | OpenFlags::WRONLY,
        FileMode::from_bits(0o644),
        Default::default(),
        Default::default(),
    )?;
    let mut buf = VecInputBuffer::new(content);
    file.write(locked, current_task, &mut buf)?;
    Ok(())
}

/// Lay down a small directory tree on the root tmpfs so a Linux `ls` (or
/// `cat`) has real entries to enumerate and stat. Best-effort: a failure here
/// is logged but does not abort the boot (the binary may not need these).
fn populate_rootfs(locked: &mut starnix_sync::Locked<Unlocked>, current_task: &CurrentTask) {
    let dirs: &[&[u8]] = &[b"/bin", b"/etc", b"/tmp", b"/dev"];
    for d in dirs {
        if mkdir(locked, current_task, d).is_err() {
            m6_syscall::invoke::debug_puts("[starnix] mkdir failed during rootfs populate\n");
        }
    }
    let files: &[(&[u8], &[u8])] = &[
        (b"/etc/hostname", b"m6\n"),
        (b"/etc/os-release", b"NAME=M6\nID=m6\n"),
        (b"/README", b"Hello from the M6 Starnix tmpfs root.\n"),
    ];
    for (p, c) in files {
        if write_file(locked, current_task, p, c).is_err() {
            m6_syscall::invoke::debug_puts("[starnix] write_file failed during rootfs populate\n");
        }
    }
}

/// Build a Starnix `Kernel` + init `CurrentTask` (tmpfs root), `exec` the ELF,
/// wire stdio to the console, and run the forked dispatch loop to completion.
///
/// Returns the Linux process exit code.
pub fn run_linux_binary_via_starnix(
    cfg: &StarnixBootConfig,
    elf_data: &[u8],
    argv: &[&[u8]],
    envp: &[&[u8]],
    extra_files: &[(&[u8], &[u8])],
) -> Result<i32, Errno> {
    // 1. Install the M6 allocator context the VMO/VMAR shim draws from.
    zx::mem_context::init(
        cfg.untyped_slot,
        cfg.root_cnode_slot,
        cfg.asid_pool_slot,
        cfg.cnode_radix,
        cfg.first_free_slot,
    );

    // 2. The (single-threaded) lock context for bring-up.
    // SAFETY: svc_starnix runs single-threaded; this is the sole Locked root.
    let locked = unsafe { Unlocked::new() };

    // 3. Kernel (minimal core).
    let kernel = Kernel::new(
        b"".into(),
        KernelFeatures::default(),
        SystemLimits::default(),
        crate::security::KernelState,
    )
    .map_err(|_| errno!(ENOMEM))?;

    // 4. Root filesystem: a tmpfs mounted as `/`.
    let fs = TmpFs::new_fs(locked, &kernel);
    let fs_context = FsContext::new(Namespace::new(fs));

    // 5. The init process (pid 1).
    let init_pid = kernel.pids.write().allocate_pid();
    let builder = crate::execution::create_init_process(
        locked,
        &kernel,
        init_pid,
        TaskCommand::new(b"init"),
        fs_context.fork(),
        &[],
    )?;
    let mut current_task: CurrentTask = builder.into();

    // 6. Wire stdin/stdout/stderr (fds 0/1/2) to the M6 console.
    let console = new_console_file(locked, &current_task);
    for fd in 0..3 {
        current_task
            .files
            .insert(locked, &current_task, FdNumber::from_raw(fd), console.clone())?;
    }

    // 6b. Lay down a small directory tree so a Linux `ls /` (or `cat`) has
    //     real entries to enumerate. Best-effort.
    populate_rootfs(locked, &current_task);

    // 6b'. Register the standard character "mem" device ops and create their
    //      nodes under /dev. Opening an IFCHR node routes through the device
    //      registry to the ops registered here, so binaries that touch
    //      /dev/null, /dev/urandom, etc. work. We register ops only (no
    //      sysfs/devtmpfs) because the full path spawns a kthread the minimal
    //      core lacks; we create the nodes directly on the tmpfs below.
    crate::device::mem::mem_device_ops_only(locked, &current_task);
    let dev_nodes: &[(&[u8], starnix_uapi::device_type::DeviceType)] = &[
        (b"/dev/null", DeviceType::NULL),
        (b"/dev/zero", DeviceType::ZERO),
        (b"/dev/full", DeviceType::FULL),
        (b"/dev/random", DeviceType::RANDOM),
        (b"/dev/urandom", DeviceType::URANDOM),
    ];
    for (path, dev) in dev_nodes {
        if mknod_char(locked, &current_task, path, *dev).is_err() {
            m6_syscall::invoke::debug_puts("[starnix] mknod failed for a /dev node\n");
        }
    }

    // 6c. Lay down any caller-provided files (an ELF interpreter, shared
    //     libraries, data) into the tmpfs at their absolute path, creating parent
    //     directories as needed. Empty for a plain static binary. Best-effort: a
    //     failure here surfaces later as the binary's own ENOENT, not a panic.
    for (path, data) in extra_files {
        if lay_down_file(locked, &current_task, path, data).is_err() {
            m6_syscall::invoke::debug_puts("[starnix] failed to lay down a rootfs file\n");
        }
    }

    // 7. Materialise the ELF as a VFS file under the tmpfs root, then open it
    //    executable so the forked loader can resolve + map it.
    let exe_path = b"/init";
    {
        let create = current_task.open_file_at(
            locked,
            FdNumber::AT_FDCWD,
            (exe_path as &[u8]).into(),
            OpenFlags::CREAT | OpenFlags::WRONLY,
            FileMode::from_bits(0o755),
            Default::default(),
            Default::default(),
        )?;
        let mut buf = VecInputBuffer::new(elf_data);
        create.write(locked, &current_task, &mut buf)?;
        // The write handle holds a FileWriteGuard on the node; exec refuses to
        // run a file with an open writer (ETXTBSY). Close it through the fd table
        // (the canonical delayed-release path) and flush the releaser so the
        // guard is dropped before exec.
        let wfd = current_task.add_file(locked, create, FdFlags::empty())?;
        current_task.files.close(wfd)?;
    }
    current_task.trigger_delayed_releaser(locked);
    let executable = current_task.open_file_at(
        locked,
        FdNumber::AT_FDCWD,
        (exe_path as &[u8]).into(),
        OpenFlags::RDONLY,
        FileMode::EMPTY,
        Default::default(),
        Default::default(),
    )?;

    // 8. exec(): resolve + load the ELF, build the Linux stack, and set the
    //    initial register state (entry point + stack pointer) on the task.
    let to_cstrings = |items: &[&[u8]]| -> Vec<m6_starnix_std::ffi::CString> {
        items
            .iter()
            .map(|s| m6_starnix_std::ffi::CString::new(*s).unwrap_or_default())
            .collect()
    };
    let path_c = m6_starnix_std::ffi::CString::new(exe_path as &[u8]).unwrap_or_default();
    current_task.exec(locked, executable, path_c, to_cstrings(argv), to_cstrings(envp))?;

    // 9. Bind the restricted-mode state frame to this M6 thread and run the
    //    forked syscall dispatch loop until the process exits.
    let state = StateFrame {
        vaddr: cfg.state_frame_vaddr,
        frame_slot: cfg.state_frame_slot,
    };
    let frame_cptr = m6_syscall::slot_to_cptr(cfg.state_frame_slot, cfg.cnode_radix);
    m6_syscall::invoke::restricted_bind_state(frame_cptr).map_err(|_| errno!(EIO))?;

    let _ = TempRef::from(&current_task.task); // keep the task alive for the loop
    let code = syscall_loop::run_starnix_task_loop(locked, &mut current_task, &state);
    Ok(code)
}
