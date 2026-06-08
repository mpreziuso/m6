// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;

// The real execution layer (Zircon process/thread creation + the Fuchsia async
// executor entry) is gated. M6's process/thread-creation seam (mapping these
// onto VSpace/TCB capabilities + the restricted-mode syscall loop) is the M3
// integration work; until then the minimal core exposes ENOSYS stubs with the
// upstream signatures so the task layer compiles and links.
#[cfg(feature = "fuchsia")]
pub mod crash_reporter;
#[cfg(feature = "fuchsia")]
mod executor;
#[cfg(feature = "fuchsia")]
mod loop_entry;
#[cfg(feature = "fuchsia")]
mod task_creation;

#[cfg(feature = "fuchsia")]
pub use crash_reporter::*;
#[cfg(feature = "fuchsia")]
pub use executor::*;
#[cfg(feature = "fuchsia")]
pub use loop_entry::*;
#[cfg(feature = "fuchsia")]
pub use task_creation::*;

#[cfg(not(feature = "fuchsia"))]
mod stub {
    #[allow(unused_imports)]
    use m6_starnix_std::prelude::*;
    use crate::mm_ref::MemoryManager;
    use crate::ptrace::PtraceCoreState;
    use crate::signals::SignalActions;
    use crate::task::{
        CurrentTask, ExitStatus, Kernel, PidTable, ProcessGroup, Task, TaskBuilder, ThreadGroup,
        ThreadGroupWriteGuard,
    };
    use crate::task::{SeccompFilterContainer, SeccompState};
    use crate::vfs::{FdTable, FsContext};
    use anyhow::Error;
    use starnix_sync::{LockBefore, Locked, ProcessGroupState, RwLockWriteGuard, TaskRelease, Unlocked};
    use starnix_task_command::TaskCommand;
    use starnix_types::arch::ArchWidth;
    use starnix_types::ownership::{OwnedRef, Releasable, TempRef, release_on_error};
    use starnix_uapi::auth::Credentials;
    use starnix_uapi::errors::Errno;
    use crate::task::RobustListHeadPtr;
    use starnix_uapi::resource_limits::Resource;
    use starnix_uapi::signals::{SIGCHLD, Signal};
    use starnix_uapi::{errno, error, pid_t, rlimit};
    use m6_starnix_std::ffi::CString;
    use m6_starnix_std::sync::Arc;

    /// Process/thread/mm bundle returned by process creation. See the gated
    /// `task_creation` for the real definition.
    pub struct TaskInfo {
        /// The thread created for the task.
        pub thread: Option<zx::Thread>,
        /// The thread group the task belongs to.
        pub thread_group: Arc<ThreadGroup>,
        /// The task's memory manager.
        pub memory_manager: Option<Arc<MemoryManager>>,
    }

    /// Create the M6 process backing for a new thread group: a fresh VSpace
    /// (with an ASID), a root VMAR over it, and a [`MemoryManager`]. This is the
    /// M4 process-creation seam — real, but it requires the M6 allocator context
    /// to have been installed (`zx::mem_context::init`); without it, it reports
    /// ENOSYS, matching the previous stub.
    pub fn create_zircon_process<L>(
        locked: &mut Locked<L>,
        kernel: &Arc<Kernel>,
        parent: Option<ThreadGroupWriteGuard<'_>>,
        pid: pid_t,
        exit_signal: Option<Signal>,
        process_group: Arc<ProcessGroup>,
        signal_actions: Arc<SignalActions>,
        name: TaskCommand,
        arch_width: ArchWidth,
    ) -> Result<TaskInfo, Errno>
    where
        L: LockBefore<ProcessGroupState>,
    {
        let _ = name;
        if !zx::mem_context::is_initialised() {
            return error!(ENOSYS);
        }

        // Fresh M6 address space for the Linux process.
        let vspace_cptr = zx::mem_context::create_vspace().map_err(|_| errno!(ENOMEM))?;
        let cnode_cptr = zx::mem_context::root_cnode_cptr().map_err(|_| errno!(ENOMEM))?;
        let process = zx::Process::new(vspace_cptr, cnode_cptr, /* asid */ 0);
        let root_vmar = process.vmar();

        let memory_manager =
            Arc::new(MemoryManager::new(root_vmar, arch_width).map_err(|_| errno!(ENOMEM))?);

        let thread_group = ThreadGroup::new(
            locked,
            kernel.clone(),
            process,
            parent,
            pid,
            exit_signal,
            process_group,
            signal_actions,
        );

        Ok(TaskInfo { thread: None, thread_group, memory_manager: Some(memory_manager) })
    }

    /// Stub: creating the init child process is the M3/M4 seam — reports ENOSYS.
    pub fn create_init_child_process<L>(
        _locked: &mut Locked<L>,
        _kernel: &Arc<Kernel>,
        _initial_name: TaskCommand,
        _creds: Credentials,
        _seclabel: Option<&CString>,
    ) -> Result<TaskBuilder, Errno>
    where
        L: LockBefore<TaskRelease>,
    {
        error!(ENOSYS)
    }

    /// Stub: kernel-thread creation is the M3 seam — reports ENOSYS.
    pub fn create_kernel_thread<L>(
        _locked: &mut Locked<L>,
        _system_task: &Task,
        _initial_name: TaskCommand,
    ) -> Result<CurrentTask, Errno>
    where
        L: LockBefore<TaskRelease>,
    {
        error!(ENOSYS)
    }

    /// Stub: running a task on the executor is the M3/M4 seam — reports ENOSYS.
    pub fn execute_task<L, F, G>(
        _locked: &mut Locked<L>,
        _task_builder: TaskBuilder,
        _pre_run: F,
        _task_complete: G,
        _ptrace_state: Option<PtraceCoreState>,
    ) -> Result<(), Errno>
    where
        L: LockBefore<TaskRelease>,
        F: FnOnce(&mut Locked<Unlocked>, &mut CurrentTask) -> Result<(), Errno>
            + Send
            + Sync
            + 'static,
        G: FnOnce(Result<ExitStatus, Error>) + Send + Sync + 'static,
    {
        error!(ENOSYS)
    }

    /// Create a task with a specific pid (ported from upstream `task_creation`).
    /// The `task_info_factory` builds the process backing (see
    /// [`create_zircon_process`]).
    #[allow(clippy::too_many_arguments)]
    pub fn create_task_with_pid<F, L>(
        locked: &mut Locked<L>,
        kernel: &Kernel,
        mut pids: RwLockWriteGuard<'_, PidTable>,
        pid: pid_t,
        initial_name: TaskCommand,
        root_fs: Arc<FsContext>,
        task_info_factory: F,
        creds: Arc<Credentials>,
        rlimits: &[(Resource, u64)],
    ) -> Result<TaskBuilder, Errno>
    where
        F: FnOnce(&mut Locked<L>, i32, Arc<ProcessGroup>) -> Result<TaskInfo, Errno>,
        L: LockBefore<TaskRelease>,
    {
        debug_assert!(pids.get_task(pid).upgrade().is_none());

        let process_group = ProcessGroup::new(pid, None);
        pids.add_process_group(process_group.clone());

        let TaskInfo { thread, thread_group, memory_manager } =
            task_info_factory(locked, pid, process_group.clone())?;

        process_group.insert(locked.cast_locked::<TaskRelease>(), &thread_group);

        // init (pid 1) timer slack is 50us; inherited across fork/execve.
        let default_timerslack = 50_000;
        let builder = TaskBuilder::new(Task::new(
            pid,
            initial_name,
            thread_group,
            thread,
            FdTable::default(),
            memory_manager,
            root_fs,
            creds,
            Arc::clone(&kernel.default_abstract_socket_namespace),
            Arc::clone(&kernel.default_abstract_vsock_namespace),
            Default::default(),
            Default::default(),
            None,
            Default::default(),
            kernel.root_uts_ns.clone(),
            false,
            SeccompState::default(),
            SeccompFilterContainer::default(),
            RobustListHeadPtr::null(&ArchWidth::Arch64),
            default_timerslack,
        ));

        release_on_error!(builder, locked, {
            let temp_task = TempRef::from(&builder.task);
            builder.thread_group().add(&temp_task)?;
            for (resource, limit) in rlimits {
                builder
                    .thread_group()
                    .limits
                    .lock(locked.cast_locked::<TaskRelease>())
                    .set(*resource, rlimit { rlim_cur: *limit, rlim_max: *limit });
            }
            pids.add_task(&temp_task);
            Ok(())
        });
        Ok(builder)
    }

    /// Create the init process (pid 1) with the given root filesystem.
    pub fn create_init_process(
        locked: &mut Locked<Unlocked>,
        kernel: &Arc<Kernel>,
        pid: pid_t,
        initial_name: TaskCommand,
        fs: Arc<FsContext>,
        rlimits: &[(Resource, u64)],
    ) -> Result<TaskBuilder, Errno> {
        let pids = kernel.pids.write();
        create_task_with_pid(
            locked,
            kernel,
            pids,
            pid,
            initial_name.clone(),
            fs,
            |locked, pid, process_group| {
                create_zircon_process(
                    locked,
                    kernel,
                    None,
                    pid,
                    Some(SIGCHLD),
                    process_group,
                    SignalActions::default(),
                    initial_name.clone(),
                    ArchWidth::Arch64,
                )
            },
            Credentials::root().into(),
            rlimits,
        )
    }
}

#[cfg(not(feature = "fuchsia"))]
pub use stub::*;
