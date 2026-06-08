//! Process handle (wraps M6 VSpace + CNode + TCB collection)

use crate::object::{AsHandleRef, HandleBased, HandleRef, NullableHandle};
use crate::sys::zx_handle_t;
use crate::{Status, Vmar};

/// A process handle.
///
/// In Fuchsia a process contains a VSpace (VMAR), a handle table and threads.
/// This shim carries an opaque handle plus the optional M6 capability pointers
/// used by the native bring-up path.
pub struct Process {
    /// Opaque process handle.
    handle: NullableHandle,
    /// VSpace capability pointer (M6 native path; 0 if unused).
    pub(crate) vspace_cptr: u64,
    /// CNode capability pointer (M6 native path; 0 if unused).
    pub(crate) cnode_cptr: u64,
    /// ASID assigned to this process (M6 native path; 0 if unused).
    pub(crate) asid: u16,
}

impl Process {
    /// Create a process handle from M6 capability pointers.
    pub fn new(vspace_cptr: u64, cnode_cptr: u64, asid: u16) -> Self {
        Self {
            handle: NullableHandle::invalid(),
            vspace_cptr,
            cnode_cptr,
            asid,
        }
    }

    /// Get the VSpace capability pointer.
    pub fn vspace_cptr(&self) -> u64 {
        self.vspace_cptr
    }

    /// Get the CNode capability pointer.
    pub fn cnode_cptr(&self) -> u64 {
        self.cnode_cptr
    }

    /// Get the ASID.
    pub fn asid(&self) -> u16 {
        self.asid
    }

    /// Returns the root VMAR of this process. Stub.
    pub fn vmar(&self) -> Vmar {
        Vmar::new_root(self.vspace_cptr)
    }

    /// Terminates the current process with `retcode`. Stub: never returns.
    pub fn exit(retcode: i64) -> ! {
        let _ = retcode;
        // No M6 process-exit primitive is wired here yet; spin to satisfy `!`.
        loop {
            core::hint::spin_loop();
        }
    }

    /// Kill the process. Stub.
    pub fn kill(&self) -> Result<(), Status> {
        Ok(())
    }

    /// Duplicates this process handle with the given rights.
    ///
    /// Mirrors `zx::Process::duplicate` (the `HandleBased::duplicate` wrapper).
    /// Stub: clones the M6 capability pointers; rights are not yet enforced.
    pub fn duplicate(&self, _rights: crate::Rights) -> Result<Process, Status> {
        Ok(Self {
            handle: NullableHandle::from_raw(self.handle.raw()),
            vspace_cptr: self.vspace_cptr,
            cnode_cptr: self.cnode_cptr,
            asid: self.asid,
        })
    }

    /// Returns the address of the `ZX_PROP_PROCESS_BREAK_ON_LOAD` breakpoint.
    ///
    /// Stub: M6 has no debugger break-on-load property; reports 0 (no debugger).
    pub fn get_break_on_load(&self) -> Result<u64, Status> {
        Ok(0)
    }

    /// Sets the `ZX_PROP_PROCESS_BREAK_ON_LOAD` breakpoint address. Stub.
    pub fn set_break_on_load(&self, _value: &u64) -> Result<(), Status> {
        Ok(())
    }
}

impl From<NullableHandle> for Process {
    fn from(handle: NullableHandle) -> Self {
        Self {
            handle,
            vspace_cptr: 0,
            cnode_cptr: 0,
            asid: 0,
        }
    }
}

impl AsHandleRef for Process {
    fn as_handle_ref(&self) -> HandleRef<'_> {
        self.handle.as_handle_ref()
    }
    fn raw_handle(&self) -> zx_handle_t {
        self.handle.raw()
    }
}
impl HandleBased for Process {}
