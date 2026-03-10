//! Central Invoke syscall dispatcher
//!
//! All object-manipulation operations go through a single Invoke syscall
//! (x7 = 32). The dispatcher resolves the capability, determines its type,
//! and dispatches to the appropriate handler with repacked arguments.
//!
//! # Invoke ABI
//!
//! - x0: capability pointer (SELF_CAP = self-invocation)
//! - x1: method label (per-type namespace)
//! - x2-x6: method-specific arguments
//!
//! Self-invocations (x0 = SELF_CAP) target the current thread context for
//! operations like exit, sleep, get_random, and cache maintenance.
//! The sentinel is `u64::MAX` because slot 0 (CPtr 0) is the root CNode.

use m6_arch::exceptions::ExceptionContext;
use m6_cap::{CapRights, ObjectType};
use m6_syscall::numbers::{self, method};

use crate::ipc;
use crate::syscall::error::{SyscallError, SyscallResult};
use crate::syscall::{
    SyscallArgs, asid_ops, cache_ops, cap_ops, iommu_ops, irq_ops, mem_ops, misc_ops, tcb_ops,
    timer_ops,
};

/// Handle Invoke syscall.
///
/// Resolves the capability at arg0, determines its type, and dispatches
/// to the appropriate handler based on the method label in arg1.
pub fn handle_invoke(args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let cap_cptr = args.arg0;
    let label = args.arg1;

    // Self-invocations (cap_cptr = SELF_CAP sentinel)
    if cap_cptr == numbers::SELF_CAP {
        return dispatch_self(label, args);
    }

    // Resolve the capability and check invocation rights
    let cap = ipc::lookup_cap_any(cap_cptr)?;
    let required = minimum_invoke_rights(cap.obj_type, label);
    if !cap.rights.contains(required) {
        return Err(SyscallError::NoRights);
    }

    match cap.obj_type {
        ObjectType::Untyped => dispatch_untyped(label, args),
        ObjectType::Frame | ObjectType::DeviceFrame => dispatch_frame(label, args),
        ObjectType::VSpace => dispatch_vspace(label, args),
        ObjectType::ASIDPool => dispatch_asid_pool(label, args),
        ObjectType::CNode => dispatch_cnode(label, args),
        ObjectType::TCB => dispatch_tcb(label, args, ctx),
        ObjectType::IRQHandler => dispatch_irq_handler(label, args),
        ObjectType::IRQControl => dispatch_irq_control(label, args, ctx),
        ObjectType::TimerControl => dispatch_timer_control(label, args),
        ObjectType::Timer => dispatch_timer(label, args),
        ObjectType::SmmuControl => dispatch_smmu_control(label, args),
        ObjectType::IOSpace => dispatch_iospace(label, args),
        ObjectType::DmaPool => dispatch_dma_pool(label, args),
        _ => Err(SyscallError::TypeMismatch),
    }
}

// -- Invocation rights policy
//
// Centralised rights check for all object invocations. Determines the
// minimum CapRights required on the invoked capability for a given
// (object_type, method_label) pair. Checked once in handle_invoke before
// any handler runs — this prevents privilege escalation through
// attenuated (e.g. READ-only) capabilities.

fn minimum_invoke_rights(obj_type: ObjectType, label: u64) -> CapRights {
    match obj_type {
        // Frame: read-only query vs mutating write
        ObjectType::Frame | ObjectType::DeviceFrame => match label {
            method::frame::GET_PHYS => CapRights::READ,
            _ => CapRights::WRITE,
        },

        // TCB: reading registers is non-mutating
        ObjectType::TCB => match label {
            method::tcb::READ_REGS => CapRights::READ,
            _ => CapRights::WRITE,
        },

        // Singleton control caps require full authority
        ObjectType::IRQControl => CapRights::ALL,
        ObjectType::TimerControl => CapRights::ALL,

        // All other types and methods: WRITE
        _ => CapRights::WRITE,
    }
}

// -- Arg repacking helpers
//
// The Invoke ABI packs args as: x0=cap, x1=label, x2-x6=method args.
// Existing handlers expect: arg0=cap, arg1-arg5=handler-specific args.
// These helpers translate between the two layouts.

/// Repack args for standard object invocations.
///
/// Maps: arg0=cap(same), arg1=x2, arg2=x3, arg3=x4, arg4=x5, arg5=x6.
#[inline]
fn shift_args(args: &SyscallArgs) -> SyscallArgs {
    SyscallArgs {
        arg0: args.arg0,
        arg1: args.arg2,
        arg2: args.arg3,
        arg3: args.arg4,
        arg4: args.arg5,
        arg5: args.arg6,
        arg6: 0,
    }
}

/// Repack args for self-invocations (cap_cptr = SELF_CAP).
///
/// Maps: arg0=x2, arg1=x3, arg2=x4, arg3=x5, arg4=x6.
#[inline]
fn self_args(args: &SyscallArgs) -> SyscallArgs {
    SyscallArgs {
        arg0: args.arg2,
        arg1: args.arg3,
        arg2: args.arg4,
        arg3: args.arg5,
        arg4: args.arg6,
        arg5: 0,
        arg6: 0,
    }
}

/// Repack args for CNode copy/move where depths are reordered.
///
/// Invoke sends: x0=dest_cnode, x1=label, x2=dest_idx, x3=src_cnode,
///               x4=src_idx, x5=dest_depth, x6=src_depth
/// Handler expects: arg0=dest_cnode, arg1=dest_idx, arg2=dest_depth,
///                  arg3=src_cnode, arg4=src_idx, arg5=src_depth
#[inline]
fn cnode_copy_move_args(args: &SyscallArgs) -> SyscallArgs {
    SyscallArgs {
        arg0: args.arg0,
        arg1: args.arg2,
        arg2: args.arg5,
        arg3: args.arg3,
        arg4: args.arg4,
        arg5: args.arg6,
        arg6: 0,
    }
}

// -- Per-type dispatchers

fn dispatch_self(label: u64, args: &SyscallArgs) -> SyscallResult {
    let repacked = self_args(args);
    match label {
        method::current::EXIT => tcb_ops::handle_tcb_exit(&repacked),
        method::current::SLEEP => tcb_ops::handle_tcb_sleep(&repacked),
        method::current::GET_RANDOM => misc_ops::handle_get_random(&repacked),
        method::current::CACHE_CLEAN => cache_ops::handle_cache_clean(&repacked),
        method::current::CACHE_INVALIDATE => cache_ops::handle_cache_invalidate(&repacked),
        method::current::CACHE_FLUSH => cache_ops::handle_cache_flush(&repacked),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_untyped(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::untyped::RETYPE => mem_ops::handle_retype(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_frame(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::frame::GET_PHYS => mem_ops::handle_frame_get_phys(&shift_args(args)),
        method::frame::WRITE => mem_ops::handle_frame_write(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_vspace(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::vspace::MAP_FRAME => mem_ops::handle_map_frame(&shift_args(args)),
        method::vspace::UNMAP_FRAME => mem_ops::handle_unmap_frame(&shift_args(args)),
        method::vspace::MAP_PAGE_TABLE => mem_ops::handle_map_page_table(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_asid_pool(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::asid_pool::ASSIGN => asid_ops::handle_asid_pool_assign(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_cnode(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::cnode::COPY => cap_ops::handle_cap_copy(&cnode_copy_move_args(args)),
        method::cnode::MOVE => cap_ops::handle_cap_move(&cnode_copy_move_args(args)),
        method::cnode::MINT => cap_ops::handle_cap_mint(&shift_args(args)),
        method::cnode::DELETE => cap_ops::handle_cap_delete(&shift_args(args)),
        method::cnode::REVOKE => cap_ops::handle_cap_revoke(&shift_args(args)),
        method::cnode::MUTATE => cap_ops::handle_cap_mutate(&shift_args(args)),
        method::cnode::ROTATE => cap_ops::handle_cap_rotate(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_tcb(label: u64, args: &SyscallArgs, ctx: &mut ExceptionContext) -> SyscallResult {
    let repacked = shift_args(args);
    match label {
        method::tcb::CONFIGURE => tcb_ops::handle_tcb_configure(&repacked),
        method::tcb::WRITE_REGS => tcb_ops::handle_tcb_write_registers(&repacked, ctx),
        method::tcb::READ_REGS => tcb_ops::handle_tcb_read_registers(&repacked, ctx),
        method::tcb::RESUME => tcb_ops::handle_tcb_resume(&repacked),
        method::tcb::SUSPEND => tcb_ops::handle_tcb_suspend(&repacked),
        method::tcb::SET_PRIORITY => tcb_ops::handle_tcb_set_priority(&repacked),
        method::tcb::BIND_NOTIF => tcb_ops::handle_tcb_bind_notification(&repacked),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_irq_handler(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::irq_handler::ACK => irq_ops::handle_irq_ack(&shift_args(args)),
        method::irq_handler::SET_HANDLER => irq_ops::handle_irq_set_handler(&shift_args(args)),
        method::irq_handler::CLEAR_HANDLER => irq_ops::handle_irq_clear_handler(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_irq_control(
    label: u64,
    args: &SyscallArgs,
    ctx: &mut ExceptionContext,
) -> SyscallResult {
    match label {
        method::irq_control::GET => irq_ops::handle_irq_control_get(&shift_args(args)),
        method::irq_control::MSI_ALLOCATE => irq_ops::handle_msi_allocate(&shift_args(args), ctx),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_timer_control(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::timer_control::GET => timer_ops::handle_timer_control_get(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_timer(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::timer::BIND => timer_ops::handle_timer_bind(&shift_args(args)),
        method::timer::ARM => timer_ops::handle_timer_arm(&shift_args(args)),
        method::timer::CANCEL => timer_ops::handle_timer_cancel(&shift_args(args)),
        method::timer::CLEAR => timer_ops::handle_timer_clear(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_smmu_control(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::smmu_control::CREATE_IOSPACE => iommu_ops::handle_iospace_create(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_iospace(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::iospace::CREATE_DMA_POOL => iommu_ops::handle_dma_pool_create(&shift_args(args)),
        method::iospace::MAP_FRAME => iommu_ops::handle_iospace_map_frame(&shift_args(args)),
        method::iospace::UNMAP_FRAME => iommu_ops::handle_iospace_unmap_frame(&shift_args(args)),
        method::iospace::BIND_STREAM => iommu_ops::handle_iospace_bind_stream(&shift_args(args)),
        method::iospace::UNBIND_STREAM => {
            iommu_ops::handle_iospace_unbind_stream(&shift_args(args))
        }
        method::iospace::SET_FAULT_HANDLER => {
            iommu_ops::handle_iospace_set_fault_handler(&shift_args(args))
        }
        _ => Err(SyscallError::InvalidArg),
    }
}

fn dispatch_dma_pool(label: u64, args: &SyscallArgs) -> SyscallResult {
    match label {
        method::dma_pool::ALLOC => iommu_ops::handle_dma_pool_alloc(&shift_args(args)),
        method::dma_pool::FREE => iommu_ops::handle_dma_pool_free(&shift_args(args)),
        _ => Err(SyscallError::InvalidArg),
    }
}
