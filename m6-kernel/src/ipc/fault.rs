//! Fault delivery to user fault handlers.
//!
//! When a user thread faults, the kernel delivers a fault message to
//! the thread's `fault_endpoint` (if configured). The fault handler
//! can then handle the fault (e.g., map a page) and reply to resume
//! the faulted thread.
//!
//! # Fault Delivery Flow
//!
//! 1. User thread faults (e.g., page fault)
//! 2. Kernel captures fault context (ELR, FAR, ESR)
//! 3. Kernel checks if TCB has a fault endpoint
//! 4. If yes: deliver fault message via Call semantics
//!    - Thread blocks waiting for reply
//!    - Handler receives fault message with badge identifying the thread
//!    - Handler can inspect/modify thread state, map pages, etc.
//!    - Handler replies to resume the thread
//! 5. If no: thread is terminated (no handler = fatal fault)
//!
//! # Message Format
//!
//! The fault message uses the standard 6-register IPC format:
//! - x0: fault_type
//! - x1: faulting_pc (ELR)
//! - x2: fault_address (FAR)
//! - x3: esr_raw
//! - x4: flags
//! - x5: reserved
//! - x6 (badge): identifies the faulting thread

use m6_arch::exceptions::ExceptionContext;
use m6_arch::registers::esr;
use m6_cap::objects::{FaultMessage, FaultType, ThreadState};
use m6_cap::ObjectRef;

use crate::cap::object_table::{self, KernelObjectType};
use crate::ipc::message::IpcMessage;

/// Fault delivery error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDeliveryError {
    /// No fault endpoint configured for this thread.
    NoFaultEndpoint,
    /// Invalid fault endpoint (doesn't exist or wrong type).
    InvalidEndpoint,
    /// Failed to create reply object.
    ReplyCreationFailed,
}

/// Classify an exception into a semantic fault type.
///
/// Maps ARM64 exception classes to the higher-level `FaultType` enum
/// that is delivered to fault handlers.
#[must_use]
pub fn classify_fault(ec: u8) -> FaultType {
    match ec {
        // Data aborts (page faults)
        esr::ec::DATA_ABORT_LOWER | esr::ec::DATA_ABORT_SAME => FaultType::PageFault,

        // Instruction aborts
        esr::ec::INSTRUCTION_ABORT_LOWER | esr::ec::INSTRUCTION_ABORT_SAME => {
            FaultType::InstructionFault
        }

        // Alignment faults
        esr::ec::PC_ALIGNMENT | esr::ec::SP_ALIGNMENT => FaultType::AlignmentFault,

        // Debug exceptions
        esr::ec::BREAKPOINT_LOWER
        | esr::ec::BREAKPOINT_SAME
        | esr::ec::WATCHPOINT_LOWER
        | esr::ec::WATCHPOINT_SAME
        | esr::ec::SOFTWARE_STEP_LOWER
        | esr::ec::SOFTWARE_STEP_SAME
        | esr::ec::BRK_AARCH64 => FaultType::DebugFault,

        // Illegal execution state
        esr::ec::ILLEGAL_EXECUTION => FaultType::IllegalState,

        // Floating-point exceptions
        esr::ec::FP_EXCEPTION | esr::ec::FP_EXCEPTION_AARCH32 => FaultType::FpException,

        // Unknown/other
        _ => FaultType::Unknown,
    }
}

/// Build a fault message from an exception context.
///
/// Extracts fault information from the saved exception context and
/// packages it into a `FaultMessage` for delivery to the handler.
#[must_use]
pub fn build_fault_message(ctx: &ExceptionContext, fault_type: FaultType) -> FaultMessage {
    let ec = ctx.exception_class();
    let iss = esr::iss(ctx.esr);
    let flags = m6_cap::objects::fault::flags::pack(iss, ec);

    FaultMessage::new(fault_type, ctx.elr, ctx.far, ctx.esr, flags)
}

/// Deliver a fault to a thread's fault endpoint.
///
/// This function implements Call semantics: the faulting thread sends
/// a fault message and blocks waiting for a reply. When the handler
/// replies, the thread resumes execution.
///
/// # Arguments
///
/// * `tcb_ref` - Reference to the faulting thread's TCB
/// * `fault_msg` - The fault message to deliver
///
/// # Returns
///
/// * `Ok(())` - Fault delivered, thread is now blocked on reply
/// * `Err(NoFaultEndpoint)` - No fault endpoint configured
/// * `Err(InvalidEndpoint)` - Endpoint doesn't exist or wrong type
/// * `Err(ReplyCreationFailed)` - Failed to create reply object
pub fn deliver_fault(
    tcb_ref: ObjectRef,
    fault_msg: &FaultMessage,
) -> Result<(), FaultDeliveryError> {
    // Get the fault endpoint from the TCB
    let fault_ep: ObjectRef = object_table::with_tcb(tcb_ref, |tcb| tcb.tcb.fault_endpoint);

    if !fault_ep.is_valid() {
        return Err(FaultDeliveryError::NoFaultEndpoint);
    }

    // Verify it's actually an endpoint
    let is_endpoint = object_table::with_object(fault_ep, |obj| {
        obj.obj_type == KernelObjectType::Endpoint
    })
    .unwrap_or(false);

    if !is_endpoint {
        return Err(FaultDeliveryError::InvalidEndpoint);
    }

    // Create IPC message from fault message
    let ipc_msg = IpcMessage::from_regs(fault_msg.to_regs());

    // Create a reply object for the faulting thread
    let reply_ref = create_fault_reply(tcb_ref)?;

    // Store reply reference in the TCB
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.reply_slot = reply_ref;
    });

    // Get the badge for this TCB (we use the TCB's object index as badge)
    // This allows the handler to identify which thread faulted
    let badge = tcb_ref.index() as u64;

    // Try to deliver the fault message
    object_table::with_endpoint_mut(fault_ep, |endpoint| {
        use m6_cap::objects::EndpointState;
        use crate::ipc::queue::{ipc_enqueue, ipc_dequeue};

        match endpoint.state {
            EndpointState::RecvQueue => {
                // Handler is waiting - deliver immediately
                let handler_ref =
                    ipc_dequeue(&mut endpoint.queue_head, &mut endpoint.queue_tail)
                        .expect("RecvQueue but empty queue");

                if endpoint.queue_head.is_null() {
                    endpoint.state = EndpointState::Idle;
                }

                // Transfer fault message to handler
                transfer_fault_message(handler_ref, &ipc_msg, badge);

                // Give handler the reply capability
                let _: () = object_table::with_tcb_mut(handler_ref, |tcb| {
                    tcb.tcb.caller = reply_ref;
                });

                // Block faulting thread waiting for reply
                let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
                    tcb.tcb.state = ThreadState::BlockedOnReply;
                    tcb.ipc_blocked_on = ObjectRef::NULL;
                });

                // Remove faulting thread from run queue
                crate::sched::remove_task(tcb_ref);

                // Wake handler
                wake_handler(handler_ref);
            }

            EndpointState::Idle | EndpointState::SendQueue => {
                // No handler waiting - queue the fault
                // Store message in faulting thread's TCB
                let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
                    tcb.ipc_message = ipc_msg.regs;
                    tcb.ipc_badge = badge;
                    tcb.tcb.state = ThreadState::BlockedOnSend;
                    tcb.ipc_blocked_on = fault_ep;
                });

                // Add to endpoint's send queue
                endpoint.state = EndpointState::SendQueue;
                ipc_enqueue(&mut endpoint.queue_head, &mut endpoint.queue_tail, tcb_ref);

                // Remove from run queue
                crate::sched::remove_task(tcb_ref);
            }
        }
    });

    Ok(())
}

/// Create a reply object for a faulting thread.
fn create_fault_reply(tcb_ref: ObjectRef) -> Result<ObjectRef, FaultDeliveryError> {
    use core::mem::ManuallyDrop;
    use m6_cap::objects::ReplyObject;

    let reply_ref = object_table::alloc(KernelObjectType::Reply)
        .ok_or(FaultDeliveryError::ReplyCreationFailed)?;

    object_table::with_object_mut(reply_ref, |obj| {
        obj.data.reply = ManuallyDrop::new(ReplyObject::new(tcb_ref));
    });

    Ok(reply_ref)
}

/// Transfer fault message to handler's context.
fn transfer_fault_message(handler_ref: ObjectRef, msg: &IpcMessage, badge: u64) {
    let _: () = object_table::with_tcb_mut(handler_ref, |tcb| {
        msg.to_context(&mut tcb.context);
        tcb.context.gpr[6] = badge;
    });
}

/// Wake the fault handler thread.
fn wake_handler(handler_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(handler_ref, |tcb| {
        tcb.tcb.state = ThreadState::Running;
        tcb.ipc_blocked_on = ObjectRef::NULL;
        tcb.clear_ipc_state();
    });

    crate::sched::insert_task(handler_ref);
}

/// Handle a user fault by delivering it to the fault endpoint.
///
/// This is the main entry point called from the exception handler.
/// It builds the fault message, attempts delivery, and handles
/// the case where no fault endpoint is configured.
///
/// # Arguments
///
/// * `tcb_ref` - Reference to the faulting thread's TCB
/// * `ctx` - Exception context with fault details
/// * `fault_type` - Classified fault type
///
/// # Returns
///
/// * `true` - Fault was delivered (or thread was terminated)
/// * `false` - Current thread should continue (shouldn't happen for faults)
pub fn handle_user_fault(tcb_ref: ObjectRef, ctx: &ExceptionContext, fault_type: FaultType) -> bool {
    let fault_msg = build_fault_message(ctx, fault_type);

    log::debug!(
        "User fault: type={:?} pc={:#x} addr={:#x} esr={:#x}",
        fault_type,
        ctx.elr,
        ctx.far,
        ctx.esr
    );

    match deliver_fault(tcb_ref, &fault_msg) {
        Ok(()) => {
            log::debug!("Fault delivered to handler, thread blocked on reply");
            true
        }
        Err(FaultDeliveryError::NoFaultEndpoint) => {
            // No fault handler - terminate the thread
            log::warn!(
                "No fault endpoint for thread {:?}, terminating. Fault: {:?} at {:#x}",
                tcb_ref,
                fault_type,
                ctx.elr
            );
            terminate_thread(tcb_ref);
            true
        }
        Err(e) => {
            log::error!("Failed to deliver fault: {:?}", e);
            terminate_thread(tcb_ref);
            true
        }
    }
}

/// Terminate a thread due to an unhandled fault.
///
/// Sets the thread state to Inactive and removes it from the run queue.
/// The thread will not be scheduled again.
fn terminate_thread(tcb_ref: ObjectRef) {
    let _: () = object_table::with_tcb_mut(tcb_ref, |tcb| {
        tcb.tcb.state = ThreadState::Inactive;
        tcb.ipc_blocked_on = ObjectRef::NULL;
    });

    crate::sched::remove_task(tcb_ref);

    log::info!("Thread {:?} terminated due to unhandled fault", tcb_ref);
}
