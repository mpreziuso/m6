// Forked from Fuchsia's starnix_uapi, adapted for M6 (no_std, ARM64 only).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.

use crate::errors::Errno;
use crate::{error, uapi};

#[derive(Clone, Copy, PartialEq)]
#[repr(usize)]
pub enum ElfNoteType {
    PrStatus = uapi::NT_PRSTATUS as usize,
    FpRegSet = uapi::NT_PRFPREG as usize,
    ArmTaggedAddrCtrl = uapi::NT_ARM_TAGGED_ADDR_CTRL as usize,
    ArmPacEnabledKeys = uapi::NT_ARM_PAC_ENABLED_KEYS as usize,
}

impl TryFrom<usize> for ElfNoteType {
    type Error = Errno;

    fn try_from(v: usize) -> Result<Self, Errno> {
        match v {
            x if x == ElfNoteType::PrStatus as usize => Ok(ElfNoteType::PrStatus),
            x if x == ElfNoteType::FpRegSet as usize => Ok(ElfNoteType::FpRegSet),
            x if x == ElfNoteType::ArmTaggedAddrCtrl as usize => {
                // TODO: NT_ARM_TAGGED_ADDR_CTRL not yet implemented
                error!(ENOTSUP)
            }
            x if x == ElfNoteType::ArmPacEnabledKeys as usize => {
                // TODO: NT_ARM_PAC_ENABLED_KEYS not yet implemented
                error!(ENOTSUP)
            }
            _ => error!(EINVAL),
        }
    }
}
