// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::task::{CurrentTask, Kernel, Task};

/// An object that can be either a Kernel or a CurrentTask.
///
/// This allows to retrieve the Kernel from it, and the task if it is available.
pub trait KernelOrTask<'a>: m6_starnix_std::fmt::Debug + Clone + Copy {
    fn kernel(&self) -> &'a Kernel;
    fn maybe_task(&self) -> Option<&'a CurrentTask>;
}

impl<'a> KernelOrTask<'a> for &'a Kernel {
    fn kernel(&self) -> &'a Kernel {
        self
    }
    fn maybe_task(&self) -> Option<&'a CurrentTask> {
        None
    }
}

impl<'a> KernelOrTask<'a> for &'a CurrentTask {
    fn kernel(&self) -> &'a Kernel {
        (self as &Task).kernel()
    }
    fn maybe_task(&self) -> Option<&'a CurrentTask> {
        Some(self)
    }
}
