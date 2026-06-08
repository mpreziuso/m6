// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
// The cpu sysfs class exposes Fuchsia CPU-control FIDL (cpu_ctrl / power_cpu);
// gated until M6 has a native CPU performance interface.
#[cfg(feature = "fuchsia")]
mod cpu_class_directory;
mod device_directory;
mod fs;
mod kernel_directory;
// The sysfs power directory exposes Fuchsia-backed suspend/resume controls; M6
// has no power service, so it is gated until a native one exists.
#[cfg(feature = "fuchsia")]
mod power_directory;

#[cfg(feature = "fuchsia")]
pub use cpu_class_directory::*;
pub use device_directory::*;
pub use fs::*;
pub use kernel_directory::*;
#[cfg(feature = "fuchsia")]
pub use power_directory::*;
