// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
mod anon_node;
mod dir_entry;
mod dirent_sink;
mod epoll;
mod fd_number;
mod fd_table;
mod file_object;
mod file_system;
mod file_write_guard;
mod fs_context;
mod lru_map;
mod fs_node;
mod memory_regular;
mod namespace;
mod record_locks;
mod splice;
mod symlink_node;
mod userfault_file;
mod wd_number;
mod xattr;

pub mod aio;
pub mod buffers;
pub mod eventfd;
#[cfg(feature = "fuchsia")]
pub mod file_server;
pub mod fs_args;
pub mod fs_node_cache;
pub mod fs_registry;
pub mod fsverity;
pub mod inotify;
pub mod io_uring;
pub mod memory_directory;
pub mod path;
pub mod pidfd;
pub mod pipe;
pub mod pseudo;
pub mod rw_queue;
#[cfg(feature = "fuchsia")]
pub mod socket;
// Minimal always-on socket *type* layer for the non-Fuchsia (first-light) build.
// See socket_min.rs — supplies SocketAddress/SocketHandle/UnixSocket so the
// VFS/task core compiles without the full zxio/netlink socket subsystem.
#[cfg(not(feature = "fuchsia"))]
#[path = "socket_min.rs"]
pub mod socket;
pub mod syscalls;
// timerfd's TimerFile is built on the gated HrTimer/zx-timer subsystem; the
// timerfd syscalls fall back to ENOSYS in the minimal core (see vfs/syscalls.rs).
#[cfg(feature = "fuchsia")]
pub mod timer;

pub use anon_node::*;
pub use buffers::*;
pub use dir_entry::*;
pub use dirent_sink::*;
pub use epoll::*;
pub use fd_number::*;
pub use fd_table::*;
pub use file_object::*;
pub use file_system::*;
pub use file_write_guard::*;
pub use fs_context::*;
pub use fs_node::*;
pub use memory_directory::*;
pub use memory_regular::*;
pub use namespace::*;
pub use path::*;
pub use pidfd::*;
pub use record_locks::*;
pub use symlink_node::*;
pub use userfault_file::*;
pub use wd_number::*;
pub use xattr::*;
