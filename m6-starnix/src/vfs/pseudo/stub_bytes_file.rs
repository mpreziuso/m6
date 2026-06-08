// Forked from Fuchsia's Starnix for M6 (no_std, ARM64 only).
// Original: Copyright 2024 The Fuchsia Authors. BSD license.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#[allow(unused_imports)] use m6_starnix_std::prelude::*;
use crate::task::CurrentTask;
use crate::vfs::pseudo::simple_file::{BytesFile, BytesFileOps, SimpleFileNode};
use crate::vfs::{FileObject, FsNodeOps};
use bstr::ByteSlice;
use starnix_logging::BugRef;
use starnix_sync::{FileOpsCore, Locked, Mutex};
use starnix_uapi::errors::Errno;
use m6_starnix_std::borrow::Cow;
use m6_starnix_std::panic::Location;
use m6_starnix_std::sync::Arc;

#[derive(Clone)]
pub struct StubBytesFile {
    data: Arc<Mutex<Vec<u8>>>,
    bug: BugRef,
    location: &'static Location<'static>,
}

impl StubBytesFile {
    #[track_caller]
    pub fn new_node(bug: BugRef) -> impl FsNodeOps {
        Self::new_node_with_data(bug, vec![])
    }

    #[track_caller]
    pub fn new_node_with_data(bug: BugRef, initial_data: impl Into<Vec<u8>>) -> impl FsNodeOps {
        let location = Location::caller();
        let file = BytesFile::new(StubBytesFile {
            data: Arc::new(Mutex::new(initial_data.into())),
            bug,
            location,
        });
        SimpleFileNode::new(move |_, _| Ok(file.clone()))
    }
}

impl BytesFileOps for StubBytesFile {
    fn write(&self, _current_task: &CurrentTask, data: Vec<u8>) -> Result<(), Errno> {
        *self.data.lock() = data;
        Ok(())
    }
    fn read(&self, _current_task: &CurrentTask) -> Result<Cow<'_, [u8]>, Errno> {
        Ok(self.data.lock().clone().into())
    }

    fn open(
        &self,
        _locked: &mut Locked<FileOpsCore>,
        file: &FileObject,
        current_task: &CurrentTask,
    ) -> Result<(), Errno> {
        let path = file.name.path(current_task);
        starnix_logging::__track_stub_inner(
            self.bug,
            path.to_str_lossy().as_ref(),
            None,
            self.location,
        );
        Ok(())
    }
}
