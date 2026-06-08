// An RCU-protected string.

use fuchsia_rcu::{RcuCell, RcuReadScope};
use starnix_types::string::{FsStr, FsString};

/// An RCU-protected string.
///
/// Wraps an `RcuCell<FsString>` and provides a convenient API for reading the
/// string as an `FsStr` within an `RcuReadScope`.
#[derive(Debug, Default)]
pub struct RcuString {
    cell: RcuCell<FsString>,
}

impl RcuString {
    /// Create a new `RcuString`.
    pub fn new(value: impl Into<FsString>) -> Self {
        Self {
            cell: RcuCell::new(value.into()),
        }
    }

    /// Read the string value.
    ///
    /// The returned `FsStr` is valid for the duration of the `RcuReadScope`.
    pub fn read<'a>(&self, scope: &'a RcuReadScope) -> &'a FsStr {
        self.cell.as_ref(scope).as_ref()
    }

    /// Update the string value.
    ///
    /// Replaces the underlying `FsString`. Readers holding an `RcuReadScope`
    /// continue to see the old value until they drop the scope.
    pub fn update(&self, value: impl Into<FsString>) {
        self.cell.update(value.into());
    }
}

impl From<FsString> for RcuString {
    fn from(value: FsString) -> Self {
        Self::new(value)
    }
}

impl From<&FsStr> for RcuString {
    fn from(value: &FsStr) -> Self {
        Self::new(value)
    }
}
