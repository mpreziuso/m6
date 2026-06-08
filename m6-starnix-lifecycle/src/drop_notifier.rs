// Forked from Fuchsia's Starnix for M6 (no_std).
// Original: Copyright 2023 The Fuchsia Authors. BSD license.
//
// M6 adaptation: upstream `DropNotifier` is built on a `zx::EventPair` whose
// peer receives PEER_CLOSED when the notifier drops, plus a `fuchsia_async`
// `RWHandle` waiter. The M6 zx-shim's `EventPair` is currently inert (no real
// signalling yet), so the `event()` handle never actually fires PEER_CLOSED.
// The shape is faithful to upstream so the only consumer (`vfs::pidfd`) compiles;
// the real notification semantics arrive once the zx-shim grows EventPair
// signalling (or an M6-native drop-notification primitive).

use zx::HandleBased;

/// Notifies a waiter when the owning object is dropped.
///
/// An object that needs a client notified on drop keeps a `DropNotifier` as a
/// member; the client requests an [`DropNotifier::event`]. When the notifier is
/// dropped, the local event peer closes, signalling PEER_CLOSED on the returned
/// event pair.
#[derive(Debug)]
pub struct DropNotifier {
    _local_event: zx::EventPair,
    notified_event: zx::EventPair,
}

impl DropNotifier {
    /// Get an event pair that will receive a PEER_CLOSED signal when this object
    /// is dropped.
    pub fn event(&self) -> zx::EventPair {
        self.notified_event
            .duplicate_handle(zx::Rights::SAME_RIGHTS)
            .expect("duplicate event")
    }
}

impl Default for DropNotifier {
    fn default() -> Self {
        let (_local_event, notified_event) = zx::EventPair::create();
        Self {
            _local_event,
            notified_event,
        }
    }
}
