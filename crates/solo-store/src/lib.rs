//! Chain state on disk (spec 22).
//!
//! [`DiskStore`] keeps a node's chain state in one `redb` file under its
//! data directory: the flat state, the nodes of the spec 10 trie behind
//! every root the node still serves, the history window of spec 20 §5 (the
//! value every committed key held before each block changed it) and the
//! block log, all written in one transaction per executed block, so that a
//! crash between blocks leaves the state of the last block and a crash
//! inside a block's write leaves the state of the block before. It
//! implements [`solo_host::Storage`], so the executor runs the kernel over
//! it exactly as over the in-memory store, and the trie it maintains loads
//! its nodes from the file on demand ([`solo_trie::NodeSource`]), so a
//! restarted node opens in constant time.
//!
//! [`snapshot`] is the committee-signed state snapshot: a file holding the
//! state at an epoch boundary, the record the kernel wrote for it and the
//! finality certificate that vouches for the record, which a new node
//! verifies before it serves anything.

#![forbid(unsafe_code)]

pub mod disk;
pub mod snapshot;

#[cfg(any(test, feature = "fault-injection"))]
pub use disk::Fault;
pub use disk::{
    CHAIN_FILE, CREATING_FILE, DiskStore, Entries, Frozen, NotKept, StoreError, StoreStats,
};
pub use snapshot::{
    EntryReader, Export, ExportLimits, Snapshot, SnapshotError, SnapshotHeader, Trust,
};
