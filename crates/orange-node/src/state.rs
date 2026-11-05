//! Where a node keeps its chain state (spec 22): in memory, as `orange dev`
//! and the simulator do, or on disk in a [`DiskStore`] under its data
//! directory, which a restarted node opens and resumes from. Both keep the
//! history window of spec 20 §5 and the trie behind every kept header
//! root; the node drives either through [`ChainState`].

use std::collections::BTreeMap;
use std::path::PathBuf;

use orange_host::{MemStorage, Storage, Writes};
#[cfg(feature = "fault-injection")]
use orange_store::Fault;
use orange_store::{DiskStore, StoreError, StoreStats};
use orange_trie::Trie;

/// Where [`crate::Node::open`] keeps the chain state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum StoreConfig {
    /// In memory: gone when the node is.
    #[default]
    Memory,
    /// On disk, in [`orange_store::CHAIN_FILE`] under this directory, which a
    /// node opened over the same directory later resumes from.
    Disk(PathBuf),
}

/// The in-memory state: the store with its history, the trie behind each
/// kept header root, and the genesis root.
#[derive(Debug, Default)]
pub struct MemState {
    storage: MemStorage,
    committed: BTreeMap<u64, Trie>,
    genesis: Option<[u8; 32]>,
}

/// The chain state of a node, in memory or on disk.
#[derive(Debug)]
pub enum ChainState {
    /// In memory.
    Memory(Box<MemState>),
    /// On disk.
    Disk(Box<DiskStore>),
}

/// In memory: what the simulator, `orange dev` without a data directory and
/// the host-function tests run over.
impl Default for ChainState {
    fn default() -> ChainState {
        ChainState::Memory(Box::default())
    }
}

/// A store error, as the node reports it; by value, as `map_err` takes it.
#[allow(clippy::needless_pass_by_value)]
fn store_error(e: StoreError) -> crate::NodeError {
    crate::NodeError::Store(e.to_string())
}

impl ChainState {
    /// Opens the state `config` names.
    ///
    /// # Errors
    /// What opening the disk store reports.
    pub fn open(config: &StoreConfig) -> Result<ChainState, crate::NodeError> {
        Ok(match config {
            StoreConfig::Memory => ChainState::Memory(Box::default()),
            StoreConfig::Disk(dir) => {
                ChainState::Disk(Box::new(DiskStore::open(dir).map_err(store_error)?))
            }
        })
    }

    /// Whether the genesis has not been applied yet: a memory state before
    /// its first seal, a disk store a previous run never sealed.
    #[must_use]
    pub fn is_fresh(&self) -> bool {
        match self {
            ChainState::Memory(m) => m.genesis.is_none(),
            ChainState::Disk(d) => d.is_fresh(),
        }
    }

    /// The disk store, if the state is on disk.
    #[must_use]
    pub fn disk(&self) -> Option<&DiskStore> {
        match self {
            ChainState::Memory(_) => None,
            ChainState::Disk(d) => Some(d),
        }
    }

    /// Injects `fault` into the disk store's next commit; nothing in memory.
    /// Only in builds with the `fault-injection` feature, for tests.
    #[cfg(feature = "fault-injection")]
    pub fn inject(&mut self, fault: Fault) {
        if let ChainState::Disk(d) = self {
            d.inject(fault);
        }
    }

    /// What the disk store has done; `None` in memory.
    #[must_use]
    pub fn stats(&self) -> Option<StoreStats> {
        self.disk().map(DiskStore::stats)
    }

    /// The latest sealed version: the executed height, 0 before any.
    #[must_use]
    pub fn head(&self) -> u64 {
        self.versions().map_or(0, |(_, latest)| latest)
    }

    /// The code hash of the kernel that last wrote the state, when it is on
    /// disk and a previous run wrote it.
    #[must_use]
    pub fn kernel(&self) -> Option<[u8; 32]> {
        self.disk().and_then(DiskStore::kernel)
    }

    /// Records the kernel that writes from now on.
    pub fn set_kernel(&mut self, kernel: [u8; 32]) {
        if let ChainState::Disk(d) = self {
            d.set_kernel(kernel);
        }
    }

    /// The state commitment of the genesis state, once sealed.
    #[must_use]
    pub fn genesis_root(&self) -> Option<[u8; 32]> {
        match self {
            ChainState::Memory(m) => m.genesis,
            ChainState::Disk(d) => d.genesis_root(),
        }
    }

    /// Seals the genesis state as version 0. Its trie is `committed`, the
    /// trie behind the root the genesis header carries (spec 20 §3.1),
    /// which the kernel took before it stored that header; the state's own
    /// without one, under a kernel that stores no genesis header.
    ///
    /// # Errors
    /// What the disk store reports.
    pub fn seal_genesis(&mut self, committed: Option<Trie>) -> Result<(), crate::NodeError> {
        match self {
            ChainState::Memory(m) => {
                m.storage.keep_history(0);
                let genesis = committed.unwrap_or_else(|| m.storage.state_trie());
                m.genesis = Some(genesis.root());
                m.committed.insert(0, genesis);
                Ok(())
            }
            ChainState::Disk(d) => d.seal(0, committed.as_ref()).map_err(store_error),
        }
    }

    /// Seals the block at `height`: what was written since the last seal
    /// becomes its history, and `committed`, the trie behind the root its
    /// header carries (none when the kernel asked for no root), is kept to
    /// prove against.
    ///
    /// # Errors
    /// What the disk store reports; nothing of the block is then on disk.
    pub fn seal(&mut self, height: u64, committed: Option<Trie>) -> Result<(), crate::NodeError> {
        match self {
            ChainState::Memory(m) => {
                m.storage.seal(height);
                m.committed.extend(committed.map(|trie| (height, trie)));
                Ok(())
            }
            ChainState::Disk(d) => d.seal(height, committed.as_ref()).map_err(store_error),
        }
    }

    /// Writes what was written since the last seal without sealing: after a
    /// finalization or a kernel switch. Nothing in memory.
    ///
    /// # Errors
    /// What the disk store reports.
    pub fn flush(&mut self) -> Result<(), crate::NodeError> {
        match self {
            ChainState::Memory(_) => Ok(()),
            ChainState::Disk(d) => d.flush().map_err(store_error),
        }
    }

    /// Forgets the versions below `oldest`: their history and their tries.
    ///
    /// # Errors
    /// What the disk store reports.
    pub fn prune(&mut self, oldest: u64) -> Result<(), crate::NodeError> {
        match self {
            ChainState::Memory(m) => {
                m.storage.prune(oldest);
                let kept = m.storage.versions().map_or(0, |(oldest, _)| oldest);
                m.committed = m.committed.split_off(&kept);
                Ok(())
            }
            ChainState::Disk(d) => d.prune(oldest).map_err(store_error),
        }
    }

    /// The versions the state can read as (see [`MemStorage::versions`]).
    #[must_use]
    pub fn versions(&self) -> Option<(u64, u64)> {
        match self {
            ChainState::Memory(m) => m.storage.versions(),
            ChainState::Disk(d) => d.versions(),
        }
    }

    /// How many key writes the history holds (see [`MemStorage::history_keys`]).
    #[must_use]
    pub fn history_keys(&self) -> usize {
        match self {
            ChainState::Memory(m) => m.storage.history_keys(),
            ChainState::Disk(d) => d.history_keys(),
        }
    }

    /// The oldest version readable within `keys` key writes of history (see
    /// [`MemStorage::oldest_within`]).
    #[must_use]
    pub fn oldest_within(&self, keys: usize) -> u64 {
        match self {
            ChainState::Memory(m) => m.storage.oldest_within(keys),
            ChainState::Disk(d) => d.oldest_within(keys),
        }
    }

    /// Makes reads see a sealed version (see [`MemStorage::set_view`]).
    ///
    /// # Errors
    /// The versions the state can read as.
    pub fn set_view(&mut self, version: Option<u64>) -> Result<(), Option<(u64, u64)>> {
        match self {
            ChainState::Memory(m) => m.storage.set_view(version),
            ChainState::Disk(d) => d.set_view(version),
        }
    }

    /// The trie behind the header root of `height`, if kept.
    #[must_use]
    pub fn trie_at(&self, height: u64) -> Option<Trie> {
        match self {
            ChainState::Memory(m) => m.committed.get(&height).cloned(),
            ChainState::Disk(d) => d.trie_at(height),
        }
    }
}

impl Storage for ChainState {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        match self {
            ChainState::Memory(m) => m.storage.get(key),
            ChainState::Disk(d) => d.get(key),
        }
    }

    fn set(&mut self, key: &[u8], value: &[u8]) {
        match self {
            ChainState::Memory(m) => m.storage.set(key, value),
            ChainState::Disk(d) => d.set(key, value),
        }
    }

    fn delete(&mut self, key: &[u8]) -> bool {
        match self {
            ChainState::Memory(m) => m.storage.delete(key),
            ChainState::Disk(d) => d.delete(key),
        }
    }

    fn scan(&self, prefix: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        match self {
            ChainState::Memory(m) => m.storage.scan(prefix),
            ChainState::Disk(d) => d.scan(prefix),
        }
    }

    fn state_trie(&self) -> Trie {
        match self {
            ChainState::Memory(m) => m.storage.state_trie(),
            ChainState::Disk(d) => d.state_trie(),
        }
    }

    fn merge_layer(&mut self, writes: Writes, trie: Trie) {
        match self {
            ChainState::Memory(m) => m.storage.merge_layer(writes, trie),
            ChainState::Disk(d) => d.merge_layer(writes, trie),
        }
    }
}
