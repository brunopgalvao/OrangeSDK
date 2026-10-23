//! Work a node runs on threads of its own, off the loop that steps the
//! driver: the snapshot export of a serving node (spec 22 §7.4). What
//! it produces comes back to the node loop, which takes it up between
//! steps; a node that shuts down calls the work off and waits for it.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use solo_store::{Export, ExportLimits, Snapshot, SnapshotError};

/// A snapshot export running on its own thread over a frozen store.
pub struct ExportJob {
    epoch: u64,
    cancel: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<Snapshot, SnapshotError>>>,
}

impl ExportJob {
    /// Starts `export` on a thread. While `hold` is set the thread waits
    /// before it begins: what tests use to keep an export running.
    #[must_use]
    pub fn start(export: Export, hold: Arc<AtomicBool>) -> ExportJob {
        let cancel = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&cancel);
        let epoch = export.epoch();
        let handle = std::thread::spawn(move || {
            while hold.load(Ordering::Relaxed) && !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            export.run(ExportLimits::default(), &stop)
        });
        ExportJob {
            epoch,
            cancel,
            handle: Some(handle),
        }
    }

    /// The epoch being exported.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether the export has ended, well or not.
    #[must_use]
    pub fn finished(&self) -> bool {
        self.handle.as_ref().is_none_or(JoinHandle::is_finished)
    }

    /// Waits for the export and takes what it produced; an export whose
    /// thread panicked reports it as an I/O error.
    ///
    /// # Errors
    /// What the export reports.
    pub fn join(mut self) -> Result<Snapshot, SnapshotError> {
        let panicked = SnapshotError::Io("the export thread panicked".to_owned());
        let joined = self.handle.take().map(JoinHandle::join);
        joined.map_or(Err(SnapshotError::Cancelled), |j| {
            j.unwrap_or(Err(panicked))
        })
    }
}

impl Drop for ExportJob {
    /// Calls the export off and waits for its thread, which stops at its
    /// next entry and removes its scratch.
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}
