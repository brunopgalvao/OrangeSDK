//! Scratch paths for tests. A [`Scratch`] names `orange-<kind>-<pid>-<name>`
//! in the system's temporary directory and removes whatever is there, a
//! file or a whole directory, when it drops: at the end of the test, and
//! when the test panics, as unwinding drops it too. Whatever an earlier,
//! killed run left at the same path is removed when the guard is made.
//!
//! Declare the guard before anything that writes into it, such as a node
//! process or an open store, so that it drops after them. A helper that
//! hands out a plain path, for a file the test reopens later or a store it
//! returns, gives the guard to the test's thread with [`Scratch::keep`]:
//! the test harness runs every test on a thread of its own, and the path
//! goes when that thread ends, after the test and everything it held.

#![forbid(unsafe_code)]

use std::cell::RefCell;
use std::ops::Deref;
use std::path::{Path, PathBuf};

thread_local! {
    /// Guards kept until the current thread, the test's, ends.
    static KEPT: RefCell<Vec<Scratch>> = const { RefCell::new(Vec::new()) };
}

/// A path in the temporary directory, removed when this guard drops.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// `orange-<kind>-<pid>-<name>` in the temporary directory, cleared of
    /// anything there. Nothing is created: the caller writes a file or a
    /// directory there, or leaves that to the code under test.
    #[must_use]
    pub fn new(kind: &str, name: &str) -> Scratch {
        let path =
            std::env::temp_dir().join(format!("orange-{kind}-{}-{name}", std::process::id()));
        remove(&path);
        Scratch(path)
    }

    /// [`Scratch::new`], created as an empty directory.
    ///
    /// # Panics
    ///
    /// If the directory cannot be created.
    #[must_use]
    pub fn dir(kind: &str, name: &str) -> Scratch {
        let scratch = Scratch::new(kind, name);
        std::fs::create_dir_all(&scratch.0).expect("scratch directory");
        scratch
    }

    /// The path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.0
    }

    /// The path, the guard kept until the current thread ends: for a test,
    /// once it has returned or panicked and dropped what it held.
    #[must_use]
    pub fn keep(self) -> PathBuf {
        let path = self.0.clone();
        KEPT.with(|kept| kept.borrow_mut().push(self));
        path
    }

    /// The path as a string.
    ///
    /// # Panics
    ///
    /// If the temporary directory's path is not UTF-8.
    #[must_use]
    pub fn str(&self) -> &str {
        self.0.to_str().expect("UTF-8 temporary directory")
    }
}

impl Deref for Scratch {
    type Target = Path;

    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        remove(&self.0);
    }
}

/// Removes `path`, a directory with everything in it or a file; nothing
/// there is fine.
fn remove(path: &Path) {
    if std::fs::remove_dir_all(path).is_err() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_and_a_file_go_when_their_guards_drop() {
        let dir = Scratch::dir("scratch-unit", "dir");
        assert!(dir.is_dir());
        assert!(
            dir.path()
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("orange-scratch-unit-")
        );
        std::fs::create_dir_all(dir.join("a/b")).unwrap();
        std::fs::write(dir.join("a/b/c"), b"x").unwrap();
        let file = Scratch::new("scratch-unit", "file");
        assert!(!file.exists());
        std::fs::write(&file, b"y").unwrap();
        assert_eq!(std::fs::read(file.str()).unwrap(), b"y");
        let (dir_path, file_path) = (dir.to_path_buf(), file.as_ref().to_path_buf());
        drop(dir);
        drop(file);
        assert!(!dir_path.exists() && !file_path.exists());
        // A guard over nothing drops quietly.
        drop(Scratch::new("scratch-unit", "nothing"));
    }

    #[test]
    fn a_kept_path_goes_when_its_thread_ends() {
        let path = std::thread::spawn(|| {
            let path = Scratch::new("scratch-unit", "kept").keep();
            std::fs::write(&path, b"z").unwrap();
            path
        })
        .join()
        .unwrap();
        assert!(!path.exists());
        // And when the thread panics.
        let (tx, rx) = std::sync::mpsc::channel();
        let panicked = std::thread::spawn(move || {
            let path = Scratch::dir("scratch-unit", "kept-panic").keep();
            tx.send(path).unwrap();
            panic!("the test failed");
        })
        .join();
        assert!(panicked.is_err());
        assert!(!rx.recv().unwrap().exists());
    }

    #[test]
    fn a_new_guard_clears_what_an_earlier_run_left() {
        let path = Scratch::new("scratch-unit", "left").to_path_buf();
        std::fs::create_dir_all(path.join("old")).unwrap();
        let again = Scratch::new("scratch-unit", "left");
        assert!(!again.exists());
        std::fs::write(&path, b"old").unwrap();
        let file = Scratch::dir("scratch-unit", "left");
        assert!(file.is_dir() && std::fs::read_dir(&file).unwrap().next().is_none());
    }
}
