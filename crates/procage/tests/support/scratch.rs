//! Scratch directories for the caged tests, removed when the test is done.

use std::path::{Path, PathBuf};

/// A directory under the system temp dir, removed on drop; derefs to its
/// path.
#[derive(Debug)]
pub struct Scratch(PathBuf);

impl Scratch {
    /// A fresh directory at `dir` (an earlier one there is removed first).
    pub fn at(dir: PathBuf) -> Scratch {
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// The same directory, its path canonicalised (the Linux tests).
    #[allow(dead_code)]
    pub fn canonical(self) -> Scratch {
        let path = std::fs::canonicalize(&self.0).unwrap();
        let mut this = self;
        this.0 = path;
        this
    }
}

impl std::ops::Deref for Scratch {
    type Target = PathBuf;
    fn deref(&self) -> &PathBuf {
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
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
