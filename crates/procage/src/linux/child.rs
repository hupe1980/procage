//! The handle of a caged child: it kills the child and its descendants when
//! dropped, and removes the run's private temporary directory.

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use crate::violation::{Coverage, Violation, Violations};

use super::sys;

/// A running caged child.
///
/// It dereferences to [`std::process::Child`] for I/O and waiting. The run
/// ends when the handle is dropped or [`Child::kill_all`] is called, not when
/// the child exits by itself. Ending it kills the child's process group and
/// every descendant that can still be found from the child, then reaps the
/// child. Under the default [`Lifetime::Run`](procage_policy::Lifetime::Run)
/// no process of the run can leave the group (`setsid` and `setpgid` fail),
/// so the group kill reaches all of them, also after the child exited. With
/// `Lifetime::Tree`, a descendant whose parent exits in a session of its own
/// is out of reach. [`Child::detach`] gives up that control.
///
/// `std::process::Child::kill`, reachable through `Deref`, kills only the
/// direct child.
#[derive(Debug)]
pub struct Child {
    inner: Option<std::process::Child>,
    dropped_env: Vec<String>,
    tmpdir: Option<PathBuf>,
    coverage: Coverage,
}

impl Child {
    pub(super) fn new(
        inner: std::process::Child,
        dropped_env: Vec<String>,
        tmpdir: Option<PathBuf>,
        coverage: Coverage,
    ) -> Self {
        Self {
            inner: Some(inner),
            dropped_env,
            tmpdir,
            coverage,
        }
    }

    fn inner(&self) -> &std::process::Child {
        self.inner
            .as_ref()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    fn inner_mut(&mut self) -> &mut std::process::Child {
        self.inner
            .as_mut()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    /// Kills the child's process group and every descendant reachable from
    /// the child, then waits for the child.
    pub fn kill_all(&mut self) -> io::Result<()> {
        let child = self.inner_mut();
        let pid =
            libc::pid_t::try_from(child.id()).map_err(|_| io::Error::other("pid out of range"))?;
        if child.try_wait()?.is_none() {
            for descendant in descendants(pid) {
                sys::kill(descendant);
            }
        }
        // The group outlives a reaped leader while members remain, and its
        // id cannot be handed to another process while it exists.
        sys::killpg(pid);
        child.wait().map(drop)
    }

    /// Gives up lifetime control: the child keeps running after this handle
    /// is gone. The private temporary directory, if any, is left in place.
    pub fn detach(mut self) -> std::process::Child {
        self.tmpdir = None;
        self.inner
            .take()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    /// Environment names the passthrough denylist dropped for this spawn.
    pub fn dropped_env(&self) -> &[String] {
        &self.dropped_env
    }

    /// The run's private temporary directory (`TMPDIR`), when the policy
    /// declares the `tmpdir` grant.
    pub fn tmpdir(&self) -> Option<&Path> {
        self.tmpdir.as_deref()
    }

    /// The operations the sandbox denied this run. Linux does not report
    /// denials yet, so the record is empty and its coverage says so:
    /// [`Coverage::NotObserved`] with
    /// [`CageOptions::with_violations`](super::CageOptions::with_violations),
    /// [`Coverage::Off`] without.
    pub fn violations(&mut self) -> Violations {
        Violations::empty(self.coverage.clone())
    }

    /// Live violations; always `None` on Linux, which reports none yet.
    pub fn violation_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<Violation>> {
        None
    }
}

/// Every process's parent, from `/proc/<pid>/stat` (readable for every
/// process, unlike the `children` lists, which some kernels lack).
fn parents() -> Vec<(libc::pid_t, libc::pid_t)> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let pid: libc::pid_t = e.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
            // `pid (comm) state ppid ...`; comm may contain spaces and ')'.
            let rest = &stat[stat.rfind(')')? + 1..];
            let ppid = rest.split_whitespace().nth(1)?.parse().ok()?;
            Some((pid, ppid))
        })
        .collect()
}

/// Every process below `pid` that can still be found from it.
fn descendants(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let parents = parents();
    let mut out = Vec::new();
    let mut queue = vec![pid];
    while let Some(p) = queue.pop() {
        for &(child, parent) in &parents {
            if parent == p && !out.contains(&child) {
                out.push(child);
                queue.push(child);
            }
        }
    }
    out
}

impl Deref for Child {
    type Target = std::process::Child;

    fn deref(&self) -> &std::process::Child {
        self.inner()
    }
}

impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut std::process::Child {
        self.inner_mut()
    }
}

impl Drop for Child {
    fn drop(&mut self) {
        if self.inner.is_some() {
            let _ = self.kill_all();
        }
        if let Some(dir) = self.tmpdir.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
