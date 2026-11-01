//! The handle of a caged child: it kills the child and its descendants when
//! dropped, and removes the run's private temporary directory.

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::violation::{Coverage, Sink, Violation, Violations, lock};

use super::sys;

/// A spawn's violation reporting.
#[derive(Debug)]
pub(super) enum Reporting {
    /// The cage was built without it.
    Off,
    /// No listener (the reason); the kernel answers refused calls.
    Unavailable(String),
    /// The supervisor records into `record` and sets `done` when no process
    /// of the run is left.
    On { record: Sink, done: Arc<AtomicBool> },
}

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
    reporting: Reporting,
    /// What the run's receipt is made of.
    receipt: crate::receipt::RunFacts,
    /// The caller ended the run while it was running.
    killed: bool,
}

impl Child {
    pub(super) fn new(
        inner: std::process::Child,
        dropped_env: Vec<String>,
        tmpdir: Option<PathBuf>,
        reporting: Reporting,
        receipt: crate::receipt::RunFacts,
    ) -> Self {
        Self {
            inner: Some(inner),
            dropped_env,
            tmpdir,
            reporting,
            receipt,
            killed: false,
        }
    }

    /// The run's [receipt](crate::Receipt): `None` while the child runs,
    /// the receipt once it has exited (after [`wait`](std::process::Child::wait),
    /// or once [`try_wait`](std::process::Child::try_wait) saw it exit).
    pub fn receipt(&mut self) -> Option<crate::Receipt> {
        let status = self.inner_mut().try_wait().ok()??;
        let record = self.violations();
        Some(self.receipt.receipt(status, &record, self.killed))
    }

    /// Marks the record complete once the supervisor is done and the child
    /// reaped: every refused call of the run has then been recorded.
    fn settle(&mut self) {
        let Reporting::On { record, done } = &self.reporting else {
            return;
        };
        let reaped = self
            .inner
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))));
        if !reaped {
            return;
        }
        // The listener hangs up as soon as the last process of the run is
        // gone; a descendant that outlives the child keeps it open.
        let start = Instant::now();
        while !done.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(2));
        }
        if done.load(Ordering::Acquire) {
            lock(record).finish();
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
        let running = child.try_wait()?.is_none();
        if running {
            for descendant in descendants(pid) {
                sys::kill(descendant);
            }
        }
        // The group outlives a reaped leader while members remain, and its
        // id cannot be handed to another process while it exists.
        sys::killpg(pid);
        let waited = child.wait().map(drop);
        self.killed |= running;
        // No process of the run is left: the listener hangs up at once.
        if let Reporting::On { done, .. } = &self.reporting {
            let start = Instant::now();
            while !done.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        self.settle();
        waited
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

    /// The system calls the seccomp filter refused this run so far, with the
    /// kind of rule behind each (see [`crate::violation`]).
    ///
    /// The record is [`complete`](Violations::complete) once the child has
    /// exited and no process of the run is left; a descendant that outlives
    /// the child keeps it open until it exits or [`Child::kill_all`] ends
    /// it. Its coverage is [`Coverage::SystemCalls`]: file, network and
    /// signal denials by Landlock are not in it. Without
    /// [`CageOptions::with_violations`](super::CageOptions::with_violations)
    /// the coverage is [`Coverage::Off`].
    pub fn violations(&mut self) -> Violations {
        self.settle();
        match &self.reporting {
            Reporting::Off => Violations::empty(Coverage::Off),
            Reporting::Unavailable(reason) => {
                Violations::empty(Coverage::Unavailable(reason.clone()))
            }
            Reporting::On { record, .. } => lock(record).snapshot(),
        }
    }

    /// The run's refused calls as they happen, once (later calls return
    /// `None`); `None` as well when reporting is off or unavailable. The
    /// receiver buffers 1,024; when it lags, later ones are only in
    /// [`Child::violations`].
    pub fn violation_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<Violation>> {
        match &self.reporting {
            Reporting::On { record, .. } => lock(record).take_receiver(),
            _ => None,
        }
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
