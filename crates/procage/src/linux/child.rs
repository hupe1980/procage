//! The handle of a caged child: it kills the child and its descendants when
//! dropped, and removes the run's private temporary directory.

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use crate::unix::Proc;
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
/// the child exits by itself. Ending it kills the child's session and process
/// group and every descendant that can still be found from the child, then
/// reaps the child. Under the default
/// [`Lifetime::Run`](procage_policy::Lifetime::Run) no process of the run can
/// leave the child's session (`setsid` fails; process groups stay in it), so
/// the session kill reaches all of them, also after the child exited. With
/// `Lifetime::Tree`, a descendant whose parent exits in a session of its own
/// is out of reach. [`Child::detach`] gives up that control.
///
/// `std::process::Child::kill`, reachable through `Deref`, kills only the
/// direct child.
#[derive(Debug)]
pub struct Child {
    inner: Option<Proc>,
    /// The child's pid, which is also its process group's id.
    pid: u32,
    dropped_env: Vec<String>,
    tmpdir: Option<PathBuf>,
    reporting: Reporting,
    /// What the run's receipt is made of.
    receipt: crate::receipt::RunFacts,
    /// The caller ended the run while it was running.
    killed: bool,
    /// The run's audits.
    audit: crate::audit::RunAudit,
    /// The run's proxy; dropped when the run ends.
    #[cfg(feature = "proxy")]
    proxy: Option<procage_proxy::Run>,
    /// The controller of the run's new terminal, until taken.
    pty: Option<crate::Pty>,
}

impl Child {
    pub(super) fn new(
        inner: Proc,
        dropped_env: Vec<String>,
        tmpdir: Option<PathBuf>,
        reporting: Reporting,
        receipt: crate::receipt::RunFacts,
        audit: crate::audit::RunAudit,
    ) -> Self {
        Self {
            pid: inner.pid(),
            inner: Some(inner),
            dropped_env,
            tmpdir,
            reporting,
            receipt,
            killed: false,
            audit,
            #[cfg(feature = "proxy")]
            proxy: None,
            pty: None,
        }
    }

    pub(super) fn set_pty(&mut self, pty: Option<crate::Pty>) {
        self.pty = pty;
    }

    /// The controller side of the run's new terminal (`Tty::NewPty`), once:
    /// `None` without one or after the first call. Until it is taken the
    /// handle holds it, and ending the run closes it.
    pub fn take_pty(&mut self) -> Option<crate::Pty> {
        self.pty.take()
    }

    #[cfg(feature = "proxy")]
    pub(super) fn set_proxy(&mut self, run: Option<procage_proxy::Run>) {
        self.proxy = run;
    }

    /// The run's [audits](crate::audit): `None` while the child runs. Once it
    /// has exited, this ends the run (as [`Child::kill_all`] does), so no
    /// descendant writes after the walk, and gives the link check's findings
    /// (report mode) and, with the handoff audit, what the run created or
    /// changed.
    pub fn audit(&mut self) -> Option<crate::Audit> {
        self.inner_mut().try_wait().ok()??;
        let ended = self.kill_all().is_ok();
        Some(self.audit.finish(ended))
    }

    /// The run's [receipt](crate::Receipt): `None` while the child runs,
    /// the receipt once it has exited (after [`wait`](std::process::Child::wait),
    /// or once [`try_wait`](std::process::Child::try_wait) saw it exit). It
    /// ends the run (as [`Child::kill_all`] does) so its audit summary covers
    /// a finished run.
    pub fn receipt(&mut self) -> Option<crate::Receipt> {
        let status = self.inner_mut().try_wait().ok()??;
        // The audit's second walk needs the run over, as `audit` does.
        let ended = self.kill_all().is_ok();
        let record = self.violations();
        let audit = self.audit.finish(ended);
        Some(self.receipt.receipt(status, &record, self.killed, &audit))
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

    pub(crate) fn inner(&self) -> &Proc {
        self.inner
            .as_ref()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    pub(crate) fn inner_mut(&mut self) -> &mut Proc {
        self.inner
            .as_mut()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    /// Kills the child, the descendants reachable from it, and the child's
    /// session and process group, then waits for the child.
    pub fn kill_all(&mut self) -> io::Result<()> {
        self.signal()?;
        let waited = self.inner_mut().wait().map(drop);
        self.end(waited)
    }

    /// The first half of ending the run: kills the descendants still
    /// reachable from a running child, the child's session and its process
    /// group.
    pub(crate) fn signal(&mut self) -> io::Result<()> {
        let pid =
            libc::pid_t::try_from(self.pid).map_err(|_| io::Error::other("pid out of range"))?;
        let running = self.inner_mut().running()?;
        if running {
            // Found before the child dies (its children are reparented when
            // it exits); the child is killed first, so it cannot see a
            // descendant die and exit by itself.
            let below = descendants(pid);
            sys::kill(pid);
            for descendant in below {
                sys::kill(descendant);
            }
        }
        // The child leads its own session unless it shares the caller's
        // terminal; under `Lifetime::Run` no descendant can leave it, though
        // it may start process groups. Once the child is reaped its pid may
        // be reused, but not while the session has a member: a live process
        // with that pid means no member is left, and the session or group
        // of that id is another's.
        if running || !sys::alive(pid) {
            kill_session(pid);
        }
        self.killed |= running;
        Ok(())
    }

    /// The second half, once the child is reaped (`waited`): the record.
    pub(crate) fn end(&mut self, waited: io::Result<()>) -> io::Result<()> {
        // The run's connections close with it, before its record does.
        #[cfg(feature = "proxy")]
        drop(self.proxy.take());
        // No process of the run is left: the listener hangs up at once.
        if let Reporting::On { done, .. } = &self.reporting {
            let start = Instant::now();
            while !done.load(Ordering::Acquire) && start.elapsed() < Duration::from_secs(2) {
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        self.settle();
        if let Reporting::On { record, .. } = &self.reporting {
            lock(record).close();
        }
        waited
    }

    /// Gives up lifetime control: the child keeps running after this handle
    /// is gone. The private temporary directory, if any, is left in place.
    pub fn detach(self) -> std::process::Child {
        match self.release() {
            Proc::Std(c) => c,
            #[cfg(feature = "tokio")]
            Proc::Tokio(_) => unreachable!("an async handle detaches through AsyncChild"),
        }
    }

    pub(crate) fn release(mut self) -> Proc {
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

    #[cfg(feature = "tokio")]
    pub(crate) fn violation_stream(&mut self) -> Option<crate::ViolationStream> {
        match &self.reporting {
            Reporting::On { record, .. } => lock(record).take_stream(),
            _ => None,
        }
    }
}

/// Kills every live process of session `sid`, then process group `sid`.
/// Members forked meanwhile are found by the next look. The session and the
/// group outlive a reaped leader while members remain, and their id cannot
/// be handed to another process while they exist.
pub(super) fn kill_session(sid: libc::pid_t) {
    let mut killed = Vec::new();
    for _ in 0..64 {
        let members: Vec<libc::pid_t> = processes()
            .into_iter()
            .filter(|p| p.session == sid && !p.zombie && !killed.contains(&p.pid))
            .map(|p| p.pid)
            .collect();
        if members.is_empty() {
            break;
        }
        for member in members {
            sys::kill(member);
            killed.push(member);
        }
    }
    sys::killpg(sid);
}

/// Every process with its parent and session, from `/proc/<pid>/stat`
/// (readable for every process, unlike the `children` lists, which some
/// kernels lack).
fn processes() -> Vec<Process> {
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|e| {
            let pid: libc::pid_t = e.file_name().to_str()?.parse().ok()?;
            let stat = std::fs::read_to_string(e.path().join("stat")).ok()?;
            // `pid (comm) state ppid pgrp session ...`; comm may contain
            // spaces and ')'.
            let mut rest = stat[stat.rfind(')')? + 1..].split_whitespace();
            let zombie = rest.next()? == "Z";
            let ppid = rest.next()?.parse().ok()?;
            let session = rest.nth(1)?.parse().ok()?;
            Some(Process {
                pid,
                ppid,
                session,
                zombie,
            })
        })
        .collect()
}

/// One process, from `/proc/<pid>/stat`.
struct Process {
    pid: libc::pid_t,
    ppid: libc::pid_t,
    session: libc::pid_t,
    zombie: bool,
}

/// Every process below `pid` that can still be found from it.
fn descendants(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let all = processes();
    let mut out = Vec::new();
    let mut queue = vec![pid];
    while let Some(p) = queue.pop() {
        for proc in &all {
            if proc.ppid == p && !out.contains(&proc.pid) {
                out.push(proc.pid);
                queue.push(proc.pid);
            }
        }
    }
    out
}

impl Deref for Child {
    type Target = std::process::Child;

    fn deref(&self) -> &std::process::Child {
        match self.inner() {
            Proc::Std(c) => c,
            #[cfg(feature = "tokio")]
            Proc::Tokio(_) => unreachable!("an async handle derefs through AsyncChild"),
        }
    }
}

impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut std::process::Child {
        match self.inner_mut() {
            Proc::Std(c) => c,
            #[cfg(feature = "tokio")]
            Proc::Tokio(_) => unreachable!("an async handle derefs through AsyncChild"),
        }
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
