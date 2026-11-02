//! The handle of a caged child: it kills the child and its descendants when
//! dropped, and removes the run's private temporary directory.

use std::io;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};

use super::lifetime::{self, Run};
use super::sys;
use super::violations::{self, Sink};
use crate::unix::Proc;
use crate::violation::{Coverage, Violation, Violations};

/// What a spawn reports: whether the run's marker finds its processes
/// (a forking policy), and the run's violation record, when reporting.
#[derive(Debug)]
pub(super) struct Reporting {
    pub(super) forking: bool,
    pub(super) record: Option<Sink>,
}

/// A running caged child.
///
/// It dereferences to [`std::process::Child`] for I/O and waiting. The run
/// ends when the handle is dropped or [`Child::kill_all`] is called, not when
/// the child exits by itself. Ending it kills the child's process group,
/// every descendant that can still be found from the child, and, when the
/// policy allows forking, every process whose sandbox carries the run's
/// marker: descendants that started their own session and were reparented
/// to `launchd`, also after the child exited. Then it reaps the child.
/// [`Child::detach`] gives up that control.
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
    run: Option<Run>,
    reporting: Reporting,
    /// The record as it was when the run ended.
    ended: Option<Violations>,
    /// What the run's receipt is made of.
    receipt: crate::receipt::RunFacts,
    /// The caller ended the run while it was running.
    killed: bool,
    /// The run's audits.
    audit: crate::audit::RunAudit,
}

impl Child {
    pub(super) fn new(
        inner: Proc,
        dropped_env: Vec<String>,
        tmpdir: Option<PathBuf>,
        run: Option<Run>,
        reporting: Reporting,
        receipt: crate::receipt::RunFacts,
        audit: crate::audit::RunAudit,
    ) -> Self {
        Self {
            pid: inner.pid(),
            inner: Some(inner),
            dropped_env,
            tmpdir,
            run,
            reporting,
            ended: None,
            receipt,
            killed: false,
            audit,
        }
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

    /// Ends the run: kills the child's process group, every descendant
    /// reachable from the child and every process carrying the run's marker,
    /// then waits for the child.
    ///
    /// Fails when processes of the run are still found after 64 rounds of
    /// search and kill (the error names them; for example a process running
    /// as another user after executing a set-user-id program). Between a
    /// process being found and killed, it could exit and its pid be reused;
    /// macOS has no process handle that would close that window.
    pub fn kill_all(&mut self) -> io::Result<()> {
        self.signal()?;
        // Reaped first, the child no longer shows up in the marker search.
        let waited = self.inner_mut().wait().map(drop);
        self.end(waited)
    }

    /// The first half of ending the run: kills the descendants still
    /// reachable from a running child, and the child's process group.
    pub(crate) fn signal(&mut self) -> io::Result<()> {
        let pid =
            libc::pid_t::try_from(self.pid).map_err(|_| io::Error::other("pid out of range"))?;
        if self.inner_mut().try_wait()?.is_none() {
            self.killed = true;
            for descendant in sys::descendants(pid) {
                sys::kill(descendant);
            }
        }
        // The group outlives a reaped leader while members remain, and its
        // id cannot be handed to another process while it exists.
        sys::killpg(pid);
        Ok(())
    }

    /// The second half, once the child is reaped (`waited`): the marker
    /// search and the record.
    pub(crate) fn end(&mut self, waited: io::Result<()>) -> io::Result<()> {
        let ended = match &self.run {
            Some(run) if self.reporting.forking => lifetime::end(run),
            _ => Ok(()),
        };
        // Every denial of the run must have arrived before its marker can tag
        // another run's; without a fence the slot is retired instead.
        let delivered = self.finish_record();
        ended?;
        // No process carries the marker any more: another run may have it.
        if let Some(run) = self.run.take()
            && delivered
        {
            run.free();
        }
        waited
    }

    /// Fences the run's record, marks it complete and stops routing to it;
    /// `true` without a record or when the fence passed.
    fn finish_record(&mut self) -> bool {
        let Some(record) = self.reporting.record.take() else {
            return true;
        };
        let record = &record;
        // Always a fresh fence: descendants killed just now may have been
        // denied after an earlier one.
        let delivered = violations::fence();
        if delivered {
            violations::lock(record).finish();
        }
        if let Some(run) = &self.run {
            violations::unregister(run.marker());
        }
        violations::lock(record).close();
        // The handle keeps a copy for `violations` after the run ended.
        self.ended = Some(violations::lock(record).snapshot());
        delivered
    }

    /// The operations the sandbox denied this run so far, with the kind of
    /// rule behind each (see [`crate::violation`]).
    ///
    /// Once the child has exited, this first waits (at most a second) until
    /// every denial reported before that has arrived; the record then says
    /// it is [`complete`](Violations::complete). A record that is not
    /// complete after the child exited (a loaded host) can be read again.
    /// Without [`CageOptions::with_violations`](super::CageOptions::with_violations)
    /// the record's coverage is [`Coverage::Off`].
    pub fn violations(&mut self) -> Violations {
        let Some(record) = self.reporting.record.clone() else {
            return self
                .ended
                .clone()
                .unwrap_or_else(|| Violations::empty(Coverage::Off));
        };
        let exited = self
            .inner
            .as_mut()
            .is_some_and(|c| matches!(c.try_wait(), Ok(Some(_))));
        if exited && !violations::lock(&record).is_complete() && violations::fence() {
            violations::lock(&record).finish();
        }
        violations::lock(&record).snapshot()
    }

    /// The run's violations as they arrive, once (later calls return
    /// `None`); `None` as well when reporting is off or unavailable. The
    /// receiver buffers 1,024 violations; when it lags, later ones are only
    /// in [`Child::violations`].
    pub fn violation_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<Violation>> {
        let record = self.reporting.record.as_ref()?;
        let mut record = violations::lock(record);
        if record.snapshot().coverage() != &Coverage::Observed {
            return None;
        }
        record.take_receiver()
    }

    #[cfg(feature = "tokio")]
    pub(crate) fn violation_stream(&mut self) -> Option<crate::ViolationStream> {
        let record = self.reporting.record.as_ref()?;
        let mut record = violations::lock(record);
        if record.snapshot().coverage() != &Coverage::Observed {
            return None;
        }
        record.take_stream()
    }

    /// Gives up lifetime control: the child keeps running after this handle
    /// is gone. The private temporary directory, if any, is left in place,
    /// and the run's marker is never given to another run of this process.
    pub fn detach(self) -> std::process::Child {
        match self.release() {
            Proc::Std(c) => c,
            #[cfg(feature = "tokio")]
            Proc::Tokio(_) => unreachable!("an async handle detaches through AsyncChild"),
        }
    }

    pub(crate) fn release(mut self) -> Proc {
        self.tmpdir = None;
        if let (Some(_), Some(run)) = (&self.reporting.record, &self.run) {
            violations::unregister(run.marker());
        }
        self.reporting.record = None;
        self.run = None;
        self.inner
            .take()
            .unwrap_or_else(|| unreachable!("present until drop or detach"))
    }

    pub(super) fn run(&self) -> Option<&Run> {
        self.run.as_ref()
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
