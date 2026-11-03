//! Spawning on a tokio runtime (feature `tokio`): the std path's child
//! sequence and run handling, with an awaitable child and a violation
//! stream.

use std::io;
use std::ops::{Deref, DerefMut};
use std::os::fd::BorrowedFd;
use std::path::Path;

use crate::native::{Cage, Child, Grants, SpawnError};
use crate::unix::Proc;
use crate::{Audit, Receipt, Violation, ViolationStream, Violations};

impl Cage {
    /// Spawns `command` in this cage on the current tokio runtime, with
    /// `grants` bound for this spawn: [`Cage::spawn`] for async code.
    ///
    /// The checks, the child sequence and the errors are the std path's: the
    /// sequence is installed on the command's std half and tokio spawns it.
    /// Fails with [`SpawnError::NoRuntime`] before forking when no tokio
    /// runtime runs on the calling thread. The runtime needs its I/O driver
    /// (`enable_io`), as every tokio child process does.
    pub fn spawn_async(
        &self,
        command: &mut tokio::process::Command,
        grants: &Grants,
    ) -> Result<AsyncChild, SpawnError> {
        self.spawn_async_with_fds(command, grants, &[])
    }

    /// Like [`Cage::spawn_async`], and also hands `fds` to the child, as
    /// [`Cage::spawn_with_fds`] does.
    pub fn spawn_async_with_fds(
        &self,
        command: &mut tokio::process::Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
    ) -> Result<AsyncChild, SpawnError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(SpawnError::NoRuntime);
        }
        let launch = self.launch(command.as_std_mut(), grants, fds)?;
        let spawned = command.spawn();
        launch.release(command.as_std_mut());
        match spawned {
            Ok(inner) => Ok(AsyncChild(
                self.adopt(launch, Proc::Tokio(std::panic::AssertUnwindSafe(inner))),
            )),
            Err(e) => Err(launch.abandon(e)),
        }
    }
}

/// A running caged child on a tokio runtime (feature `tokio`).
///
/// It dereferences to [`tokio::process::Child`] for I/O and waiting, and
/// otherwise behaves as [`Child`]: the run ends when the handle is dropped
/// or [`AsyncChild::kill_all`] is awaited, not when the child exits by
/// itself, and ending it kills every process of the run. Dropping it works
/// inside and outside a runtime. `tokio::process::Child::kill`, reachable
/// through `Deref`, kills only the direct child.
#[derive(Debug)]
pub struct AsyncChild(Child);

impl AsyncChild {
    /// Ends the run, as [`Child::kill_all`] does, awaiting the child's exit.
    /// The last step (the marker search and the record's fence on macOS)
    /// runs on the calling task and takes milliseconds.
    pub async fn kill_all(&mut self) -> io::Result<()> {
        self.0.signal()?;
        let waited = self.deref_mut().wait().await.map(drop);
        self.0.end(waited)
    }

    /// The run's [audits](crate::audit), as [`Child::audit`].
    pub fn audit(&mut self) -> Option<Audit> {
        self.0.audit()
    }

    /// The run's [receipt](crate::Receipt), as [`Child::receipt`]: `None`
    /// until the child has exited (awaited, or seen by `try_wait`).
    pub fn receipt(&mut self) -> Option<Receipt> {
        self.0.receipt()
    }

    /// The operations the sandbox denied this run so far, as
    /// [`Child::violations`].
    pub fn violations(&mut self) -> Violations {
        self.0.violations()
    }

    /// The run's violations as they arrive, once, as an async stream that
    /// ends when the record is complete or the run ends; `None` when
    /// reporting is off or unavailable, or when this or
    /// [`AsyncChild::violation_receiver`] was called before.
    pub fn violation_stream(&mut self) -> Option<ViolationStream> {
        self.0.violation_stream()
    }

    /// The run's violations on a std channel, once, as
    /// [`Child::violation_receiver`].
    pub fn violation_receiver(&mut self) -> Option<std::sync::mpsc::Receiver<Violation>> {
        self.0.violation_receiver()
    }

    /// Gives up lifetime control, as [`Child::detach`]; the tokio child
    /// then follows its own `kill_on_drop` setting.
    pub fn detach(self) -> tokio::process::Child {
        match self.0.release() {
            Proc::Tokio(c) => c.0,
            Proc::Std(_) => unreachable!("an async handle holds a tokio child"),
        }
    }

    /// The controller side of the run's new terminal (`Tty::NewPty`), once;
    /// see `Child::take_pty`.
    pub fn take_pty(&mut self) -> Option<crate::Pty> {
        self.0.take_pty()
    }

    /// Environment names the passthrough denylist dropped for this spawn.
    pub fn dropped_env(&self) -> &[String] {
        self.0.dropped_env()
    }

    /// The run's private temporary directory (`TMPDIR`), when the policy
    /// declares the `tmpdir` grant.
    pub fn tmpdir(&self) -> Option<&Path> {
        self.0.tmpdir()
    }
}

impl Deref for AsyncChild {
    type Target = tokio::process::Child;

    fn deref(&self) -> &tokio::process::Child {
        match self.0.inner() {
            Proc::Tokio(c) => &c.0,
            Proc::Std(_) => unreachable!("an async handle holds a tokio child"),
        }
    }
}

impl DerefMut for AsyncChild {
    fn deref_mut(&mut self) -> &mut tokio::process::Child {
        match self.0.inner_mut() {
            Proc::Tokio(c) => &mut c.0,
            Proc::Std(_) => unreachable!("an async handle holds a tokio child"),
        }
    }
}
