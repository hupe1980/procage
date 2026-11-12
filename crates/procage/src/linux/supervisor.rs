//! The supervisor of a run whose seccomp filter notifies: it answers every
//! call the filter hands it, and records the refused ones when the run
//! reports violations.
//!
//! The filter notifies a listener instead of failing at once
//! (`SECCOMP_RET_USER_NOTIF`) for two kinds of rules:
//!
//! - with violation reporting, every `EPERM` deny: the supervisor answers
//!   `EPERM` (what the call returns without reporting), then records it;
//! - under `Exec::Never`, `execve` and `execveat` (`Action::Supervise`):
//!   the exec the child sequence issues to start the program goes through
//!   (`CONTINUE`), every later one is refused (`EPERM`).
//!
//! The child hands the listener to the parent before its exec and keeps no
//! copy. With supervised exec it also hands over the read end of the *exec
//! sentinel*, a pipe whose write end only the child holds, close-on-exec:
//! the kernel closes it while it replaces the child with the program,
//! before any instruction of the program runs. A supervised call while the
//! sentinel is open comes from the child sequence (std's `execvp`, any
//! `PATH` candidate), where nothing of the caller runs; once it has hung up,
//! the program runs, and every exec is refused. No argument is checked, so
//! the `CONTINUE` race (arguments changed after the check) does not apply.
//!
//! `Command::spawn` returns only after the exec, so the supervisor starts
//! before it: it waits for the hand-over until the child sends it or the
//! parent wakes it (the spawn returned, or failed). When no process of the
//! run uses the filter any more, the listener hangs up: every call of the
//! run has then been answered (and recorded), which is what makes the
//! record complete. If the supervisor were gone, the kernel would answer
//! `ENOSYS`: the call stays refused, an exec included.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::SystemTime;

use procage_policy::linux::{Action, SeccompRule, Syscall};

use super::{seccomp, sys};
use crate::violation::{DeniedBy, Sink, Violation, lock};

/// What the hand-over gave.
pub(crate) enum Started {
    /// The supervisor serves the run; the flag is set once the listener has
    /// hung up (no process of the run uses the filter any more).
    Serving(Arc<AtomicBool>),
    /// The kernel refused a listener (the errno); the plain filter is in
    /// force (reporting only: supervised exec fails the spawn instead).
    Refused(i32),
    /// Nothing arrived from the child (the errno of the last receive).
    Missing(i32),
}

/// A supervisor waiting for the hand-over of a spawn in progress. Dropping
/// it (or [`Pending::started`]) wakes it once the spawn has returned.
pub(crate) struct Pending {
    wake: Option<OwnedFd>,
    started: mpsc::Receiver<Started>,
}

impl Pending {
    /// The spawn returned: what the hand-over gave.
    pub(crate) fn started(mut self) -> Started {
        drop(self.wake.take());
        self.started.recv().unwrap_or(Started::Missing(libc::EPIPE))
    }
}

/// Starts the supervisor of one run on the parent's end `socket`, before
/// the spawn; `record` when the run reports violations.
pub(crate) fn start(
    socket: OwnedFd,
    rules: Arc<[SeccompRule]>,
    record: Option<Sink>,
) -> std::io::Result<Pending> {
    let (wake_read, wake_write) = sys::pipe()?;
    let (tell, started) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("procage-supervisor".into())
        .spawn(move || {
            // The child sends before its exec; the parent wakes this thread
            // when the spawn returned, and then the message, if any, is
            // already there.
            while !sys::wait_either(&socket, &wake_read, 1000) {
                if sys::hung_up(&wake_read) {
                    break;
                }
            }
            let (listener, sentinel) = match sys::receive(&socket) {
                Ok(sys::HandOver::Listener(listener, sentinel)) => (listener, sentinel),
                Ok(sys::HandOver::Refused(errno)) => {
                    let _ = tell.send(Started::Refused(errno));
                    return;
                }
                Err(errno) => {
                    let _ = tell.send(Started::Missing(errno));
                    return;
                }
            };
            let done = Arc::new(AtomicBool::new(false));
            let _ = tell.send(Started::Serving(done.clone()));
            drop(tell);
            supervise(&listener, sentinel.as_ref(), &rules, record.as_ref());
            done.store(true, Ordering::Release);
        })?;
    Ok(Pending {
        wake: Some(wake_write),
        started,
    })
}

fn supervise(
    listener: &OwnedFd,
    sentinel: Option<&OwnedFd>,
    rules: &[SeccompRule],
    record: Option<&Sink>,
) {
    let numbered: Vec<(u32, &SeccompRule)> = rules
        .iter()
        .filter(|r| matches!(r.action, Action::Eperm | Action::Supervise))
        .filter_map(|r| match (seccomp::NATIVE.number)(&r.syscall) {
            Ok(Some(nr)) => Some((nr, r)),
            _ => None,
        })
        .collect();
    loop {
        match sys::wait_listener(listener, 1000) {
            Ok(sys::Wait::Ready) => {}
            Ok(sys::Wait::Idle) => continue,
            Ok(sys::Wait::HungUp) | Err(_) => return,
        }
        let Ok(n) = sys::receive_notification(listener) else {
            // Withdrawn between the wake-up and the receive.
            continue;
        };
        let rule = numbered
            .iter()
            .find(|(nr, r)| *nr == n.nr && r.condition.matches(&n.args))
            .map(|(_, r)| *r);
        // The run's own exec: the sentinel is open, so the program has not
        // started yet. Anything else is refused.
        if rule.is_some_and(|r| r.action == Action::Supervise)
            && sentinel.is_some_and(|s| !sys::hung_up(s))
        {
            let _ = sys::answer_continue(listener, n.id);
            continue;
        }
        // Answered before anything else is done with it. ENOENT: withdrawn.
        // The kernel gives the calling thread; the violation names its
        // process. The caller is blocked until the answer, so the name is
        // read first and checked against a withdrawn call (a reused id).
        let Some(record) = record else {
            let _ = sys::answer_eperm(listener, n.id);
            continue;
        };
        let (pid, name) = process_of(n.pid)
            .filter(|_| sys::notification_valid(listener, n.id))
            .unwrap_or((n.pid, "?".to_string()));
        let _ = sys::answer_eperm(listener, n.id);
        let violation = Violation {
            pid,
            process: name,
            operation: rule.map_or_else(|| format!("syscall {}", n.nr), |r| r.syscall.to_string()),
            target: rule.and_then(|r| target(&r.syscall, &n.args)),
            denied_by: rule.map_or(DeniedBy::Unknown("unmatched".into()), |r| {
                DeniedBy::from_reason(r.reason)
            }),
            received: SystemTime::now(),
            repeats: 1,
        };
        lock(record).push(violation);
    }
}

/// The process (thread group) of thread `tid` and its name.
fn process_of(tid: u32) -> Option<(u32, String)> {
    let status = std::fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    let tgid: u32 = status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))?
        .trim()
        .parse()
        .ok()?;
    let name = std::fs::read_to_string(format!("/proc/{tgid}/comm")).ok()?;
    Some((tgid, name.trim_end().to_string()))
}

/// What a refused call was aimed at, where its arguments name it.
fn target(syscall: &Syscall, args: &[u64; 6]) -> Option<String> {
    let low = |n: usize| args[n] as u32;
    match syscall {
        Syscall::Socket => Some(format!("family {}", family(low(0)))),
        Syscall::Ioctl => Some(match low(1) {
            0x5412 => "command TIOCSTI".to_string(),
            0x541c => "command TIOCLINUX".to_string(),
            c => format!("command {c:#x}"),
        }),
        Syscall::Clone => Some(format!("flags {:#x}", low(0))),
        Syscall::Open => Some(format!("flags {:#o}", low(1))),
        Syscall::Openat => Some(format!("flags {:#o}", low(2))),
        Syscall::Kill | Syscall::Tkill => Some(format!("pid {}", args[0] as i32)),
        Syscall::Tgkill => Some(format!("pid {}", args[1] as i32)),
        Syscall::Ptrace => Some(format!("pid {}", args[1] as i32)),
        _ => None,
    }
}

fn family(af: u32) -> String {
    match af as i32 {
        libc::AF_UNIX => "AF_UNIX".into(),
        libc::AF_INET => "AF_INET".into(),
        libc::AF_INET6 => "AF_INET6".into(),
        libc::AF_NETLINK => "AF_NETLINK".into(),
        libc::AF_PACKET => "AF_PACKET".into(),
        libc::AF_VSOCK => "AF_VSOCK".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_name_what_the_arguments_name() {
        let args = |a0: u64, a1: u64, a2: u64| [a0, a1, a2, 0, 0, 0];
        assert_eq!(
            target(&Syscall::Socket, &args(libc::AF_INET as u64, 1, 0)).as_deref(),
            Some("family AF_INET")
        );
        assert_eq!(
            target(&Syscall::Ioctl, &args(0, 0x5412, 0)).as_deref(),
            Some("command TIOCSTI")
        );
        assert_eq!(
            target(&Syscall::Openat, &args(0, 0, 0o1000)).as_deref(),
            Some("flags 0o1000")
        );
        assert_eq!(target(&Syscall::Setsid, &args(0, 0, 0)), None);
    }
}
