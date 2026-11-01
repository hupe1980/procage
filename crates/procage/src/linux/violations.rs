//! The supervisor of a reporting run: it answers every system call the
//! seccomp filter refuses, and records it.
//!
//! With violation reporting, the filter's `EPERM` denies notify a listener
//! instead of failing at once (`SECCOMP_RET_USER_NOTIF`). The child hands
//! the listener to the parent before its exec and keeps no copy. A refused
//! call blocks until the supervisor answers, so the supervisor answers each
//! with `EPERM` (what the call returns without reporting), then records it.
//! When no process of the run uses the filter any more, the listener hangs
//! up: every refused call of the run has then been answered and recorded,
//! which is what makes the record complete. If the supervisor were gone,
//! the kernel would answer `ENOSYS`: the call stays refused.

use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::SystemTime;

use procage_policy::linux::{Action, SeccompRule, Syscall};

use super::{seccomp, sys};
use crate::violation::{DeniedBy, Sink, Violation, lock};

/// Starts the supervisor of one run; the flag is set once the listener has
/// hung up (no process of the run uses the filter any more).
pub(crate) fn start(
    listener: OwnedFd,
    rules: Arc<[SeccompRule]>,
    record: Sink,
) -> std::io::Result<Arc<AtomicBool>> {
    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    std::thread::Builder::new()
        .name("procage-supervisor".into())
        .spawn(move || {
            supervise(&listener, &rules, &record);
            flag.store(true, Ordering::Release);
        })?;
    Ok(done)
}

fn supervise(listener: &OwnedFd, rules: &[SeccompRule], record: &Sink) {
    let numbered: Vec<(u32, &SeccompRule)> = rules
        .iter()
        .filter(|r| r.action == Action::Eperm)
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
        // The kernel gives the calling thread; the violation names its
        // process. The caller is blocked until the answer, so both are still
        // its own; checked against a withdrawn call (a reused id) all the
        // same.
        let (pid, name) = process_of(n.pid)
            .filter(|_| sys::notification_valid(listener, n.id))
            .unwrap_or((n.pid, "?".to_string()));
        // Answered before anything else is done with it. ENOENT: withdrawn.
        let _ = sys::answer_eperm(listener, n.id);
        let rule = numbered
            .iter()
            .find(|(nr, r)| *nr == n.nr && r.condition.matches(&n.args))
            .map(|(_, r)| *r);
        let violation = Violation {
            pid,
            process: name,
            operation: rule.map_or_else(|| format!("syscall {}", n.nr), |r| r.syscall.to_string()),
            target: rule.and_then(|r| target(&r.syscall, &n.args)),
            denied_by: rule.map_or(DeniedBy::Unknown("unmatched".into()), |r| {
                DeniedBy::from_reason(r.reason)
            }),
            received: SystemTime::now(),
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
