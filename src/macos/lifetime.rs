//! Run markers: how the handle finds every process of a run.
//!
//! A forking policy's profile ends with a block that denies looking up any
//! service name starting with a prefix and allows one such name, the run's
//! marker (see [`procage_policy::RUN_MARKER_PARAM`]). Both are profile
//! parameters, bound here per spawn. The sandbox is inherited by every
//! process the child starts and cannot be changed from inside, so each of
//! them carries the marker wherever it is reparented, and the parent finds
//! them by asking, per process, whether its sandbox allows the marker and
//! denies another name with the prefix (the probe). The caller, unsandboxed
//! processes and sandboxes that allow every lookup allow both names; other
//! sandboxes deny the marker.
//!
//! The prefix is random per process. A marker is free again only after a
//! kill found no process carrying it; until then, and forever after
//! `detach` or a failed kill, no other run of this process gets it.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use procage_policy::{RUN_MARKER_PARAM, RUN_PREFIX_PARAM};

use super::{SpawnError, Unsupported, sys};

/// How many rounds of search and kill end a run before giving up.
pub(crate) const ROUNDS: usize = 64;

/// `org.procage.run.<pid>.<random>.`, once per process.
fn prefix() -> &'static str {
    static PREFIX: OnceLock<String> = OnceLock::new();
    PREFIX.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        // std seeds `RandomState` from the operating system's generator.
        let random = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        format!("org.procage.run.{:x}.{random:016x}.", std::process::id())
    })
}

/// Slots in use or retired.
fn taken() -> &'static Mutex<BTreeSet<u32>> {
    static TAKEN: OnceLock<Mutex<BTreeSet<u32>>> = OnceLock::new();
    TAKEN.get_or_init(Default::default)
}

/// The marker slot of one run. Dropping it retires the slot; only
/// [`Run::free`] makes it available again.
#[derive(Debug)]
pub(crate) struct Run {
    slot: u32,
    marker: CString,
    probe: CString,
}

impl Run {
    /// The lowest slot no live or retired run holds.
    pub(crate) fn take() -> Run {
        let mut taken = taken().lock().unwrap_or_else(|e| e.into_inner());
        let slot = (0..=u32::MAX)
            .find(|s| !taken.contains(s))
            .unwrap_or_else(|| unreachable!("fewer than 2^32 runs"));
        taken.insert(slot);
        Run::of(slot)
    }

    fn of(slot: u32) -> Run {
        let name = |suffix: &str| {
            CString::new(format!("{}{suffix}", prefix()))
                .unwrap_or_else(|_| unreachable!("hex digits and dots only"))
        };
        Run {
            slot,
            marker: name(&slot.to_string()),
            probe: name("probe"),
        }
    }

    /// The profile parameters for this run.
    pub(crate) fn params(&self) -> [(String, String); 2] {
        params(&self.marker)
    }

    /// The slot number.
    pub(crate) fn slot(&self) -> u32 {
        self.slot
    }

    /// Whether this is slot 0, the one a cage compiles when it is prepared.
    pub(crate) fn is_first(&self) -> bool {
        self.slot == 0
    }

    /// Makes the slot available again. Only once no process carries it.
    pub(crate) fn free(self) {
        taken()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.slot);
    }
}

/// The parameters of slot 0, compiled when a cage is prepared.
pub(crate) fn first_params() -> [(String, String); 2] {
    params(&Run::of(0).marker)
}

fn params(marker: &CString) -> [(String, String); 2] {
    [
        (RUN_PREFIX_PARAM.to_string(), prefix().to_string()),
        (
            RUN_MARKER_PARAM.to_string(),
            marker.to_string_lossy().into_owned(),
        ),
    ]
}

/// Checks once per process that the kernel answers the marker query: the
/// unsandboxed caller must allow the probe name.
pub(crate) fn probe(lib: &sys::Libsandbox) -> Result<(), SpawnError> {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    RESULT
        .get_or_init(|| {
            let probe = Run::of(0).probe;
            let pid = std::process::id().cast_signed();
            match lib.allows_lookup(pid, &probe) {
                Ok(true) => Ok(()),
                Ok(false) => Err("the caller's own lookup check was denied".into()),
                Err(errno) => Err(format!("the lookup check failed with errno {errno}")),
            }
        })
        .clone()
        .map_err(|detail| {
            SpawnError::Unsupported(Unsupported::RunMarker {
                os_build: sys::os_build(),
                detail,
            })
        })
}

/// The live processes of the calling user whose sandbox carries `run`'s
/// marker.
pub(crate) fn members(lib: &sys::Libsandbox, run: &Run) -> io::Result<Vec<libc::pid_t>> {
    let mut found = Vec::new();
    for pid in sys::all_pids().map_err(io::Error::from_raw_os_error)? {
        if pid <= 0 || !sys::live_of_user(pid) {
            continue;
        }
        match (
            lib.allows_lookup(pid, &run.marker),
            lib.allows_lookup(pid, &run.probe),
        ) {
            (Ok(true), Ok(false)) => found.push(pid),
            (Ok(_), Ok(_)) => {}
            // It exited between the listing and the check.
            _ if !sys::live_of_user(pid) => {}
            (Err(errno), _) | (_, Err(errno)) => {
                return Err(io::Error::from_raw_os_error(errno));
            }
        }
    }
    Ok(found)
}

/// Kills what `scan` finds until a scan finds nothing, for at most `rounds`
/// rounds. Fails with the pids the last scan still found.
pub(crate) fn reap(
    mut scan: impl FnMut() -> io::Result<Vec<libc::pid_t>>,
    mut kill: impl FnMut(libc::pid_t),
    rounds: usize,
) -> io::Result<()> {
    for _ in 0..rounds {
        let found = scan()?;
        if found.is_empty() {
            return Ok(());
        }
        for pid in found {
            kill(pid);
        }
        // Let the signals land before looking again.
        std::thread::sleep(Duration::from_millis(1));
    }
    let survivors = scan()?;
    if survivors.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "processes of the run survived: {survivors:?}"
        )))
    }
}

/// Kills every process of `run`.
pub(crate) fn end(run: &Run) -> io::Result<()> {
    let lib = super::libsandbox().map_err(io::Error::other)?;
    reap(|| members(lib, run), sys::kill, ROUNDS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slots_are_reused_only_when_freed() {
        let a = Run::take();
        let b = Run::take();
        assert_ne!(a.slot, b.slot);
        let (a_slot, b_slot) = (a.slot, b.slot);
        a.free();
        let c = Run::take();
        assert_eq!(c.slot, a_slot);
        // Dropping retires.
        drop(b);
        let d = Run::take();
        assert_ne!(d.slot, b_slot);
        c.free();
        d.free();
    }

    #[test]
    fn names_are_plain() {
        let run = Run::of(7);
        for name in [&run.marker, &run.probe] {
            let s = name.to_str().unwrap();
            assert!(s.starts_with(prefix()), "{s}");
            assert!(
                s.bytes()
                    .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase() || b == b'.'),
                "{s}"
            );
        }
        assert_ne!(run.marker, run.probe);
        assert_eq!(run.params()[1].1, format!("{}7", prefix()));
    }

    #[test]
    fn a_run_that_keeps_living_is_reported() {
        let mut kills = 0;
        let err = reap(|| Ok(vec![4242]), |_| kills += 1, 3).unwrap_err();
        assert_eq!(kills, 3);
        assert!(err.to_string().contains("[4242]"), "{err}");
    }

    #[test]
    fn a_run_that_dies_is_done() {
        let mut left = vec![vec![1, 2], vec![2], vec![]].into_iter();
        let mut killed = Vec::new();
        reap(|| Ok(left.next().unwrap()), |p| killed.push(p), 8).unwrap();
        assert_eq!(killed, [1, 2, 2]);
    }
}
