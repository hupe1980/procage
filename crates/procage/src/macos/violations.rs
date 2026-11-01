//! The violation monitor: one per process, started on the first spawn of a
//! cage that reports violations.
//!
//! The kernel logs every Seatbelt denial to the unified log, ending with the
//! denying rule's message, which a reporting profile sets to the run's
//! marker (and the rule's kind). The monitor runs `/usr/bin/log stream` with
//! a predicate that admits only denials naming this process's marker prefix,
//! parses each line and adds the violation to the record of the run whose
//! marker it names.
//!
//! A fence is a denial too: a forked child applies a profile whose message is
//! the fence marker, is denied opening `/`, and exits. Kernel denials reach
//! the stream in the order they were logged (pinned by a kernel fact; a
//! `syslog` line from this process was measured to overtake them), so when
//! the fence's own denial arrives, every denial logged before it has too: a
//! run's record is complete once a fence made after the run ended is seen.
//!
//! `log stream` keeps running when the process that started it dies, so it
//! runs under a `/bin/sh` watchdog that kills it when the pipe from this
//! process closes. Both binaries must be root-owned, not writable by group
//! or others, and on a read-only volume (the sealed system volume) before
//! they are run.

use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use super::{lifetime, sys};
use crate::violation::{Coverage, Record, parse};
pub(crate) use crate::violation::{Sink, lock};

/// The shell that runs the watchdog.
const SH: &str = "/bin/sh";
/// The unified-log reader.
const LOG: &str = "/usr/bin/log";
/// How long the stream may take to deliver its first fence.
const READY: Duration = Duration::from_secs(2);
/// How long a fence may take.
const FENCE: Duration = Duration::from_secs(1);

/// `$1` is the predicate. `log` reads nothing; the subshell reads the pipe
/// from this process (fd 3, since an asynchronous list's standard input is
/// `/dev/null`) and kills `log` when it closes; the shell waits for `log`,
/// so a `log` that exits closes the stream.
const SCRIPT: &str = "exec 3<&0
/usr/bin/log stream --style ndjson --predicate \"$1\" </dev/null 3<&- &
L=$!
(read _ <&3; kill $L) >/dev/null 2>&1 &
exec 3<&-
wait $L";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Status {
    Idle,
    Starting,
    Ready,
    Down(String),
}

struct State {
    status: Status,
    /// Distinguishes helpers, so a reader of an old one cannot change state.
    generation: u64,
    /// The pipe the watchdog reads; dropping it ends the helper.
    stdin: Option<ChildStdin>,
    sinks: HashMap<String, Sink>,
    /// The pids of fences whose denial arrived.
    seen: HashSet<u32>,
}

struct Monitor {
    state: Mutex<State>,
    changed: Condvar,
}

fn monitor() -> &'static Monitor {
    static MONITOR: OnceLock<Monitor> = OnceLock::new();
    MONITOR.get_or_init(|| Monitor {
        state: Mutex::new(State {
            status: Status::Idle,
            generation: 0,
            stdin: None,
            sinks: HashMap::new(),
            seen: HashSet::new(),
        }),
        changed: Condvar::new(),
    })
}

impl Monitor {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Starts the helper unless it is ready; the coverage new runs get.
    fn ensure(&self) -> Coverage {
        let mut state = self.state();
        loop {
            match &state.status {
                Status::Ready => return Coverage::Observed,
                Status::Starting => {
                    state = self.changed.wait(state).unwrap_or_else(|e| e.into_inner());
                }
                Status::Idle | Status::Down(_) => break,
            }
        }
        state.status = Status::Starting;
        state.generation += 1;
        let generation = state.generation;
        drop(state);
        let started = self.start(generation);
        let mut state = self.state();
        let coverage = match started {
            Ok(()) if state.status == Status::Ready => Coverage::Observed,
            Ok(()) => match &state.status {
                Status::Down(reason) => Coverage::Unavailable(reason.clone()),
                _ => Coverage::Unavailable("the log stream did not start".into()),
            },
            Err(reason) => {
                state.status = Status::Down(reason.clone());
                state.stdin = None;
                Coverage::Unavailable(reason)
            }
        };
        self.changed.notify_all();
        coverage
    }

    /// Runs the helper and waits for it to deliver a ping.
    fn start(&self, generation: u64) -> Result<(), String> {
        for binary in [SH, LOG] {
            trusted(binary)?;
        }
        fence_bytecode()?;
        let prefix = lifetime::prefix();
        // The prefix is hex digits and dots: nothing to escape.
        let predicate = format!("sender == \"Sandbox\" AND eventMessage CONTAINS \"{prefix}\"");
        let mut child = Command::new(SH)
            .args(["-c", SCRIPT, "sh", &predicate])
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start {SH}: {e}"))?;
        let stdout = child.stdout.take().expect("piped");
        let stderr = child.stderr.take().expect("piped");
        self.state().stdin = child.stdin.take();
        std::thread::Builder::new()
            .name("procage-violations".into())
            .spawn(move || {
                read(generation, stdout, stderr);
                // The helper ended; reap it.
                let _ = child.wait();
            })
            .map_err(|e| format!("cannot start the reader thread: {e}"))?;
        let deadline = Instant::now() + READY;
        while Instant::now() < deadline {
            if let Some(seen) = self.ping(generation, Duration::from_millis(50)) {
                if seen {
                    let mut state = self.state();
                    if state.generation == generation && state.status == Status::Starting {
                        state.status = Status::Ready;
                    }
                }
                return Ok(());
            }
        }
        self.state().stdin = None;
        Err(format!(
            "the log stream did not answer within {}s",
            READY.as_secs()
        ))
    }

    /// Makes a fence and waits up to `timeout` for its denial: `Some(true)`
    /// seen, `Some(false)` the helper went down or no fence could be made,
    /// `None` timed out.
    fn ping(&self, generation: u64, timeout: Duration) -> Option<bool> {
        let Some(n) = make_fence() else {
            return Some(false);
        };
        let deadline = Instant::now() + timeout;
        let mut state = self.state();
        loop {
            if state.seen.remove(&n) {
                return Some(true);
            }
            if state.generation != generation || matches!(state.status, Status::Down(_)) {
                return Some(false);
            }
            let left = deadline.checked_duration_since(Instant::now())?;
            state = self
                .changed
                .wait_timeout(state, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }
}

/// Checks that `path` is a root-owned file, not writable by group or others,
/// on a read-only volume.
fn trusted(path: &str) -> Result<(), String> {
    let untrusted = |why: &str| Err(format!("{path} is not trusted: {why}"));
    let meta = std::fs::metadata(Path::new(path)).map_err(|e| format!("{path}: {e}"))?;
    if meta.uid() != 0 {
        return untrusted("not owned by root");
    }
    if meta.mode() & 0o022 != 0 {
        return untrusted("writable by group or others");
    }
    let c = CString::new(path).map_err(|_| format!("{path}: contains NUL"))?;
    match sys::on_read_only_volume(&c) {
        Ok(true) => Ok(()),
        Ok(false) => untrusted("not on a read-only volume"),
        Err(errno) => Err(format!("{path}: statfs failed (errno {errno})")),
    }
}

/// The message of a fence's denial.
fn fence_marker() -> String {
    format!("{}fence", lifetime::prefix())
}

/// The fence profile, compiled once: everything denied, with the fence
/// marker as the message.
fn fence_bytecode() -> Result<Arc<[u8]>, String> {
    static FENCE: OnceLock<Result<Arc<[u8]>, String>> = OnceLock::new();
    FENCE
        .get_or_init(|| {
            let lib = super::libsandbox().map_err(|e| e.to_string())?;
            let profile = format!(
                "(version 1)\n(deny default (with message \"{}\"))\n",
                fence_marker()
            );
            lib.compile(&profile, &[])
                .map(Arc::from)
                .map_err(|e| format!("cannot compile the fence profile: {e:?}"))
        })
        .clone()
}

/// Forks a fence and reaps it; its pid, or `None` when it could not run.
fn make_fence() -> Option<u32> {
    let lib = super::libsandbox().ok()?;
    let bytecode = fence_bytecode().ok()?;
    let mut command = Command::new("/usr/bin/true");
    command
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    sys::install_fence(&mut command, lib.child_ops(), bytecode);
    let mut child = command.spawn().ok()?;
    let pid = child.id();
    // Exit 0: the open of `/` was denied, so the kernel logged it.
    let denied = child.wait().ok()?.success();
    denied.then_some(pid)
}

/// The reader thread of one helper.
fn read(generation: u64, stdout: std::process::ChildStdout, mut stderr: std::process::ChildStderr) {
    let fence = fence_marker();
    let m = monitor();
    for line in BufReader::new(stdout).lines() {
        let Ok(line) = line else { break };
        let Ok(value) = serde_json::from_str::<serde_json::Value>(&line) else {
            continue;
        };
        let Some(message) = value.get("eventMessage").and_then(|v| v.as_str()) else {
            continue;
        };
        let Some((marker, violation)) = parse(message, SystemTime::now()) else {
            continue;
        };
        if marker == fence {
            let mut state = m.state();
            if state.generation == generation {
                state.seen.insert(violation.pid);
                m.changed.notify_all();
            }
            continue;
        }
        let sink = m.state().sinks.get(marker).cloned();
        if let Some(sink) = sink {
            lock(&sink).push(violation);
        }
    }
    let mut reason = String::new();
    let _ = stderr.read_to_string(&mut reason);
    let reason = match reason.trim() {
        "" => "the log stream ended".to_string(),
        text => format!("the log stream ended: {text}"),
    };
    let mut state = m.state();
    if state.generation != generation {
        return;
    }
    state.status = Status::Down(reason.clone());
    state.stdin = None;
    for (_, sink) in state.sinks.drain() {
        lock(&sink).interrupt(&reason);
    }
    m.changed.notify_all();
}

/// Registers the run `marker`, starting the helper when needed. Returns the
/// run's record; when reporting is unavailable it says why and is not
/// registered.
pub(crate) fn register(marker: &str) -> Sink {
    let m = monitor();
    let coverage = m.ensure();
    let observed = coverage == Coverage::Observed;
    let sink = Arc::new(Mutex::new(Record::new(coverage)));
    if observed {
        m.state().sinks.insert(marker.to_string(), sink.clone());
    }
    sink
}

/// Stops routing violations to `marker`.
pub(crate) fn unregister(marker: &str) {
    monitor().state().sinks.remove(marker);
}

/// Waits until every denial logged so far has arrived; `false` when the
/// helper is down or the fence timed out.
pub(crate) fn fence() -> bool {
    let m = monitor();
    let generation = {
        let state = m.state();
        if state.status != Status::Ready {
            return false;
        }
        state.generation
    };
    m.ping(generation, FENCE) == Some(true)
}

/// Ends the helper (for tests): the reader sees the stream end.
pub(crate) fn stop() {
    monitor().state().stdin = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SR-007: a helper that never delivers the fence makes the wait time
    /// out after its limit instead of blocking.
    #[test]
    fn a_silent_helper_times_out() {
        let silent = Monitor {
            state: Mutex::new(State {
                status: Status::Ready,
                generation: 1,
                stdin: None,
                sinks: HashMap::new(),
                seen: HashSet::new(),
            }),
            changed: Condvar::new(),
        };
        let start = Instant::now();
        assert_eq!(silent.ping(1, Duration::from_millis(200)), None);
        let took = start.elapsed();
        assert!(
            took >= Duration::from_millis(200) && took < Duration::from_secs(2),
            "{took:?}"
        );
    }

    #[test]
    fn system_binaries_are_trusted() {
        assert_eq!(trusted(SH), Ok(()));
        assert_eq!(trusted(LOG), Ok(()));
    }

    #[test]
    fn user_files_are_not_trusted() {
        let dir = std::env::temp_dir().join(format!("procage-trust-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("log");
        std::fs::write(&file, "#!/bin/sh\n").unwrap();
        let err = trusted(file.to_str().unwrap()).unwrap_err();
        assert!(err.contains("not owned by root"), "{err}");
        let _ = std::fs::remove_dir_all(dir);
        assert!(trusted("/nonexistent/log").is_err());
    }
}
