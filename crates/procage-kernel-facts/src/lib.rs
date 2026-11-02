//! # procage kernel facts
//!
//! The behaviour of the kernel and of libsandbox that procage builds on, as
//! executable checks. Every fact runs a real child process on the running
//! kernel and observes what happens; comparing generated profile text is never
//! evidence.
//!
//! The crate has three parts:
//!
//! - this library: the step protocol, timeouts, scratch directories and dates;
//! - the `kf-probe` binary, which performs exactly one step per invocation and
//!   prints its observations as `kf key=value` lines;
//! - the `kernel_facts` test (`harness = false`), which owns the catalog, runs
//!   every fact through `kf-probe` and prints the report.
//!
//! All unsafe code lives in [`sys`].

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::{Read, Write};
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub mod sys;

/// Default per-step timeout.
pub const TIMEOUT: Duration = Duration::from_secs(30);
/// Timeout for steps that compile thousands of rules (KF-M17 takes close
/// to two minutes on GitHub's macOS runners).
pub const TIMEOUT_HEAVY: Duration = Duration::from_secs(300);

/// Whether `value` may appear in an observation: numbers, errno values, byte
/// counts, flags, short fixed tokens and paths the step created. Never file
/// contents or environment values.
pub fn is_observation_value(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"_.:/+-".contains(&b))
}

/// Prints one observation line. Panics (and so fails the step) on a value
/// outside the observation alphabet.
pub fn emit(key: &str, value: impl Display) {
    let value = value.to_string();
    assert!(
        key.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
        "observation key {key:?}"
    );
    assert!(
        is_observation_value(&value),
        "observation {key} has a disallowed value"
    );
    println!("kf {key}={value}");
}

/// The observations of one step, by key. Later keys override earlier ones.
#[derive(Debug, Default, Clone)]
pub struct Observation(BTreeMap<String, String>);

impl Observation {
    /// Parses the `kf key=value` lines of a step's stdout; other lines are ignored.
    pub fn parse(stdout: &str) -> Self {
        let mut map = BTreeMap::new();
        for line in stdout.lines() {
            let Some(rest) = line.strip_prefix("kf ") else {
                continue;
            };
            for pair in rest.split_whitespace() {
                if let Some((k, v)) = pair.split_once('=') {
                    map.insert(k.to_owned(), v.to_owned());
                }
            }
        }
        Self(map)
    }

    /// The value of `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// The value of `key` as an integer.
    pub fn int(&self, key: &str) -> Option<i64> {
        self.get(key)?.parse().ok()
    }

    /// All observations as `k=v k=v`, for reports.
    pub fn summary(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// How a step process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    /// Exited with this code.
    Code(i32),
    /// Killed by this signal.
    Signal(i32),
    /// Killed by the runner after its timeout.
    Timeout,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Exit::Code(c) => write!(f, "code:{c}"),
            Exit::Signal(s) => write!(f, "signal:{s}"),
            Exit::Timeout => f.write_str("timeout"),
        }
    }
}

/// The result of one step.
#[derive(Debug, Clone)]
pub struct Step {
    /// How the process ended.
    pub exit: Exit,
    /// What it printed.
    pub obs: Observation,
}

impl Step {
    /// The step ran to completion (exit code 0).
    pub fn ran(&self) -> bool {
        self.exit == Exit::Code(0)
    }

    /// `exit` plus the observations, for reports.
    pub fn summary(&self) -> String {
        let obs = self.obs.summary();
        if obs.is_empty() {
            format!("exit={}", self.exit)
        } else {
            format!("exit={} {obs}", self.exit)
        }
    }
}

/// Runs `probe args…` with an empty environment, stdin from `stdin` (or
/// `/dev/null`), and kills it after `timeout`. The child is started through
/// the standard process API; no code runs between fork and exec here.
pub fn run_step(probe: &Path, args: &[&str], timeout: Duration, stdin: Option<&[u8]>) -> Step {
    let mut cmd = Command::new(probe);
    cmd.args(args)
        .env_clear()
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            let mut obs = Observation::default();
            obs.0.insert(
                "spawn_errno".into(),
                e.raw_os_error().unwrap_or(-1).to_string(),
            );
            return Step {
                exit: Exit::Code(-1),
                obs,
            };
        }
    };
    if let (Some(data), Some(mut pipe)) = (stdin, child.stdin.take()) {
        // A child that exits early closes the pipe; that shows in its exit.
        let _ = pipe.write_all(data);
    }
    let mut out = child.stdout.take().expect("piped stdout");
    let mut err = child.stderr.take().expect("piped stderr");
    let out_reader = std::thread::spawn(move || {
        let mut s = String::new();
        let _ = out.read_to_string(&mut s);
        s
    });
    let err_reader = std::thread::spawn(move || {
        let mut s = Vec::new();
        let _ = err.read_to_end(&mut s);
    });
    let deadline = Instant::now() + timeout;
    let exit = loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                break match (status.code(), status.signal()) {
                    (Some(c), _) => Exit::Code(c),
                    (None, Some(s)) => Exit::Signal(s),
                    (None, None) => Exit::Code(-1),
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(5)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break Exit::Timeout;
            }
        }
    };
    let stdout = out_reader.join().unwrap_or_default();
    let _ = err_reader.join();
    Step {
        exit,
        obs: Observation::parse(&stdout),
    }
}

/// Linux confinement tiers, weakest first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// Neither T1 nor T2: procage reports `Unsupported`.
    T3,
    /// Landlock (ABI ≥ 1) and seccomp, without user namespaces.
    T2,
    /// User namespaces, mounts, Landlock and seccomp.
    T1,
}

/// The measured Linux capabilities the tier is derived from.
#[derive(Debug, Clone, Copy, Default)]
pub struct Capabilities {
    /// An unprivileged user namespace can be created.
    pub userns: bool,
    /// Its uid/gid maps can be written.
    pub uid_map: bool,
    /// A tmpfs can be mounted inside it.
    pub tmpfs: bool,
    /// A read-only bind returns EROFS on write.
    pub ro_bind: bool,
    /// The Landlock ABI, when Landlock is available.
    pub landlock_abi: Option<u32>,
    /// A seccomp filter can be installed.
    pub seccomp_filter: bool,
}

/// Whether a capability measurement succeeded: the step exited 0 and
/// reported `ok=1`. A signal, timeout, error exit or missing `ok` means the
/// capability is absent; a broken measurement never raises the tier.
pub fn measured(step: &Step) -> bool {
    step.ran() && step.obs.get("ok") == Some("1")
}

/// The tier the measured capabilities support. Only measurements count;
/// the kernel version is never consulted.
pub fn derive_tier(c: &Capabilities) -> Tier {
    let abi = c.landlock_abi.unwrap_or(0);
    if c.userns && c.uid_map && c.tmpfs && c.ro_bind && abi >= 1 && c.seccomp_filter {
        Tier::T1
    } else if abi >= 1 && c.seccomp_filter {
        Tier::T2
    } else {
        Tier::T3
    }
}

/// The verdict on one fact.
#[derive(Debug)]
pub enum Outcome {
    /// The fact holds; the observations.
    Pass(String),
    /// The fact does not hold.
    Fail {
        /// What the fact expects.
        expected: String,
        /// What the steps observed.
        observed: String,
    },
    /// The fact does not apply here; why.
    NotApplicable(String),
    /// A control run or setup failed, so the fact can be neither passed nor failed.
    SetupFailed(String),
}

/// A fact's result: the observations on success.
pub type Check = Result<String, Outcome>;

/// The step ran (exit 0); otherwise the fact cannot be judged.
pub fn ran(s: Step) -> Result<Step, Outcome> {
    if s.ran() {
        Ok(s)
    } else {
        Err(Outcome::SetupFailed(s.summary()))
    }
}

/// Every `key=value` holds, else the fact fails with expected and observed values.
pub fn expect(s: &Step, want: &[(&str, &str)]) -> Result<(), Outcome> {
    if s.ran() && want.iter().all(|(k, v)| s.obs.get(k) == Some(*v)) {
        return Ok(());
    }
    Err(Outcome::Fail {
        expected: pairs(want),
        observed: s.summary(),
    })
}

/// A control run: every `key=value` holds, else the setup is broken (the
/// fact can neither pass nor fail).
pub fn control(s: &Step, want: &[(&str, &str)]) -> Result<(), Outcome> {
    expect(s, want).map_err(|_| {
        Outcome::SetupFailed(format!(
            "control expected {} observed {}",
            pairs(want),
            s.summary()
        ))
    })
}

fn pairs(want: &[(&str, &str)]) -> String {
    want.iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A fresh directory that only this fact uses: created exclusively with mode
/// 0700 under a unique name, canonicalised, and removed on drop.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// A scratch directory under the system temp directory.
    pub fn new() -> std::io::Result<Self> {
        Self::new_in(&std::env::temp_dir())
    }

    /// A scratch directory under `parent`, e.g. `/private/tmp`.
    pub fn new_in(parent: &Path) -> std::io::Result<Self> {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        loop {
            let nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let name = format!(
                "procage-kf-{}-{}-{nanos:x}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::Relaxed)
            );
            let candidate = parent.join(name);
            match std::fs::DirBuilder::new().mode(0o700).create(&candidate) {
                Ok(()) => {
                    let path = candidate.canonicalize()?;
                    if !is_inline_path(&path) {
                        let _ = std::fs::remove_dir_all(&path);
                        return Err(std::io::Error::other(
                            "scratch path outside the inline-path alphabet",
                        ));
                    }
                    return Ok(Self { path });
                }
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// The canonical path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The canonical path as a string (always valid UTF-8, see [`is_inline_path`]).
    pub fn as_str(&self) -> &str {
        self.path.to_str().expect("checked by is_inline_path")
    }

    /// `self/name` as a string.
    pub fn join(&self, name: &str) -> String {
        format!("{}/{name}", self.as_str())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Whether `path` is absolute and uses only `[A-Za-z0-9/._-]`, so it can be
/// written inside an SBPL string literal without escaping.
pub fn is_inline_path(path: &Path) -> bool {
    path.to_str().is_some_and(|s| {
        s.starts_with('/')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._-".contains(&b))
    })
}

/// Today's UTC date as `YYYY-MM-DD`.
pub fn utc_date() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (y, m, d) = civil_from_days((secs / 86_400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// `civil_from_days`).
pub fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (yoe + era * 400 + i64::from(m <= 2), m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn step(exit: Exit, stdout: &str) -> Step {
        Step {
            exit,
            obs: Observation::parse(stdout),
        }
    }

    /// A failed control run is a setup failure, never a pass or a
    /// plain failure; a wrong errno fails with expected and observed values.
    #[test]
    fn controls_and_expectations() {
        let missing_target = step(Exit::Code(0), "kf errno=2\n");
        assert!(matches!(
            control(&missing_target, &[("errno", "0")]),
            Err(Outcome::SetupFailed(_))
        ));
        let wrong_errno = step(Exit::Code(0), "kf errno=13\n");
        match expect(&wrong_errno, &[("errno", "1")]) {
            Err(Outcome::Fail { expected, observed }) => {
                assert_eq!(expected, "errno=1");
                assert!(observed.contains("errno=13"));
            }
            other => panic!("{other:?}"),
        }
        // A step that crashed is never judged, even if it printed the
        // expected value first.
        let crashed = step(Exit::Signal(11), "kf errno=1\n");
        assert!(expect(&crashed, &[("errno", "1")]).is_err());
        assert!(matches!(ran(crashed), Err(Outcome::SetupFailed(_))));
    }

    /// A crashed, killed or timed-out measurement counts as absent
    /// and never raises the tier.
    #[test]
    fn broken_measurements_are_absent() {
        assert!(measured(&step(Exit::Code(0), "kf ok=1\n")));
        for exit in [
            Exit::Signal(11),
            Exit::Timeout,
            Exit::Code(3),
            Exit::Code(-1),
        ] {
            assert!(!measured(&step(exit, "kf ok=1\n")), "{exit}");
        }
        assert!(!measured(&step(Exit::Code(0), "")));
        let t1 = Capabilities {
            userns: true,
            uid_map: true,
            tmpfs: true,
            ro_bind: true,
            landlock_abi: Some(8),
            seccomp_filter: true,
        };
        assert_eq!(derive_tier(&t1), Tier::T1);
        assert_eq!(
            derive_tier(&Capabilities {
                uid_map: false,
                ..t1
            }),
            Tier::T2
        );
        assert_eq!(
            derive_tier(&Capabilities {
                userns: false,
                landlock_abi: Some(1),
                ..t1
            }),
            Tier::T2
        );
        assert_eq!(
            derive_tier(&Capabilities {
                userns: false,
                landlock_abi: None,
                ..t1
            }),
            Tier::T3
        );
        assert_eq!(
            derive_tier(&Capabilities {
                seccomp_filter: false,
                ..t1
            }),
            Tier::T3
        );
        assert_eq!(derive_tier(&Capabilities::default()), Tier::T3);
    }

    /// A child that outlives its timeout is killed and reported as a
    /// timeout, promptly.
    #[test]
    fn hanging_child_is_killed() {
        let start = Instant::now();
        let s = run_step(
            Path::new("/bin/sleep"),
            &["30"],
            Duration::from_millis(200),
            None,
        );
        assert_eq!(s.exit, Exit::Timeout);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    /// The primitives facts create files and directories with never
    /// follow a pre-planted symlink: exclusive directory and file creation
    /// fail on it and leave its target untouched.
    #[test]
    fn planted_symlinks_are_not_followed() {
        let s = Scratch::new().unwrap();
        let target = s.join("target");
        std::fs::write(&target, b"original").unwrap();
        let planted = s.join("planted");
        std::os::unix::fs::symlink(&target, &planted).unwrap();
        let dir = std::fs::DirBuilder::new().mode(0o700).create(&planted);
        assert_eq!(dir.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&planted);
        assert_eq!(file.unwrap_err().kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_390), (2025, 10, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn observations() {
        let o = Observation::parse("noise\nkf rc=-1 errno=1\nkf bytes=16\nkf rc=0\n");
        assert_eq!(o.int("rc"), Some(0));
        assert_eq!(o.int("errno"), Some(1));
        assert_eq!(o.get("bytes"), Some("16"));
        assert_eq!(o.get("missing"), None);
        assert!(is_observation_value("26.6.2"));
        assert!(!is_observation_value("a b"));
        assert!(!is_observation_value("x=y"));
    }

    #[test]
    fn scratch_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let path = {
            let s = Scratch::new().unwrap();
            let mode = std::fs::metadata(s.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
            assert!(is_inline_path(s.path()));
            s.path().to_owned()
        };
        assert!(!path.exists());
    }
}
