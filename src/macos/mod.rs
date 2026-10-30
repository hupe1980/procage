//! Spawning a caged child on macOS (Seatbelt).
//!
//! A [`Cage`] is a prepared policy. Preparing it:
//!
//! 1. resolves every path to the spelling the kernel matches (`/tmp/x`
//!    becomes `/private/tmp/x`) and records the rewrite;
//! 2. lowers the policy;
//! 3. compiles the profile once, through libsandbox's private interface,
//!    which is resolved at runtime.
//!
//! Resolution also lets the child read the *metadata* of each symlink a
//! policy path passes through, and of `/etc`, `/tmp` and `/var`. The kernel
//! needs this to look up a path in the spelling the caller uses, so the child
//! can see where those links point, but nothing behind them.
//!
//! [`Cage::spawn`] then forks a child that applies the compiled profile with
//! system calls only, confirms that it is sandboxed, consumes the spawn's
//! grant tokens, and only then executes its target. If any step fails, the
//! target never runs and the error names the step.
//!
//! What the tests (`tests/spawn_macos.rs`) observe on a real kernel:
//!
//! - the child can use the files its policy grants and is refused every
//!   other file access with "operation not permitted";
//! - a protected subtree inside a writable one cannot be written;
//! - without network access in the policy, connecting to a loopback listener
//!   fails; with loopback access for that port it succeeds;
//! - paths written with `/tmp` work as written;
//! - a grant bound for one spawn gives nothing to another;
//! - a caged process that tries to spawn gets [`SpawnError::AlreadySandboxed`];
//! - with [`Tty::None`] the child leads its own
//!   session; its environment and resource limits are the policy's;
//! - 100 children spawned while other threads load libraries are all caged;
//! - a descriptor the caller left open without close-on-exec does not exist
//!   in the child; one handed over with [`Cage::spawn_with_fds`] does; with
//!   1,000 extra descriptors open, none reaches the child;
//! - dropping the [`Child`] handle kills the child, a grandchild in its
//!   process group and a grandchild that started its own session; a
//!   detached handle leaves the child running;
//! - with environment passthrough, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and
//!   `DYLD_*` variables do not reach the child unless set explicitly on the
//!   command, and the handle lists them as dropped;
//! - a policy with the grant `tmpdir` gives each run its own `TMPDIR`, which
//!   is removed when the handle is dropped;
//! - with base profile V1, `id`, `date`, `uname`, `sh`/`zsh`/`bash`, `cat`,
//!   `sed`, `awk`, `perl`, `tar`, `gzip` and Rust programs run with correct
//!   output (user name, local time), and children with `/dev/null` stdio
//!   work; the base alone still refuses the home directory, temporary files,
//!   writes to `/tmp` and the network;
//! - with read access to the whole home directory, `~/.ssh`, `~/.aws` and
//!   `~/.gnupg` (also spelled `~/.SSH`) stay unreadable; with write access
//!   to a workspace, git hooks and config, shell rc files and `.vscode`
//!   cannot be written and `.git` cannot be renamed, while ordinary files
//!   and `.git/objects` can; launch agents cannot be planted even with a
//!   write grant; waiving a class by name lifts exactly that class;
//! - the presets `minimal`, `agent_readonly`, `agent_workspace` and `build`
//!   behave as documented in `procage_policy::presets`.
//!
//! **Not yet done** (later features):
//!
//! - a descendant that double-forks and starts its own session is
//!   reparented away from the child; macOS gives no way to find it, so it
//!   escapes lifetime control;
//! - there are no pseudo-terminals (`Tty::NewPty`);
//! - the base profile ([`Base::V1`](procage_policy::Base::V1)) is curated
//!   for macOS 26.6.2; tools that are Xcode shims (`/usr/bin/git`,
//!   `/usr/bin/python3`) need developer-tool paths it does not include;
//! - there is no helper process (path B);
//! - the `KERN_PROCARGS2` query gives a caged child the arguments and
//!   environment of any process of the same user: the sandbox does not
//!   mediate it, even under `(deny sysctl-read)` (macOS 26.6.2).
//!
//! With `Tty::Inherit` the child runs in its own process group, so its reads
//! from the shared terminal stop with SIGTTIN, like a background job.

mod canon;
mod child;
mod probe;
mod spawn;
mod sys;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use procage_policy::lower::GrantSlot;
use procage_policy::{LowerError, LowerOptions, Plan, Policy, SeatbeltPlan, Target, Tty, lower};

pub use crate::unix::TMPDIR_GRANT;
pub use child::Child;
pub use probe::{ApplyMethod, probe};

use crate::unix::TmpdirGuard;

/// A step of the in-child sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Starting a new session (`setsid`).
    Session,
    /// Setting resource limits.
    Rlimit,
    /// Applying the compiled profile.
    Apply,
    /// Confirming that the process is sandboxed.
    Verify,
    /// Consuming a grant token.
    Consume,
    /// Marking inherited descriptors close-on-exec.
    Fds,
}

impl Step {
    fn from_code(code: u32) -> Option<Step> {
        Some(match code {
            sys::steps::SESSION => Step::Session,
            sys::steps::RLIMIT => Step::Rlimit,
            sys::steps::APPLY => Step::Apply,
            sys::steps::VERIFY => Step::Verify,
            sys::steps::CONSUME => Step::Consume,
            sys::steps::FDS => Step::Fds,
            _ => return None,
        })
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Step::Session => "new session",
            Step::Rlimit => "resource limits",
            Step::Apply => "apply profile",
            Step::Verify => "verify sandbox",
            Step::Consume => "consume grant token",
            Step::Fds => "close inherited descriptors",
        })
    }
}

/// Something this macOS release or this procage version cannot do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// A private libsandbox symbol is missing.
    Symbol {
        /// The symbol.
        symbol: &'static str,
        /// `kern.osversion`.
        os_build: String,
    },
    /// The in-child apply method failed its probe on this release.
    ApplyMethod {
        /// `kern.osversion`.
        os_build: String,
        /// What the probe observed.
        detail: String,
    },
    /// A policy setting this version cannot apply yet.
    Setting {
        /// The setting.
        setting: &'static str,
    },
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::Symbol { symbol, os_build } => {
                write!(
                    f,
                    "libsandbox symbol `{symbol}` is missing on macOS build {os_build}"
                )
            }
            Unsupported::ApplyMethod { os_build, detail } => {
                write!(
                    f,
                    "the in-child apply method failed its probe on macOS build {os_build}: {detail}"
                )
            }
            Unsupported::Setting { setting } => {
                write!(f, "{setting} is not supported in this release")
            }
        }
    }
}

/// A problem with a per-spawn grant binding.
#[derive(Debug)]
pub enum GrantError {
    /// The policy declares no grant of this name.
    Undeclared {
        /// The name.
        name: String,
    },
    /// The bound path cannot be resolved (it must exist).
    Missing {
        /// The grant.
        name: String,
        /// The path as bound.
        path: PathBuf,
        /// Why.
        error: io::Error,
    },
    /// The grant name is reserved for procage (`tmpdir`).
    Reserved {
        /// The name.
        name: String,
    },
    /// libsandbox issued no token for the path.
    Issue {
        /// The grant.
        name: String,
        /// The resolved path.
        path: String,
    },
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GrantError::Undeclared { name } => {
                write!(f, "the policy declares no grant named {name:?}")
            }
            GrantError::Missing { name, path, error } => {
                write!(
                    f,
                    "grant {name}: cannot resolve {}: {error}",
                    path.display()
                )
            }
            GrantError::Reserved { name } => {
                write!(
                    f,
                    "grant {name} is bound by procage itself (a private temporary directory)"
                )
            }
            GrantError::Issue { name, path } => {
                write!(f, "grant {name}: no extension token issued for {path}")
            }
        }
    }
}

/// Why no caged child runs.
#[derive(Debug)]
pub enum SpawnError {
    /// This release or version cannot do it.
    Unsupported(Unsupported),
    /// The calling process is already sandboxed; a second profile would fail
    /// or be ignored by the kernel.
    AlreadySandboxed,
    /// The policy could not be lowered for macOS.
    Lower(LowerError),
    /// A policy path could not be resolved.
    Path {
        /// The path.
        path: String,
        /// Why.
        error: io::Error,
    },
    /// libsandbox refused the profile.
    Compile {
        /// libsandbox's message.
        message: String,
    },
    /// The profile has more rules than the in-process compile limit.
    LimitExceeded {
        /// The limit.
        limit: usize,
        /// The profile's rule count.
        rules: usize,
    },
    /// A grant binding is wrong.
    Grant(GrantError),
    /// A descriptor handed to the spawn is not open.
    Fd {
        /// The descriptor.
        fd: i32,
    },
    /// The run's private temporary directory could not be created.
    Tmpdir(io::Error),
    /// A step in the child failed; the target did not run.
    Apply {
        /// The step.
        step: Step,
        /// The OS error number.
        errno: i32,
    },
    /// Spawning failed (for example, the target cannot be executed).
    Io(io::Error),
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::Unsupported(u) => write!(f, "unsupported: {u}"),
            SpawnError::AlreadySandboxed => f.write_str("the calling process is already sandboxed"),
            SpawnError::Lower(e) => write!(f, "{e}"),
            SpawnError::Path { path, error } => write!(f, "cannot resolve {path}: {error}"),
            SpawnError::Compile { message } => {
                write!(f, "libsandbox refused the profile: {message}")
            }
            SpawnError::LimitExceeded { limit, rules } => {
                write!(
                    f,
                    "the profile has {rules} rules, more than the in-process compile limit of {limit}"
                )
            }
            SpawnError::Grant(e) => write!(f, "{e}"),
            SpawnError::Fd { fd } => write!(f, "descriptor {fd} handed to the spawn is not open"),
            SpawnError::Tmpdir(e) => {
                write!(f, "cannot create the private temporary directory: {e}")
            }
            SpawnError::Apply { step, errno } => write!(
                f,
                "the child failed at step `{step}`: {}; the target did not run",
                io::Error::from_raw_os_error(*errno)
            ),
            SpawnError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for SpawnError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SpawnError::Lower(e) => Some(e),
            SpawnError::Path { error, .. } | SpawnError::Io(error) | SpawnError::Tmpdir(error) => {
                Some(error)
            }
            SpawnError::Grant(GrantError::Missing { error, .. }) => Some(error),
            _ => None,
        }
    }
}

impl From<LowerError> for SpawnError {
    fn from(e: LowerError) -> Self {
        SpawnError::Lower(e)
    }
}

/// A policy path that was rewritten to the spelling the kernel matches.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PathRewrite {
    /// As written in the policy.
    pub from: String,
    /// As resolved.
    pub to: String,
}

/// Options for [`Cage::with_options`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CageOptions {
    /// Options for lowering the policy.
    pub lower: LowerOptions,
    /// The most rules compiled in-process (default 2,000). libsandbox aborts
    /// its caller on very large profiles; larger ones are refused.
    pub compile_limit: usize,
}

impl Default for CageOptions {
    fn default() -> Self {
        Self {
            lower: LowerOptions::default(),
            compile_limit: 2000,
        }
    }
}

impl CageOptions {
    /// These options with `lower` as the lowering options.
    pub fn with_lower(mut self, lower: LowerOptions) -> Self {
        self.lower = lower;
        self
    }

    /// These options with an in-process compile limit of `limit` rules.
    pub fn with_compile_limit(mut self, limit: usize) -> Self {
        self.compile_limit = limit;
        self
    }
}

/// Per-spawn bindings of the policy's grants to existing paths.
#[derive(Debug, Clone, Default)]
pub struct Grants {
    bindings: Vec<(String, PathBuf)>,
}

impl Grants {
    /// No bindings.
    pub fn new() -> Self {
        Self::default()
    }

    /// These bindings plus grant `name` bound to `path`.
    pub fn bind(mut self, name: &str, path: impl AsRef<Path>) -> Self {
        self.bindings
            .push((name.to_string(), path.as_ref().to_path_buf()));
        self
    }
}

type CacheKey = (String, Vec<(String, String)>);

fn cache() -> &'static Mutex<HashMap<CacheKey, Arc<[u8]>>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Arc<[u8]>>>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn libsandbox() -> Result<&'static sys::Libsandbox, SpawnError> {
    sys::Libsandbox::get().map_err(|symbol| {
        SpawnError::Unsupported(Unsupported::Symbol {
            symbol,
            os_build: sys::os_build(),
        })
    })
}

/// Whether the calling process is sandboxed (by procage or anything else).
pub fn is_sandboxed() -> Result<bool, SpawnError> {
    Ok(libsandbox()?.is_sandboxed())
}

/// A prepared policy: resolved, lowered and compiled, reusable for any number
/// of spawns from any thread.
#[derive(Debug, Clone)]
pub struct Cage {
    plan: SeatbeltPlan,
    bytecode: Arc<[u8]>,
    rewrites: Vec<PathRewrite>,
    compiled: bool,
}

impl Cage {
    /// Prepares `policy` with default options.
    pub fn new(policy: &Policy) -> Result<Cage, SpawnError> {
        Cage::with_options(policy, &CageOptions::default())
    }

    /// Prepares `policy`. Fails with [`SpawnError::AlreadySandboxed`] in a
    /// process that is itself sandboxed.
    pub fn with_options(policy: &Policy, options: &CageOptions) -> Result<Cage, SpawnError> {
        if policy.tty == Tty::NewPty {
            return Err(SpawnError::Unsupported(Unsupported::Setting {
                setting: "Tty::NewPty",
            }));
        }
        let lib = libsandbox()?;
        // A sandboxed process cannot cage a child (the kernel refuses or
        // ignores a second profile); say so before anything else fails.
        if lib.is_sandboxed() {
            return Err(SpawnError::AlreadySandboxed);
        }
        let (resolved, rewrites) = canon::resolve_policy(policy)?;
        let Plan::Seatbelt(plan) = lower(&resolved, Target::MacOs, &options.lower)? else {
            unreachable!("lowering for macOS yields a Seatbelt plan");
        };
        if plan.rule_count > options.compile_limit {
            return Err(SpawnError::LimitExceeded {
                limit: options.compile_limit,
                rules: plan.rule_count,
            });
        }
        let key = (plan.profile.clone(), plan.params.clone());
        let cached = cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&key)
            .cloned();
        let (bytecode, compiled) = match cached {
            Some(bytecode) => (bytecode, false),
            None => {
                let bytecode: Arc<[u8]> = lib
                    .compile(&plan.profile, &plan.params)
                    .map_err(|message| SpawnError::Compile {
                        message: message.unwrap_or_else(|| "<no error text>".into()),
                    })?
                    .into();
                cache()
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(key, bytecode.clone());
                (bytecode, true)
            }
        };
        Ok(Cage {
            plan,
            bytecode,
            rewrites,
            compiled,
        })
    }

    /// The lowered plan (profile text, parameters, grant slots, hygiene).
    pub fn plan(&self) -> &SeatbeltPlan {
        &self.plan
    }

    /// The path rewrites made while preparing.
    pub fn rewrites(&self) -> &[PathRewrite] {
        &self.rewrites
    }

    /// Whether preparing this cage compiled the profile (`false`: the
    /// in-memory cache already held it).
    pub fn compiled(&self) -> bool {
        self.compiled
    }

    fn grant_slot(&self, name: &str) -> Option<&GrantSlot> {
        self.plan.grants.iter().find(|g| g.name.as_str() == name)
    }

    /// Spawns `command` in this cage, with `grants` bound for this spawn.
    ///
    /// The command's program must be executable under the policy. Fails
    /// without forking when the caller is already sandboxed, when the
    /// apply method failed its probe, or when a grant binding is wrong. The
    /// child receives only standard input, output and error.
    pub fn spawn(&self, command: &mut Command, grants: &Grants) -> Result<Child, SpawnError> {
        self.spawn_with_fds(command, grants, &[])
    }

    /// Like [`Cage::spawn`], and also hands `fds` to the child: they stay
    /// open across the exec, at the same numbers. Every other descriptor
    /// numbered 3 or higher is closed in the child.
    pub fn spawn_with_fds(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
    ) -> Result<Child, SpawnError> {
        let lib = libsandbox()?;
        if lib.is_sandboxed() {
            return Err(SpawnError::AlreadySandboxed);
        }
        probe()?;
        let keep = kept_fds(fds.iter().map(AsRawFd::as_raw_fd))?;
        if grants.bindings.iter().any(|(name, _)| name == TMPDIR_GRANT) {
            return Err(SpawnError::Grant(GrantError::Reserved {
                name: TMPDIR_GRANT.into(),
            }));
        }
        let tmpdir = match self.grant_slot(TMPDIR_GRANT) {
            Some(_) => Some(crate::unix::private_tmpdir().map_err(SpawnError::Tmpdir)?),
            None => None,
        };
        let removal = TmpdirGuard(tmpdir.clone());
        let mut grants = grants.clone();
        if let Some(dir) = &tmpdir {
            grants = grants.bind(TMPDIR_GRANT, dir);
            if !command.get_envs().any(|(k, _)| k == "TMPDIR") {
                command.env("TMPDIR", dir);
            }
        }
        let tokens = spawn::tokens(lib, self, &grants)?;
        let dropped = crate::unix::environment(command, &self.plan.hygiene.env);
        sys::ChildPlan {
            ops: lib.child_ops(),
            bytecode: self.bytecode.clone(),
            tokens,
            limits: crate::unix::limits(&self.plan.hygiene.limits),
            new_session: self.plan.hygiene.tty != Tty::Inherit,
            keep,
            fd_buffer: sys::fd_buffer(),
        }
        .install(command);
        let inner = command.spawn().map_err(spawn::decode)?;
        Ok(Child::new(inner, dropped, removal.disarm()))
    }
}

/// The descriptors to hand over: those above the standard three, each of
/// which must be open.
fn kept_fds(fds: impl IntoIterator<Item = i32>) -> Result<Vec<i32>, SpawnError> {
    let keep: Vec<i32> = fds.into_iter().filter(|&fd| fd > 2).collect();
    match keep.iter().find(|&&fd| !sys::fd_is_open(fd)) {
        Some(&fd) => Err(SpawnError::Fd { fd }),
        None => Ok(keep),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_descriptor_that_is_not_open_is_refused() {
        // `BorrowedFd` guarantees an open descriptor in safe code; the check
        // guards against one closed by another thread.
        let closed = 1_000_000;
        assert!(matches!(kept_fds([closed]), Err(SpawnError::Fd { fd }) if fd == closed));
        assert_eq!(kept_fds([0, 1, 2]).unwrap(), Vec::<i32>::new());
        let file = std::fs::File::open("/").unwrap();
        let fd = file.as_raw_fd();
        assert_eq!(kept_fds([fd]).unwrap(), vec![fd]);
    }
}

/// Probes for procage's own tests; not part of the API.
#[doc(hidden)]
pub mod testing {
    use super::{SpawnError, Unsupported, sys};

    /// Resolves `symbol` like the symbol table does.
    pub fn resolve_symbol(symbol: &'static str) -> Result<(), SpawnError> {
        if sys::has_symbol(symbol) {
            Ok(())
        } else {
            Err(SpawnError::Unsupported(Unsupported::Symbol {
                symbol,
                os_build: sys::os_build(),
            }))
        }
    }

    /// Whether the calling process leads its own session.
    pub fn is_session_leader() -> bool {
        sys::is_session_leader()
    }

    /// Whether the calling process leads its own process group.
    pub fn is_group_leader() -> bool {
        sys::is_group_leader()
    }

    /// Contends for dyld's locks until `stop` is set.
    pub fn dyld_churn(stop: &std::sync::atomic::AtomicBool) {
        sys::dyld_churn(stop);
    }

    /// Clears close-on-exec on `fd`.
    pub fn clear_cloexec(fd: i32) -> bool {
        sys::clear_cloexec(fd).is_ok()
    }

    /// Whether `fd` is open in the calling process.
    pub fn fd_is_open(fd: i32) -> bool {
        sys::fd_is_open(fd)
    }

    /// Whether process `pid` exists.
    pub fn alive(pid: u32) -> bool {
        libc::pid_t::try_from(pid).is_ok_and(sys::alive)
    }

    /// Spawns `/bin/sleep 30`, in a new session when `setsid`.
    pub fn spawn_sleeper(setsid: bool) -> std::io::Result<u32> {
        sys::spawn_sleeper(setsid)
    }

    /// The soft limits for open files and core size.
    pub fn nofile_and_core() -> Option<(u64, u64)> {
        Some((
            sys::getrlimit(libc::RLIMIT_NOFILE)?.0,
            sys::getrlimit(libc::RLIMIT_CORE)?.0,
        ))
    }

    /// Looks up the Mach service `name`; the `kern_return_t` (0: found).
    pub fn mach_lookup(name: &str) -> i32 {
        std::ffi::CString::new(name).map_or(libc::EINVAL, |c| sys::mach_lookup(&c))
    }

    /// `fcntl(fd, cmd, 0)`; the errno, or 0 on success.
    pub fn fcntl_errno(fd: i32, cmd: i32) -> i32 {
        sys::fcntl_errno(fd, cmd)
    }

    /// Reads another process's arguments and environment
    /// (`KERN_PROCARGS2`); the errno, or 0.
    pub fn procargs_errno(pid: u32) -> i32 {
        libc::pid_t::try_from(pid).map_or(libc::EINVAL, sys::procargs_errno)
    }

    /// `kill(pid, sig)`; the errno, or 0.
    pub fn kill_errno(pid: u32, sig: i32) -> i32 {
        libc::pid_t::try_from(pid).map_or(libc::EINVAL, |p| sys::kill_errno(p, sig))
    }

    /// A new pseudo-terminal: the controller and the path of the device.
    pub fn open_pty() -> std::io::Result<(std::os::fd::OwnedFd, std::path::PathBuf)> {
        sys::open_pty()
    }

    /// Makes the terminal `fd` the caller's controlling terminal
    /// (`TIOCSCTTY`); the errno, or 0.
    pub fn make_controlling(fd: i32) -> i32 {
        sys::ioctl_errno(fd, libc::TIOCSCTTY.into())
    }

    /// Pushes `byte` into the input of terminal `fd` (`TIOCSTI`); the
    /// errno, or 0.
    pub fn tiocsti_errno(fd: i32, byte: u8) -> i32 {
        sys::tiocsti_errno(fd, byte)
    }
}
