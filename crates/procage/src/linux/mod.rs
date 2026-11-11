//! Spawning a caged child on Linux (Landlock, seccomp, namespaces).
//!
//! Linux has no single sandbox call. procage combines kernel features into
//! a **tier**, chosen by what the host allows ([`probe()`]):
//!
//! - **T1**: user, mount, IPC, UTS and (unless the policy allows all
//!   networking) network namespaces, mounts, Landlock and seccomp. Needs
//!   unprivileged user namespaces.
//! - **T2**: Landlock and seccomp only, as in a Docker container with
//!   default settings or on a host that restricts user namespaces.
//! - Without either, preparing a cage fails with [`Unsupported`]. procage
//!   never runs a child unsandboxed.
//!
//! A [`Cage`] lowers a policy for the tier and the kernel's Landlock ABI; a
//! construct the tier cannot enforce is a capability gap at preparation.
//! [`Cage::spawn`] builds everything in the parent (the Landlock ruleset on
//! descriptors opened for that spawn, the seccomp filter, the mounts and id
//! maps) and forks a child that applies it with system calls only, in this
//! order: session, parent-death signal, namespaces and mounts (T1),
//! capabilities dropped, resource limits, inherited descriptors marked
//! close-on-exec, `no_new_privs`, Landlock, seccomp (handing its listener to
//! the parent when reporting), and a check that seccomp and `no_new_privs`
//! hold. If any step fails, the target never runs and the error names the
//! step.
//!
//! The data-driven hard-deny classes (`secrets`, `trust-handoff`,
//! `persistence`, see [`procage_policy::presets`]) hold where no rule
//! reaches their paths. Where one does, T1 masks the paths that exist at
//! spawn (an approximation the caller must accept by name) and T2 cannot
//! enforce them (a gap; only a waiver lets the policy through). On T2, a
//! grant bound to a path that reaches a class path is refused.
//!
//! `tests/spawn_linux.rs` and `tests/escape_linux.rs` check this on a real
//! kernel, on both tiers; the [threat model](crate::threat_model) lists
//! every escape class and its evidence.
//!
//! **Kernels.** Both tiers need Landlock, from ABI 1 (Linux 5.13). Each
//! newer ABI makes more of a policy exact; what an older one cannot express
//! is a capability gap or, where noted, a stricter rule:
//!
//! | ABI | Linux | For example | What changes below it |
//! |---|---|---|---|
//! | 1 | 5.13 | Ubuntu 22.04 (5.15) | No sandbox below. |
//! | 3 | 6.2 | Ubuntu 22.04 HWE, 23.10 (6.5) | Landlock cannot deny truncation: procage refuses `truncate(2)` by path and `open` with `O_TRUNC` without write access everywhere, also inside writable paths (truncate through a descriptor opened for writing instead), and `openat2` fails with `ENOSYS`. Debian 12 (6.1) is at ABI 2. |
//! | 4 | 6.7 | Ubuntu 24.04 (6.8) | No TCP rules: with the network off, seccomp still refuses IP sockets, but a TCP socket the caller hands over can connect. |
//! | 6 | 6.12 | Debian 13, RHEL 10 | No signal scope: `Signals::SelfAndChildren` is a gap. A harness that needs signals may choose `Signals::SameUser` (every process of the same user) and tell its user. Abstract Unix sockets are not scoped. |
//! | 9 | 7.1 | | No Unix-socket rules: `ipc.unix_sockets` is a gap on T2 and an approximation on T1 (below). |
//! | 10 | 7.2 | | No UDP rules: with the network off, a UDP socket the caller hands over can send. |
//!
//! procage uses the rights up to ABI [`BACKEND_MAX_ABI`]; each was tested on
//! a mainline kernel of that ABI (see the testing docs).
//!
//! Distributions backport Landlock (RHEL 9.6 has ABI 5), so [`probe()`] asks
//! the kernel rather than reading its version.
//! [`CageOptions::with_landlock_abi`] lowers and enforces a policy as on an
//! older kernel: to test what your users' kernels give, or to run one plan
//! on every host of a fleet.
//!
//! **Reading everything except secrets.** A policy that reads `/` reaches
//! the paths of the `secrets`, `trust-handoff` and `persistence` classes.
//! On tier T1 the paths that exist at spawn are masked. On tier T2 a hidden
//! path (an `Access::Hide` rule, or the secrets class) that no write rule
//! reaches is kept out by granting the trees around it entry by entry, as
//! listed at spawn: entries added later on the way are denied, the
//! directories on the way cannot be listed, symbolic links on the way are
//! not followed, and `stat` of the hidden path still works. A hidden or
//! protected path inside a writable tree cannot be kept out on T2, and a
//! write grant bound around one fails the spawn. Each of these is an
//! approximation the caller accepts with
//! [`LowerOptions::accept_spawn_snapshot`](procage_policy::LowerOptions::accept_spawn_snapshot).
//!
//! **Unix sockets.** `ipc.unix_sockets` allows `AF_UNIX` sockets when the
//! network is off or `Network::Ip`. From Landlock ABI 9 both tiers enforce it
//! exactly: a pathname socket outside its paths cannot be reached, and
//! abstract sockets are scoped to the run. With `Network::All` every
//! pathname socket stays reachable. Below ABI 9, on tier T1
//! abstract sockets stay inside the cage's network namespace (with
//! `Network::Ip`, which has none, the scope keeps them out from ABI 6, and
//! the setting is refused below) and every
//! listening socket outside the allowed paths, as listed in `/proc/net/unix`
//! at spawn, is masked; sockets bound later outside them stay reachable (an
//! approximation accepted with the same option), and tier T2 cannot
//! restrict pathname sockets and refuses the setting.
//!
//! **Service and engine sockets.** With `Network::All` (or
//! `ipc.unix_sockets` set), the `service-handoff` and `container-engines`
//! classes keep the child from the D-Bus buses, the systemd managers and
//! container engines (see `procage_policy::presets` for the lists). The
//! cage looks for these sockets in the system locations and every runtime
//! directory (`/run/user/*`, `$XDG_RUNTIME_DIR`,
//! [`CageOptions::with_runtime_dir`]) when it is made and at each spawn.
//! Tier T1 covers what it finds and the classes' directories as a whole; a
//! socket bound later elsewhere is not covered, so this is an approximation
//! accepted with the spawn snapshot or by name. Tier T2 cannot cover a socket:
//! while one exists the cage is refused, naming it, and a spawn is refused if
//! one appeared after the cage was made; `Network::Ip`, which refuses Unix
//! sockets, needs no search (`Relax::no_unix_sockets` switches to it). A
//! connect refused by a cover is not reported as a violation. Waive
//! `container-engines` for builds that need an engine.
//!
//! **Limits:**
//!
//! - no PID namespace or private `/proc`, so signal scoping needs Landlock
//!   ABI 6;
//! - with `Lifetime::Tree`, a descendant that double-forks and starts its
//!   own session is reparented away from the child and outlives the run;
//! - no loopback networking (a gap on both tiers); proxy-only networking
//!   needs T1 and [`CageOptions::with_proxy`]; on T2,
//!   Unix-socket restrictions need Landlock ABI 9; protect, and hide
//!   inside a writable tree, are gaps; glob rules are gaps on both tiers;
//! - the probe is cached per process, not per boot.

mod child;
mod classes;
mod probe;
mod seccomp;
mod services;
mod spawn;
mod sys;
pub(crate) use sys::{open_terminal, set_window};
mod violations;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use procage_policy::linux::RuleTarget;
use procage_policy::{
    Construct, HardDenyClass, LinuxPlan, LowerError, LowerOptions, Plan, Policy, Relax, Relaxed,
    Target, Tier, Tty, lift, lower,
};

pub use crate::unix::TMPDIR_GRANT;
pub use crate::violation::{Coverage, DeniedBy, Violation, Violations};
pub use child::Child;
pub use probe::{Probe, probe};

use crate::unix::TmpdirGuard;

/// The newest Landlock ABI whose rights this backend uses.
pub const BACKEND_MAX_ABI: u8 = 11;

/// Ends the run of a [`Cage::exec_session`] helper: kills every live
/// process of session `pid` (the helper's pid), then its process group.
/// Call it before reaping the helper, while the session's id cannot belong
/// to another process. Pids 0 and 1 are ignored.
pub fn end_session(pid: u32) {
    if let Ok(pid) = libc::pid_t::try_from(pid)
        && pid > 1
    {
        child::kill_session(pid);
    }
}

/// A step of the in-child sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Resetting ignored signals to their default action (a spawn), then
    /// starting a new session or process group.
    Session,
    /// Setting the parent-death signal.
    Lifetime,
    /// Creating the namespaces (T1).
    Namespaces,
    /// Writing the uid and gid maps (T1).
    IdMap,
    /// Making the mounts (T1).
    Mounts,
    /// Dropping capabilities.
    Capabilities,
    /// Setting resource limits.
    Rlimit,
    /// Marking inherited descriptors close-on-exec.
    Fds,
    /// Setting `no_new_privs`.
    NoNewPrivs,
    /// Restricting the process with Landlock.
    Landlock,
    /// Installing the seccomp filter.
    Seccomp,
    /// Confirming that seccomp and `no_new_privs` hold.
    Verify,
    /// Handing a listener to the parent: the seccomp listener (violation
    /// reporting), or the proxy listeners (with a proxy of the cage's own,
    /// after bringing up the namespace's loopback).
    Listener,
}

impl Step {
    fn from_code(code: u32) -> Option<Step> {
        use sys::steps::*;
        Some(match code {
            SESSION => Step::Session,
            LIFETIME => Step::Lifetime,
            NAMESPACES => Step::Namespaces,
            ID_MAP => Step::IdMap,
            MOUNTS => Step::Mounts,
            CAPABILITIES => Step::Capabilities,
            RLIMIT => Step::Rlimit,
            FDS => Step::Fds,
            NO_NEW_PRIVS => Step::NoNewPrivs,
            LANDLOCK => Step::Landlock,
            SECCOMP => Step::Seccomp,
            VERIFY => Step::Verify,
            LISTENER => Step::Listener,
            _ => return None,
        })
    }
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Step::Session => "new session",
            Step::Lifetime => "parent-death signal",
            Step::Namespaces => "create namespaces",
            Step::IdMap => "write id maps",
            Step::Mounts => "mounts",
            Step::Capabilities => "drop capabilities",
            Step::Rlimit => "resource limits",
            Step::Fds => "close inherited descriptors",
            Step::NoNewPrivs => "no_new_privs",
            Step::Landlock => "apply Landlock",
            Step::Seccomp => "install seccomp filter",
            Step::Verify => "verify sandbox",
            Step::Listener => "hand over the seccomp listener",
        })
    }
}

/// Something this host or this procage version cannot do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// Landlock is missing or older than the tier needs.
    Landlock {
        /// The ABI the kernel reports (0: none).
        abi: u8,
        /// The ABI the tier needs.
        needed: u8,
    },
    /// The requested tier is not available on this host.
    Tier {
        /// The tier asked for.
        requested: Tier,
        /// The errno of the user-namespace probe, if it failed.
        userns_errno: Option<i32>,
    },
    /// A syscall in the policy has no number on this architecture.
    Syscall {
        /// Its name.
        name: String,
    },
    /// A policy setting this backend cannot apply.
    Setting {
        /// The setting.
        setting: &'static str,
    },
    /// [`Cage::exec`] on tier T1 was called in a process with more than one
    /// thread, which user namespaces refuse.
    ExecThreads {
        /// The threads the process has.
        threads: usize,
    },
    /// `EnvPolicy::Passthrough` cannot be used: this standard library does
    /// not show whether `Command::env_clear` was called, so procage cannot
    /// tell whether the caller's environment may be passed.
    EnvClear,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unsupported::Landlock { abi: 0, needed } => {
                write!(f, "Landlock is not available (ABI {needed} needed)")
            }
            Unsupported::Landlock { abi, needed } => {
                write!(f, "Landlock ABI {abi} is older than the {needed} needed")
            }
            Unsupported::Tier {
                requested,
                userns_errno,
            } => {
                write!(f, "tier {requested} is not available on this host")?;
                match userns_errno {
                    Some(e) => write!(
                        f,
                        " (user namespaces: {})",
                        io::Error::from_raw_os_error(*e)
                    ),
                    None => Ok(()),
                }
            }
            Unsupported::Syscall { name } => {
                write!(f, "syscall `{name}` has no number on this architecture")
            }
            Unsupported::ExecThreads { threads } => write!(
                f,
                "Cage::exec on tier T1 needs a single-threaded process (this one has {threads} \
                 threads, which user namespaces refuse): call it before starting threads, or \
                 choose tier T2 with CageOptions::with_tier"
            ),
            Unsupported::EnvClear => write!(
                f,
                "EnvPolicy::Passthrough needs to see whether Command::env_clear was called, \
                 which this Rust standard library does not show; use EnvPolicy::Allowlist"
            ),
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
    /// The policy declares the `tmpdir` grant, which [`Cage::exec`] cannot
    /// provide: no handle would remove the directory.
    TmpdirWithExec,
    /// On tier T2, a grant with write access was bound around a hidden
    /// path, which piecewise grants cannot keep out.
    Covers {
        /// The grant.
        name: String,
        /// The hidden path inside it.
        hidden: PathBuf,
    },
    /// On tier T2, the bound path reaches paths of a hard-deny class that
    /// Landlock cannot deny inside it.
    CoversClass {
        /// The grant.
        name: String,
        /// The class.
        class: HardDenyClass,
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
            GrantError::Covers { name, hidden } => write!(
                f,
                "grant {name} gives write access around {}, which tier T2 cannot keep hidden \
                 inside a writable tree: bind the grant elsewhere, or use tier T1",
                hidden.display()
            ),
            GrantError::TmpdirWithExec => write!(
                f,
                "the tmpdir grant needs a handle that removes the directory, and Cage::exec \
                 returns none: use Cage::spawn, or bind a directory of your own to another grant"
            ),
            GrantError::Reserved { name } => {
                write!(
                    f,
                    "grant {name} is bound by procage itself (a private temporary directory)"
                )
            }
            GrantError::CoversClass { name, class } => write!(
                f,
                "grant {name} reaches paths of the hard-deny class {class}, which tier T2 cannot deny inside it"
            ),
        }
    }
}

#[cfg(feature = "tokio")]
pub use crate::async_child::AsyncChild;

/// Why no caged child runs.
#[derive(Debug)]
#[non_exhaustive]
pub enum SpawnError {
    /// [`Cage::exec_session`] in a process that leads a process group but
    /// no session, which cannot start one: start the helper as a plain
    /// child, or in a session of its own.
    GroupLeader,
    /// This host or version cannot do it.
    Unsupported(Unsupported),
    /// The policy could not be lowered for the tier.
    Lower(LowerError),
    /// A policy path could not be used.
    Path {
        /// The path.
        path: String,
        /// Why.
        error: io::Error,
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
    /// A writable tree has more entries than the walk for hard-deny paths
    /// may visit.
    Walk {
        /// The tree.
        root: PathBuf,
        /// The limit.
        limit: usize,
    },
    /// On tier T1, a path the cage mounts over no longer leads to the
    /// object it planned (a link or another file was put in its place
    /// after the plan); nothing was mounted and the target did not run.
    MountMoved {
        /// The planned path.
        path: PathBuf,
        /// The symbolic link on the way, if the path now passes one.
        link: Option<PathBuf>,
    },
    /// A step in the child failed; the target did not run.
    Apply {
        /// The step.
        step: Step,
        /// The OS error number.
        errno: i32,
    },
    /// Spawning failed (for example, the target cannot be executed).
    Io(io::Error),
    /// A protected, hidden or class file has another name (a hard link),
    /// which path rules do not cover; see [`LinkAudit`](crate::LinkAudit).
    HardLinks(Vec<crate::LinkFinding>),
    /// A question to [`Cage::explain`] has no answer.
    Explain(procage_policy::explain::ExplainError),
    /// [`Cage::spawn_async`] was called outside a tokio runtime.
    #[cfg(feature = "tokio")]
    NoRuntime,
}

impl fmt::Display for SpawnError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpawnError::GroupLeader => f.write_str(
                "Cage::exec_session in a process group leader that leads no session: \
                 start the helper as a plain child, or in a session of its own",
            ),
            SpawnError::Unsupported(u) => write!(f, "unsupported: {u}"),
            SpawnError::Lower(e) => write!(f, "{e}"),
            SpawnError::Path { path, error } => write!(f, "cannot use {path}: {error}"),
            SpawnError::Grant(e) => write!(f, "{e}"),
            SpawnError::Fd { fd } => write!(f, "descriptor {fd} handed to the spawn is not open"),
            SpawnError::Tmpdir(e) => {
                write!(f, "cannot create the private temporary directory: {e}")
            }
            SpawnError::Walk { root, limit } => write!(
                f,
                "{} has more than {limit} entries to search for hard-deny paths",
                root.display()
            ),
            SpawnError::MountMoved { path, link } => {
                write!(f, "{} moved after the mount plan", path.display())?;
                if let Some(link) = link {
                    write!(f, " (through the link {})", link.display())?;
                }
                f.write_str("; nothing was mounted and the target did not run")
            }
            SpawnError::Apply { step, errno } => write!(
                f,
                "the child failed at step `{step}`: {}; the target did not run",
                io::Error::from_raw_os_error(*errno)
            ),
            SpawnError::Io(e) => write!(f, "{e}"),
            SpawnError::HardLinks(found) => f.write_str(&crate::audit::refusal(found)),
            SpawnError::Explain(e) => write!(f, "{e}"),
            #[cfg(feature = "tokio")]
            SpawnError::NoRuntime => {
                f.write_str("spawn_async needs a tokio runtime on the calling thread")
            }
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

/// Options for [`Cage::with_options`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CageOptions {
    /// Options for lowering the policy.
    pub lower: LowerOptions,
    /// The tier to use (default: the strongest the host allows).
    pub tier: Option<Tier>,
    /// The most directory entries one spawn visits while looking for
    /// hard-deny paths under writable trees (default 200,000).
    pub walk_limit: usize,
    /// Home directories besides `/root`, those under `/home` and `$HOME`.
    pub homes: Vec<PathBuf>,
    /// The highest Landlock ABI to use (default: the kernel's). It never
    /// raises the ABI above the kernel's.
    pub landlock_abi: Option<u8>,
    /// Whether spawns report denied operations (see
    /// [`CageOptions::with_violations`]).
    pub violations: bool,
    /// Runtime directories besides those under `/run/user` and
    /// `$XDG_RUNTIME_DIR`, whose bus, service-manager and engine sockets
    /// the cage keeps out of reach.
    pub runtime_dirs: Vec<PathBuf>,
    /// Whether receipts hold the policy (see
    /// [`CageOptions::with_policy_in_receipt`]).
    pub policy_in_receipt: bool,
    /// What the link check does before each spawn (default: refuse).
    pub link_audit: crate::LinkAudit,
    /// Subtrees the link check does not examine for protected files (see
    /// [`CageOptions::with_link_exemption`]).
    pub link_exempt: Vec<PathBuf>,
    /// Whether runs note what they leave behind (see
    /// [`CageOptions::with_handoff_audit`]).
    pub handoff_audit: bool,
    /// The proxy each run of a `Network::Proxy` policy gets (see
    /// [`CageOptions::with_proxy`]).
    #[cfg(feature = "proxy")]
    pub proxy: Option<procage_proxy::Proxy>,
}

impl Default for CageOptions {
    fn default() -> Self {
        Self {
            lower: LowerOptions::default(),
            tier: None,
            walk_limit: 200_000,
            homes: Vec::new(),
            landlock_abi: None,
            violations: false,
            runtime_dirs: Vec::new(),
            policy_in_receipt: false,
            link_audit: crate::LinkAudit::Refuse,
            link_exempt: Vec::new(),
            handoff_audit: false,
            #[cfg(feature = "proxy")]
            proxy: None,
        }
    }
}

impl CageOptions {
    /// These options with `lower` as the lowering options.
    pub fn with_lower(mut self, lower: LowerOptions) -> Self {
        self.lower = lower;
        self
    }

    /// These options for tier `tier`.
    pub fn with_tier(mut self, tier: Tier) -> Self {
        self.tier = Some(tier);
        self
    }

    /// These options with a walk limit of `limit` entries.
    pub fn with_walk_limit(mut self, limit: usize) -> Self {
        self.walk_limit = limit;
        self
    }

    /// These options with `home` as one more home directory.
    pub fn with_home(mut self, home: impl AsRef<Path>) -> Self {
        self.homes.push(home.as_ref().to_path_buf());
        self
    }

    /// These options with the link check in `mode` (see [`crate::audit`]).
    pub fn with_link_audit(mut self, mode: crate::LinkAudit) -> Self {
        self.link_audit = mode;
        self
    }

    /// These options with `path` exempt from the link check for protected
    /// files: a file at or below it may have another name. Meant for a store
    /// whose files are written once and never rewritten in place, such as a
    /// repository's `.git/objects`, which a local `git clone` hard-links to
    /// the source repository's. A protected file there can then be changed
    /// through a name in a writable tree (git notices a changed object when
    /// it checks one, as `git fsck` does); hidden files are examined
    /// everywhere. The path must be absolute (a relative one fails the cage
    /// with [`Unsupported::Setting`]); [`Audit`](crate::Audit) lists a run's
    /// exemptions.
    pub fn with_link_exemption(mut self, path: impl AsRef<Path>) -> Self {
        self.link_exempt.push(path.as_ref().to_path_buf());
        self
    }

    /// These options with the handoff audit: each run notes the trust-handoff
    /// files, symbolic links and repositories of the writable trees, and
    /// [`Child::audit`] lists what it created or changed (see [`crate::audit`]).
    pub fn with_handoff_audit(mut self) -> Self {
        self.handoff_audit = true;
        self
    }

    /// These options with receipts that hold the policy itself and the
    /// subjects (often paths) of `fit`'s relaxations. Without it a receipt
    /// names the policy by digest only.
    pub fn with_policy_in_receipt(mut self) -> Self {
        self.policy_in_receipt = true;
        self
    }

    /// These options with `dir` as one more runtime directory (like
    /// `XDG_RUNTIME_DIR`): its bus, service-manager and engine sockets are
    /// kept out of reach like those of the directories procage finds.
    pub fn with_runtime_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.runtime_dirs.push(dir.as_ref().to_path_buf());
        self
    }

    /// These options using at most Landlock ABI `abi`, as on an older
    /// kernel: the policy is lowered and enforced for that ABI, so its gaps
    /// and plan are the ones such a kernel gives. Use it to test a policy
    /// against the kernels your users run, or to give every host of a fleet
    /// the same plan. A cap above the kernel's ABI has no effect.
    ///
    /// ```no_run
    /// # use procage::linux::{Cage, CageOptions};
    /// # use procage::policy::Policy;
    /// # fn main() -> Result<(), procage::linux::SpawnError> {
    /// // What does this policy get on Debian 12 (Linux 6.1, ABI 2)?
    /// let cage = Cage::with_options(&Policy::default(), &CageOptions::default().with_landlock_abi(2))?;
    /// assert_eq!(cage.landlock_abi(), 2);
    /// # Ok(())
    /// # }
    /// ```
    pub fn with_landlock_abi(mut self, abi: u8) -> Self {
        self.landlock_abi = Some(abi);
        self
    }

    /// These options with violation reporting: every spawn's
    /// [`Child::violations`] lists the system calls the seccomp filter
    /// refused it (`ptrace`, `io_uring_setup`, an IP socket without network,
    /// …), with the process, the target and why, exactly and complete once
    /// the run's processes are gone ([`Coverage::SystemCalls`]). File,
    /// network and signal denials by Landlock are not reported: Landlock
    /// reports them only to the privileged audit subsystem.
    ///
    /// Each reporting spawn runs one supervisor thread, which answers every
    /// refused call with `EPERM` (what it returns without reporting) and
    /// ends with the run's processes. Inside a sandbox whose filter already
    /// has a listener, the kernel refuses a second one: the run is confined
    /// as without reporting and its record says why. A call an outer
    /// sandbox refuses first (Docker's default profile refuses `bpf`) never
    /// reaches procage's filter and is not reported.
    pub fn with_violations(mut self) -> Self {
        self.violations = true;
        self
    }

    /// These options with a proxy of the cage's own (feature `proxy`), which
    /// a `Network::Proxy` policy needs on Linux. Each spawn runs in its own
    /// network namespace (tier T1), in which the child listens on
    /// `127.0.0.1` at the policy's ports and hands the listeners to the
    /// parent before it is restricted: they are the only endpoints the child
    /// can reach, and Landlock allows connecting to those ports only (from
    /// ABI 4). The proxy variables (`HTTP_PROXY`, `HTTPS_PROXY`,
    /// `ALL_PROXY`, lower-case too) name them. Refusals are in
    /// [`Child::violations`] when the cage reports violations; the run's
    /// connections close when the run ends. Tier T2 refuses `Network::Proxy`
    /// (a gap), and a policy without it is refused.
    #[cfg(feature = "proxy")]
    pub fn with_proxy(mut self, proxy: procage_proxy::Proxy) -> Self {
        self.proxy = Some(proxy);
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

/// A prepared policy: lowered for a tier, with its seccomp filter built,
/// reusable for any number of spawns from any thread.
#[derive(Debug, Clone)]
pub struct Cage {
    plan: LinuxPlan,
    filter: Arc<[seccomp::Insn]>,
    homes: Vec<PathBuf>,
    walk_limit: usize,
    /// With violation reporting: the filter whose `EPERM` denies notify.
    notifying: Option<Arc<[seccomp::Insn]>>,
    /// The filter for [`Cage::exec`] under `Lifetime::Run`: the command
    /// keeps the caller's session, so `setpgid` is refused too.
    exec_filter: Option<Arc<[seccomp::Insn]>>,
    /// The runtime directories searched for service sockets.
    runtime: Vec<PathBuf>,
    /// The objects the declared T1 mounts name, found when the cage was made.
    declared: Arc<spawn::Declared>,
    /// The approximations the caller accepts, for sockets found at spawn.
    allowed: BTreeSet<Construct>,
    /// What every run's receipt starts from.
    facts: Arc<crate::receipt::CageFacts>,
    /// The audits every spawn runs.
    audit: Arc<crate::audit::CageAudit>,
    /// Answers [`Cage::explain`].
    explainer: Arc<crate::explain::Lazy>,
    /// The cage's own proxy.
    #[cfg(feature = "proxy")]
    proxied: Option<crate::proxied::Proxied>,
}

impl Cage {
    /// Prepares `policy` with default options.
    pub fn new(policy: &Policy) -> Result<Cage, SpawnError> {
        Cage::with_options(policy, &CageOptions::default())
    }

    /// Prepares `policy`, giving up exactly the constructs this host cannot
    /// enforce and `relax` accepts. Returns the cage and what was relaxed,
    /// each with what would lift it (tier T1 or a newer Landlock ABI). Any
    /// other gap fails as [`Cage::with_options`] does, with every remaining
    /// gap, and nothing is relaxed that `relax` does not name.
    pub fn fit(
        policy: &Policy,
        options: &CageOptions,
        relax: &Relax,
    ) -> Result<(Cage, Vec<Relaxed>), SpawnError> {
        let mut fitted = policy.clone();
        let mut relaxed = Vec::new();
        // Each round relaxes at least one construct; a few always suffice.
        for _ in 0..4 {
            let gaps = match Cage::with_options(&fitted, options) {
                Ok(cage) => return Ok(cage.relaxed(&fitted, options, relaxed)),
                Err(SpawnError::Lower(LowerError::Gaps(gaps))) => gaps,
                Err(e) => return Err(e),
            };
            let done = relax
                .apply(&mut fitted, &gaps)
                .map_err(|rest| SpawnError::Lower(LowerError::Gaps(rest)))?;
            relaxed.extend(done.into_iter().map(|(gap, relaxation)| {
                Relaxed {
                    lift: socket_lift(&gap)
                        .unwrap_or_else(|| lift(policy, &gap, &options.lower, BACKEND_MAX_ABI)),
                    gap,
                    relaxation,
                }
            }));
        }
        Cage::with_options(&fitted, options).map(|cage| cage.relaxed(&fitted, options, relaxed))
    }

    /// This cage with its receipts listing `relaxed`.
    fn relaxed(
        mut self,
        fitted: &Policy,
        options: &CageOptions,
        relaxed: Vec<Relaxed>,
    ) -> (Cage, Vec<Relaxed>) {
        self.facts = Arc::new(facts(fitted, options, &self.plan, &relaxed));
        (self, relaxed)
    }

    /// Prepares `policy` for the strongest tier the host allows, or for
    /// `options.tier`.
    pub fn with_options(policy: &Policy, options: &CageOptions) -> Result<Cage, SpawnError> {
        let host = probe();
        let tier = match options.tier {
            Some(Tier::T1) if host.tier != Some(Tier::T1) => {
                return Err(SpawnError::Unsupported(Unsupported::Tier {
                    requested: Tier::T1,
                    userns_errno: host.userns_errno,
                }));
            }
            Some(tier) => tier,
            None => host.tier.unwrap_or(Tier::T2),
        };
        // One ABI for the tier check, the lowering and the ruleset.
        let abi = host
            .landlock_abi
            .min(BACKEND_MAX_ABI)
            .min(options.landlock_abi.unwrap_or(u8::MAX));
        if abi < tier.min_landlock_abi() {
            return Err(SpawnError::Unsupported(Unsupported::Landlock {
                abi,
                needed: tier.min_landlock_abi(),
            }));
        }
        let target = Target::Linux {
            tier,
            landlock_abi: abi,
        };
        let Plan::Linux(mut plan) = lower(policy, target, &options.lower)? else {
            unreachable!("lowering for Linux yields a Linux plan");
        };
        let build = |notify| {
            seccomp::build(&plan.seccomp, &seccomp::NATIVE, notify)
                .map_err(|name| SpawnError::Unsupported(Unsupported::Syscall { name }))
        };
        let filter: Arc<[seccomp::Insn]> = build(false)?.into();
        let notifying = if options.violations {
            Some(Arc::from(build(true)?))
        } else {
            None
        };
        let exec_filter = if policy.process.fork
            && policy.process.lifetime == procage_policy::Lifetime::Run
            && policy.tty != Tty::Inherit
        {
            use procage_policy::linux::{Action, Condition, SeccompRule, Syscall};
            let mut rules = plan.seccomp.clone();
            rules.push(SeccompRule {
                syscall: Syscall::Setpgid,
                condition: Condition::Always,
                action: Action::Eperm,
                reason: Some(procage_policy::DenyReason::Lifetime),
            });
            Some(Arc::from(
                seccomp::build(&rules, &seccomp::NATIVE, false)
                    .map_err(|name| SpawnError::Unsupported(Unsupported::Syscall { name }))?,
            ))
        } else {
            None
        };
        let homes = classes::homes(&options.homes);
        let rules = spawn::rule_paths(&plan);
        classes::home_gaps(&mut plan, &rules, &homes, &options.lower, target)?;
        proc_links(&mut plan, &rules, &options.lower.allow_degrade, target)?;
        let runtime = services::runtime_dirs(&options.runtime_dirs);
        if !plan.service_sockets.is_empty() {
            let found = services::find(&plan.service_sockets, &runtime, abstract_visible(&plan));
            let outcome = services::decide(&plan, &found, &options.lower.allow_degrade);
            if !outcome.gaps.is_empty() {
                return Err(SpawnError::Lower(LowerError::Gaps(outcome.gaps)));
            }
            if outcome.scope {
                let scopes = &mut plan.landlock.scopes;
                *scopes = procage_policy::linux::Scopes(
                    scopes.0 | procage_policy::linux::Scopes::ABSTRACT_UNIX_SOCKET.0,
                );
            }
            for d in outcome.degradations {
                if !plan.degradations.iter().any(|k| k.construct == d.construct) {
                    plan.degradations.push(d);
                }
            }
            plan.degradations.sort();
        }
        #[cfg(feature = "proxy")]
        let proxied = match &options.proxy {
            None => None,
            Some(proxy) => Some(crate::proxied::Proxied::new(proxy, &policy.net).ok_or(
                SpawnError::Unsupported(Unsupported::Setting {
                    setting: "CageOptions::with_proxy without Network::Proxy",
                }),
            )?),
        };
        #[cfg(not(feature = "proxy"))]
        let proxied: Option<()> = None;
        if matches!(
            plan.network,
            procage_policy::linux::LinuxNetwork::ProxyBridge { .. }
        ) && proxied.is_none()
        {
            return Err(SpawnError::Unsupported(Unsupported::Setting {
                setting: "Network::Proxy on Linux without CageOptions::with_proxy",
            }));
        }
        let declared = Arc::new(spawn::declare(&mut plan));
        let facts = Arc::new(facts(policy, options, &plan, &[]));
        let audit = Arc::new(cage_audit(policy, options, &plan, &homes)?);
        let explainer = Arc::new(crate::explain::Lazy::new(
            policy.clone(),
            target,
            options.lower.clone(),
        ));
        Ok(Cage {
            plan,
            filter,
            homes,
            walk_limit: options.walk_limit,
            notifying,
            exec_filter,
            runtime,
            declared,
            allowed: options.lower.allow_degrade.clone(),
            facts,
            audit,
            explainer,
            #[cfg(feature = "proxy")]
            proxied,
        })
    }

    /// Why a child of this cage, spawned with `grants`, may or may not
    /// perform `op` on `path` as the file is now: the deciding rule and what
    /// would change it (see [`procage_policy::explain`]).
    ///
    /// Symbolic links in `path` are resolved, the grants are bound as a
    /// spawn binds them, and the homes are the cage's. The grant of the
    /// private temporary directory is left out: its path exists only during
    /// a run.
    ///
    /// The answer names the policy's rules: show it to the user, do not
    /// relay it into the cage unfiltered.
    pub fn explain(
        &self,
        op: procage_policy::explain::Op,
        path: impl AsRef<Path>,
        grants: &Grants,
    ) -> Result<procage_policy::explain::Answer, SpawnError> {
        let path = path.as_ref();
        let question = crate::explain::question(op, path).map_err(|error| SpawnError::Path {
            path: path.display().to_string(),
            error,
        })?;
        let bound = self.bind(grants, &self.declared())?;
        let context = crate::explain::context(bound, &self.homes).map_err(SpawnError::Io)?;
        self.explainer
            .get()?
            .explain(&question, &context)
            .map_err(SpawnError::Explain)
    }

    /// The lowered plan.
    pub fn plan(&self) -> &LinuxPlan {
        &self.plan
    }

    /// The tier this cage applies.
    pub fn tier(&self) -> Tier {
        self.plan.tier
    }

    /// The Landlock ABI this cage is lowered and enforced for: the kernel's,
    /// at most [`BACKEND_MAX_ABI`] and the cap in [`CageOptions`].
    pub fn landlock_abi(&self) -> u8 {
        self.plan.landlock_abi
    }

    fn declared(&self) -> BTreeSet<&str> {
        self.plan
            .landlock
            .rules
            .iter()
            .filter_map(|r| match &r.target {
                RuleTarget::Grant(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Spawns `command` in this cage, with `grants` bound for this spawn.
    ///
    /// The command's program must be executable under the policy. Fails
    /// without forking when a grant binding is wrong or a policy path is
    /// missing. The child receives only standard input, output and error.
    ///
    /// The child's environment comes from the policy's
    /// [`EnvPolicy`](procage_policy::EnvPolicy) and the variables set or
    /// removed on `command`, which win (see [`crate::hygiene`]). After
    /// `Command::env_clear`, no variable of the caller is passed under any
    /// policy: the child gets exactly the variables set on `command`. Fails
    /// with [`Unsupported::EnvClear`] before forking when a passthrough
    /// policy is used and the standard library does not show whether
    /// `env_clear` was called.
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
        let launch = self.launch(command, grants, fds)?;
        let spawned = command.spawn();
        launch.release(command);
        match spawned {
            Ok(inner) => Ok(self.adopt(launch, crate::unix::Proc::Std(inner))),
            Err(e) => Err(launch.abandon(e)),
        }
    }

    /// Everything a spawn does before the fork: the checks, the child
    /// sequence installed on `command` and the link check.
    pub(crate) fn launch(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
    ) -> Result<Launch, SpawnError> {
        let session = match self.plan.hygiene.tty {
            Tty::Inherit => sys::Session::Group,
            Tty::NewPty => sys::Session::Terminal,
            Tty::None => sys::Session::New,
        };
        let (parent_end, notify) = match &self.notifying {
            Some(filter) => {
                let (parent_end, child_end) = sys::socket_pair().map_err(SpawnError::Io)?;
                (
                    Some(parent_end),
                    Some(sys::Notify::new(filter.to_vec(), child_end)),
                )
            }
            None => (None, None),
        };
        #[cfg(feature = "proxy")]
        let (bridge_end, bridge) = match &self.proxied {
            Some(proxied) => {
                let (parent_end, child_end) = sys::socket_pair().map_err(SpawnError::Io)?;
                let ports: Vec<u16> = proxied.protocols().iter().map(|&(_, p)| p).collect();
                let addrs: Vec<_> = proxied
                    .protocols()
                    .iter()
                    .map(|&(protocol, port)| {
                        (protocol, std::net::SocketAddr::from(([127, 0, 0, 1], port)))
                    })
                    .collect();
                crate::proxied::set_env(command, &addrs);
                (Some(parent_end), Some(sys::Bridge::new(ports, child_end)))
            }
            None => (None, None),
        };
        #[cfg(not(feature = "proxy"))]
        let bridge = None;
        let (dropped, removal, proc, mounts, pty) =
            self.prepare(command, grants, fds, session, notify, bridge)?;
        // The link check is the last step before the fork.
        let run_audit = self.audit.before_spawn().map_err(SpawnError::HardLinks)?;
        let names = grants.bindings.iter().map(|(n, _)| n.clone()).collect();
        Ok(Launch {
            parent_end,
            dropped,
            removal,
            proc,
            run_audit,
            names,
            mounts,
            pty,
            #[cfg(feature = "proxy")]
            bridge_end,
        })
    }

    /// The handle of the process `launch` was spawned as.
    pub(crate) fn adopt(&self, launch: Launch, inner: crate::unix::Proc) -> Child {
        let Launch {
            parent_end,
            dropped,
            removal,
            proc,
            run_audit,
            mut names,
            pty,
            #[cfg(feature = "proxy")]
            bridge_end,
            ..
        } = launch;
        let reporting = match parent_end {
            None => child::Reporting::Off,
            Some(socket) => self.supervise(&socket),
        };
        #[cfg(feature = "proxy")]
        let proxy_run = match (&self.proxied, bridge_end) {
            (Some(proxied), Some(socket)) => {
                // The child sent one listener per protocol before its exec.
                let mut listeners = Vec::new();
                for &(protocol, _) in proxied.protocols() {
                    if let Ok(sys::HandOver::Listener(fd)) = sys::receive(&socket) {
                        listeners.push((protocol, std::net::TcpListener::from(fd)));
                    }
                }
                let record = match &reporting {
                    child::Reporting::On { record, .. } => Some(record.clone()),
                    _ => None,
                };
                proxied.serve(listeners, record)
            }
            _ => None,
        };
        let tmpdir = removal.disarm();
        if tmpdir.is_some() {
            names.push(TMPDIR_GRANT.into());
        }
        let mut facts = crate::receipt::RunFacts::new(self.facts.clone(), names);
        if proc {
            facts = facts.with_approximation(crate::receipt::ReceiptApproximation {
                construct: Construct::ProcOtherProcesses,
                note: procage_policy::linux::PROC_OTHER_PROCESSES_NOTE.into(),
            });
        }
        let mut child = Child::new(inner, dropped, tmpdir, reporting, facts, run_audit);
        #[cfg(feature = "proxy")]
        child.set_proxy(proxy_run);
        child.set_pty(pty);
        child
    }

    /// Takes the listener the child sent and starts the run's supervisor;
    /// without a listener, the record says why.
    fn supervise(&self, socket: &std::os::fd::OwnedFd) -> child::Reporting {
        let unavailable = |reason: String| child::Reporting::Unavailable(reason);
        match sys::receive(socket) {
            Ok(sys::HandOver::Listener(listener)) => {
                let record = Arc::new(std::sync::Mutex::new(crate::violation::Record::new(
                    Coverage::SystemCalls,
                )));
                let rules: Arc<[_]> = self.plan.seccomp.clone().into();
                match violations::start(listener, rules, record.clone()) {
                    Ok(done) => child::Reporting::On { record, done },
                    Err(e) => unavailable(format!("cannot start the supervisor: {e}")),
                }
            }
            Ok(sys::HandOver::Refused(errno)) => unavailable(format!(
                "the kernel refused a seccomp listener ({}); refused calls still fail",
                std::io::Error::from_raw_os_error(errno)
            )),
            Err(errno) => unavailable(format!(
                "no listener arrived from the child ({})",
                std::io::Error::from_raw_os_error(errno)
            )),
        }
    }

    /// Turns the calling process into `command`, running in this cage: like
    /// std's [`CommandExt::exec`](std::os::unix::process::CommandExt::exec),
    /// it does not fork and returns only on failure.
    ///
    /// This is the entry point for a helper program that other code starts
    /// and owns (an MCP client, a terminal, `tokio::process::Command` with
    /// `kill_on_drop`): after `exec`, the helper's pid, standard streams,
    /// process group and exit status are the command's, so whatever kills
    /// or waits for the helper does so for the command. The confinement is
    /// the one [`Cage::spawn`] gives, except that the session and process
    /// group stay the caller's, and there is no [`Child`] handle:
    ///
    /// - the code that started the helper owns the lifetime. Start the
    ///   helper in its own process group and kill the group to end it;
    /// - under the default
    ///   [`Lifetime::Run`](procage_policy::Lifetime::Run), descendants
    ///   cannot leave that process group (`setsid` and `setpgid` fail), so
    ///   the group kill reaches all of them;
    /// - the command receives SIGKILL when the helper's parent exits.
    ///
    /// Everything that can be checked is checked before the process changes,
    /// and a failure leaves it as it was: grant bindings, the `tmpdir` grant
    /// (refused: nothing would remove the directory), on tier T1 a process
    /// with more than one thread (user namespaces refuse it: call `exec`
    /// before starting threads, or choose tier T2), the environment (see
    /// [`Cage::spawn`]) and a program that cannot be found. A failure after
    /// that ([`SpawnError::Apply`], or [`SpawnError::Io`] from `execvp`)
    /// leaves the process partly confined: the caller should exit.
    ///
    /// For a command whose descendants start process groups of their own
    /// (test runners), see [`Cage::exec_session`].
    pub fn exec(&self, command: &mut Command, grants: &Grants) -> SpawnError {
        self.exec_with_fds(command, grants, &[])
    }

    /// Like [`Cage::exec`], and also keeps `fds` open across the exec, at the
    /// same numbers. Every other descriptor numbered 3 or higher is closed.
    pub fn exec_with_fds(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
    ) -> SpawnError {
        self.exec_as(command, grants, fds, sys::Session::Keep)
    }

    /// Like [`Cage::exec`], but the command leads a session of its own: the
    /// helper starts one unless it leads one already. Its descendants may
    /// start process groups but not sessions, so the session is the run;
    /// the owner ends it with [`end_session`] of the helper's pid before
    /// reaping the helper.
    ///
    /// A helper that leads a process group but no session (started with
    /// `process_group(0)`) cannot start a session: that fails with
    /// [`SpawnError::GroupLeader`], and `Tty::Inherit` with
    /// [`Unsupported::Setting`], before the process changes. Start the
    /// helper as a plain child, or in a session of its own.
    pub fn exec_session(&self, command: &mut Command, grants: &Grants) -> SpawnError {
        self.exec_session_with_fds(command, grants, &[])
    }

    /// Like [`Cage::exec_session`], and also keeps `fds` open across the
    /// exec, at the same numbers.
    pub fn exec_session_with_fds(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
    ) -> SpawnError {
        if self.plan.hygiene.tty == Tty::Inherit {
            return SpawnError::Unsupported(Unsupported::Setting {
                setting: "Cage::exec_session with Tty::Inherit",
            });
        }
        if let (false, true) = sys::leads() {
            return SpawnError::GroupLeader;
        }
        self.exec_as(command, grants, fds, sys::Session::Lead)
    }

    fn exec_as(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
        session: sys::Session,
    ) -> SpawnError {
        use std::os::unix::process::CommandExt;
        if self.plan.hygiene.tty == Tty::NewPty {
            // No handle would hold the terminal's controller side.
            return SpawnError::Unsupported(Unsupported::Setting {
                setting: "Cage::exec with Tty::NewPty",
            });
        }
        if self.declared().contains(TMPDIR_GRANT) {
            return SpawnError::Grant(GrantError::TmpdirWithExec);
        }
        let threads = sys::thread_count();
        if self.plan.namespaces.is_some() && threads > 1 {
            return SpawnError::Unsupported(Unsupported::ExecThreads { threads });
        }
        // No handle and no supervisor: the kernel answers refused calls.
        #[cfg(feature = "proxy")]
        if self.proxied.is_some() {
            // No handle would hold the run's proxy.
            return SpawnError::Unsupported(Unsupported::Setting {
                setting: "Cage::exec with CageOptions::with_proxy",
            });
        }
        match self.prepare(command, grants, fds, session, None, None) {
            Ok((.., mounts, _)) => match self.audit.before_spawn() {
                Ok(_) => mounts.decode(command.exec()),
                Err(found) => SpawnError::HardLinks(found),
            },
            Err(e) => e,
        }
    }

    /// Everything before the fork (or the exec), without changing the
    /// calling process: checks, grant rules, the namespace plan, the
    /// environment and the child sequence installed on `command`. Returns
    /// what was dropped from the environment, the temporary directory's
    /// removal, and whether a grant reaches other processes' `/proc` entries.
    fn prepare(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
        session: sys::Session,
        notify: Option<sys::Notify>,
        bridge: Option<sys::Bridge>,
    ) -> Result<Prepared, SpawnError> {
        let keep = kept_fds(fds.iter().map(AsRawFd::as_raw_fd))?;
        if grants.bindings.iter().any(|(name, _)| name == TMPDIR_GRANT) {
            return Err(SpawnError::Grant(GrantError::Reserved {
                name: TMPDIR_GRANT.into(),
            }));
        }
        let declared = self.declared();
        let tmpdir = if declared.contains(TMPDIR_GRANT) {
            Some(crate::unix::private_tmpdir().map_err(SpawnError::Tmpdir)?)
        } else {
            None
        };
        let removal = TmpdirGuard(tmpdir.clone());
        let mut grants = grants.clone();
        if let Some(dir) = &tmpdir {
            grants = grants.bind(TMPDIR_GRANT, dir);
            if !command.get_envs().any(|(k, _)| k == "TMPDIR") {
                command.env("TMPDIR", dir);
            }
        }
        let bound = self.bind(&grants, &declared)?;
        let service_covers = self.service_covers()?;
        let pty = if session == sys::Session::Terminal {
            let (pty, device) = crate::Pty::open().map_err(SpawnError::Io)?;
            crate::unix::terminal_stdio(command, &device).map_err(SpawnError::Io)?;
            Some(pty)
        } else {
            None
        };
        let ruleset = spawn::ruleset(
            &self.plan,
            &bound,
            pty.as_ref().map(crate::Pty::device),
            &self.hidden_piecewise(),
            self.walk_limit,
        )?;
        let isolate = match self.plan.namespaces {
            Some(ns) => {
                let writable = spawn::writable(&self.plan, &bound)?;
                let mut covers = classes::t1_covers(
                    &self.plan.classes,
                    &self.homes,
                    &writable,
                    self.walk_limit,
                )?;
                if self.plan.mask_unix_sockets {
                    covers.extend(self.socket_masks(&covers)?);
                }
                covers.extend(service_covers);
                covers.sort();
                covers.dedup();
                let (uid, gid) = sys::ids();
                let net = if ns.net { libc::CLONE_NEWNET } else { 0 };
                Some(sys::Isolate {
                    flags: probe::T1_NAMESPACES | net,
                    uid_map: spawn::id_map(uid),
                    gid_map: spawn::id_map(gid),
                    mounts: spawn::mounts(&self.plan, &self.declared, &covers)?.into(),
                })
            }
            None => None,
        };
        let dropped = crate::unix::environment(command, &self.plan.hygiene.env)
            .map_err(|_| SpawnError::Unsupported(Unsupported::EnvClear))?;
        // The death signal refers to the parent of the process that runs the
        // sequence: the caller for a spawn, the caller's parent for an exec.
        let parent = if matches!(session, sys::Session::Keep | sys::Session::Lead) {
            crate::unix::find_program(command).map_err(SpawnError::Io)?;
            sys::parent_pid()
        } else {
            sys::pid()
        };
        let mounts = Mounts(isolate.as_ref().map(|iso| iso.mounts.clone()));
        sys::ChildPlan {
            session,
            parent,
            isolate,
            limits: crate::unix::limits(&self.plan.hygiene.limits),
            keep,
            ruleset,
            filter: match (&self.exec_filter, session) {
                (Some(exec), sys::Session::Keep) => exec.to_vec(),
                _ => self.filter.to_vec(),
            },
            notify,
            bridge,
        }
        .install(command);
        let proc = bound.values().any(|p| proc_gap(&self.plan, p).is_some());
        Ok((dropped, removal, proc, mounts, pty))
    }

    /// The paths kept out piecewise on tier T2: hidden rules, and the
    /// existing paths of the hidden classes in force.
    fn hidden_piecewise(&self) -> Vec<PathBuf> {
        use std::os::unix::ffi::OsStrExt;
        if self.plan.namespaces.is_some() {
            return Vec::new();
        }
        let to_path =
            |p: &procage_policy::AbsPath| PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
        let mut out: Vec<PathBuf> = self.plan.hide_by_siblings.iter().map(to_path).collect();
        for class in self.plan.classes.iter().filter(|c| c.hide) {
            for home in &self.homes {
                out.extend(class.home.iter().map(|rel| home.join(rel)));
            }
            out.extend(class.system.iter().map(to_path));
        }
        out.retain(|p| std::fs::symlink_metadata(p).is_ok());
        out.sort();
        out.dedup();
        out
    }

    /// Looks for the socket classes' sockets again for this spawn: covers on
    /// tier T1; on tier T2, or for a socket the caller did not accept as
    /// approximated, the spawn is refused, as is an abstract bus that
    /// appeared without the abstract-socket scope.
    fn service_covers(&self) -> Result<Vec<(PathBuf, classes::Cover)>, SpawnError> {
        if self.plan.service_sockets.is_empty() {
            return Ok(Vec::new());
        }
        let found = services::find(
            &self.plan.service_sockets,
            &self.runtime,
            abstract_visible(&self.plan),
        );
        let mut outcome = services::decide(&self.plan, &found, &self.allowed);
        if outcome.scope && !services::scoped(&self.plan) {
            outcome.gaps.push(procage_policy::CapabilityGap {
                construct: Construct::HdServiceHandoff,
                target: Target::Linux {
                    tier: self.plan.tier,
                    landlock_abi: self.plan.landlock_abi,
                },
                kind: procage_policy::GapKind::Unsupported,
                subject: Some("an abstract bus that appeared after the cage was made".into()),
            });
        }
        if !outcome.gaps.is_empty() {
            outcome.gaps.sort();
            return Err(SpawnError::Lower(LowerError::Gaps(outcome.gaps)));
        }
        Ok(outcome.covers)
    }

    /// Masks for the listening sockets outside `ipc.unix_sockets` (tier T1
    /// below Landlock ABI 9), except those under a path already hidden.
    fn socket_masks(
        &self,
        covers: &[(PathBuf, classes::Cover)],
    ) -> Result<Vec<(PathBuf, classes::Cover)>, SpawnError> {
        use std::os::unix::ffi::OsStrExt;
        let to_path =
            |p: &procage_policy::AbsPath| PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
        let allowed: Vec<PathBuf> = self
            .plan
            .unix_socket_paths
            .iter()
            .map(|p| std::fs::canonicalize(to_path(p)).unwrap_or_else(|_| to_path(p)))
            .collect();
        let mut masked: Vec<PathBuf> = covers
            .iter()
            .filter(|(_, c)| matches!(c, classes::Cover::Hide))
            .map(|(p, _)| p.clone())
            .collect();
        masked.extend(self.plan.mounts.iter().filter_map(|m| match m {
            procage_policy::linux::Mount::Mask(p) => Some(to_path(p)),
            _ => None,
        }));
        Ok(spawn::foreign_sockets(&allowed, &masked)?
            .into_iter()
            .map(|p| (p, classes::Cover::Hide))
            .collect())
    }

    /// Resolves each binding: declared, existing, reaching other processes'
    /// `/proc` entries only with `proc-other-processes` accepted, and on T2
    /// not reaching a hard-deny class.
    fn bind(
        &self,
        grants: &Grants,
        declared: &BTreeSet<&str>,
    ) -> Result<BTreeMap<String, PathBuf>, SpawnError> {
        let mut out = BTreeMap::new();
        for (name, path) in &grants.bindings {
            if !declared.contains(name.as_str()) {
                return Err(SpawnError::Grant(GrantError::Undeclared {
                    name: name.clone(),
                }));
            }
            let resolved = std::fs::canonicalize(path).map_err(|error| {
                SpawnError::Grant(GrantError::Missing {
                    name: name.clone(),
                    path: path.clone(),
                    error,
                })
            })?;
            if !self.allowed.contains(&Construct::ProcOtherProcesses)
                && let Some(gap) = proc_gap(&self.plan, &resolved)
            {
                return Err(SpawnError::Lower(LowerError::Gaps(vec![gap])));
            }
            if self.plan.tier == Tier::T2 {
                let writes = self.plan.landlock.rules.iter().any(|r| {
                    matches!(&r.target, RuleTarget::Grant(g) if g.as_str() == name)
                        && r.access
                            .intersect(procage_policy::linux::AccessFs::WRITE_FILE)
                            != procage_policy::linux::AccessFs::NONE
                });
                if let Some(class) =
                    classes::grant_reaches(&self.plan.classes, &self.homes, &resolved, writes)
                {
                    return Err(SpawnError::Grant(GrantError::CoversClass {
                        name: name.clone(),
                        class,
                    }));
                }
            }
            out.insert(name.clone(), resolved);
        }
        Ok(out)
    }
}

/// The gap of a rule or grant whose resolved `path` reaches other processes'
/// entries under `/proc`.
fn proc_gap(plan: &LinuxPlan, path: &Path) -> Option<procage_policy::CapabilityGap> {
    use std::os::unix::ffi::OsStrExt;
    procage_policy::linux::reaches_other_processes(path.as_os_str().as_bytes()).then(|| {
        procage_policy::CapabilityGap {
            construct: Construct::ProcOtherProcesses,
            target: Target::Linux {
                tier: plan.tier,
                landlock_abi: plan.landlock_abi,
            },
            kind: procage_policy::GapKind::Approximation,
            subject: Some(path.display().to_string()),
        }
    })
}

/// Rules that reach other processes' `/proc` entries only once resolved (a
/// symbolic link to `/proc` or `/`) are the same approximation as a rule on
/// `/proc`: refused unless accepted, then listed in the plan. The lowering
/// already counted rules spelled that way.
fn proc_links(
    plan: &mut LinuxPlan,
    rules: &[(PathBuf, bool)],
    allowed: &BTreeSet<Construct>,
    target: Target,
) -> Result<(), SpawnError> {
    use std::os::unix::ffi::OsStrExt;
    let gaps: Vec<_> = rules
        .iter()
        .filter(|(p, _)| !procage_policy::linux::reaches_other_processes(p.as_os_str().as_bytes()))
        .filter_map(|(p, _)| {
            let resolved = std::fs::canonicalize(p).ok()?;
            proc_gap(plan, &resolved).map(|mut gap| {
                gap.subject = Some(p.display().to_string());
                gap
            })
        })
        .collect();
    if gaps.is_empty() {
        return Ok(());
    }
    if !allowed.contains(&Construct::ProcOtherProcesses) {
        return Err(SpawnError::Lower(LowerError::Gaps(gaps)));
    }
    if !plan
        .degradations
        .iter()
        .any(|d| d.construct == Construct::ProcOtherProcesses)
    {
        plan.degradations.push(procage_policy::Degradation {
            construct: Construct::ProcOtherProcesses,
            target,
            note: procage_policy::linux::PROC_OTHER_PROCESSES_NOTE,
        });
        plan.degradations.sort();
    }
    Ok(())
}

/// The descriptors to hand over: those above the standard three, each of
/// A spawn up to the fork ([`Cage::launch`]).
pub(crate) struct Launch {
    parent_end: Option<std::os::fd::OwnedFd>,
    dropped: Vec<String>,
    removal: TmpdirGuard,
    proc: bool,
    run_audit: crate::audit::RunAudit,
    names: Vec<String>,
    mounts: Mounts,
    /// The controller of the run's new terminal (`Tty::NewPty`).
    pty: Option<crate::Pty>,
    /// The parent's end of the proxy listeners' socket pair.
    #[cfg(feature = "proxy")]
    bridge_end: Option<std::os::fd::OwnedFd>,
}

impl Launch {
    /// Closes the parent's copies of the terminal on `command`'s standard
    /// streams once the child has them, so the controller sees the run end.
    pub(crate) fn release(&self, command: &mut Command) {
        if self.pty.is_some() {
            crate::unix::release_stdio(command);
        }
    }

    /// The spawn failed: no process is left behind.
    pub(crate) fn abandon(self, e: std::io::Error) -> SpawnError {
        self.mounts.decode(e)
    }
}

/// What [`Cage::prepare`] made for one spawn: the names dropped from the
/// environment, the temporary directory's removal, whether a grant reaches
/// other processes' `/proc` entries, the T1 mount plan and the new
/// terminal's controller.
type Prepared = (Vec<String>, TmpdirGuard, bool, Mounts, Option<crate::Pty>);

/// The T1 mount plan a spawn handed to its child, kept to name the path
/// when the child refuses a moved mount.
pub(crate) struct Mounts(Option<std::sync::Arc<[sys::ChildMount]>>);

impl Mounts {
    fn decode(&self, e: std::io::Error) -> SpawnError {
        match spawn::decode(e) {
            SpawnError::Apply {
                step: Step::Mounts,
                errno: libc::ELOOP | libc::ESTALE,
            } if let Some(moved) = self.0.as_deref().and_then(spawn::moved) => moved,
            other => other,
        }
    }
}

/// which must be open, sorted.
fn kept_fds(fds: impl IntoIterator<Item = i32>) -> Result<Vec<i32>, SpawnError> {
    let mut keep: Vec<i32> = fds.into_iter().filter(|&fd| fd > 2).collect();
    keep.sort_unstable();
    keep.dedup();
    match keep.iter().find(|&&fd| !sys::fd_is_open(fd)) {
        Some(&fd) => Err(SpawnError::Fd { fd }),
        None => Ok(keep),
    }
}

/// Probes for procage's own tests; not part of the API.
#[doc(hidden)]
pub mod testing {
    use super::sys;

    /// Whether the calling process leads its own session.
    pub fn is_session_leader() -> bool {
        sys::leadership().0
    }

    /// Whether the calling process leads its own process group.
    pub fn is_group_leader() -> bool {
        sys::leadership().1
    }

    /// Clears close-on-exec on `fd`.
    pub fn clear_cloexec(fd: i32) -> bool {
        sys::clear_cloexec(fd).is_ok()
    }

    /// Whether `fd` is open in the calling process.
    pub fn fd_is_open(fd: i32) -> bool {
        sys::fd_is_open(fd)
    }

    /// Whether signal `sig` is ignored in the calling process.
    pub fn signal_ignored(sig: i32) -> bool {
        sys::signal_ignored(sig)
    }

    /// Whether process `pid` exists and is not a zombie (in a container
    /// whose first process does not reap orphans, killed orphans stay
    /// zombies).
    pub fn alive(pid: u32) -> bool {
        let zombie = std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|s| {
            s.rfind(')')
                .and_then(|i| s[i + 1..].split_whitespace().next())
                == Some("Z")
        });
        !zombie && libc::pid_t::try_from(pid).is_ok_and(sys::alive)
    }

    /// Reaps the caller's child `pid`, blocking; whether it was reaped.
    pub fn reap(pid: u32) -> bool {
        libc::pid_t::try_from(pid).is_ok_and(sys::reap)
    }

    /// Makes `cmd`'s child ignore `signals` before the cage's own steps.
    pub fn ignore_before_spawn(cmd: &mut std::process::Command, signals: &[i32]) {
        sys::ignore_before_spawn(cmd, signals);
    }

    /// Makes `cmd`'s child rename `planned` to `aside` and put `replacement`
    /// in its place (a link to it, or the directory renamed) before the
    /// cage's own steps.
    pub fn plant_before_spawn(
        cmd: &mut std::process::Command,
        planned: &std::path::Path,
        aside: &std::path::Path,
        replacement: &std::path::Path,
        link: bool,
    ) -> std::io::Result<()> {
        sys::plant_before_spawn(cmd, planned, aside, replacement, link)
    }

    /// Spawns `/bin/sleep 30`, in a new session when `setsid`.
    pub fn spawn_sleeper(setsid: bool) -> std::io::Result<u32> {
        sys::spawn_sleeper(setsid)
    }

    /// The soft limits for open files and core size.
    pub fn nofile_and_core() -> Option<(u64, u64)> {
        Some((
            sys::getrlimit(libc::RLIMIT_NOFILE as libc::c_int)?.0,
            sys::getrlimit(libc::RLIMIT_CORE as libc::c_int)?.0,
        ))
    }

    /// The effective, permitted and bounding capability sets.
    pub fn capabilities() -> (u64, u64, u64) {
        sys::capabilities()
    }

    /// The errno of calling `name` with arguments that make it fail without
    /// effect when it is allowed (0 if it succeeded), or `None` for a name
    /// this probe does not know.
    pub fn syscall_errno(name: &str) -> Option<i32> {
        let none = [0; 5];
        let (nr, args) = match name {
            // PTRACE_CONT on ourselves, not traced: ESRCH.
            "ptrace" => (
                libc::SYS_ptrace,
                [7, libc::c_long::from(sys::pid()), 0, 0, 0],
            ),
            // Zero entries and no parameters: EINVAL or EFAULT.
            "io_uring_setup" => (libc::SYS_io_uring_setup, none),
            // An invalid command: EINVAL.
            "bpf" => (libc::SYS_bpf, [-1, 0, 0, 0, 0]),
            // An unknown operation: EOPNOTSUPP.
            "keyctl" => (libc::SYS_keyctl, [9999, 0, 0, 0, 0]),
            // No flags: succeeds.
            "unshare" => (libc::SYS_unshare, none),
            // In a process that leads no group: succeeds (a new session).
            "setsid" => (libc::SYS_setsid, none),
            // In a process that leads no session: succeeds (a new group).
            "setpgid" => (libc::SYS_setpgid, none),
            // A bad descriptor: EBADF.
            "setns" => (libc::SYS_setns, [-1, 0, 0, 0, 0]),
            // No attributes: EFAULT.
            "perf_event_open" => (libc::SYS_perf_event_open, [0, 0, -1, -1, 0]),
            // Invalid flags: EINVAL.
            "userfaultfd" => (libc::SYS_userfaultfd, [-1, 0, 0, 0, 0]),
            // A routing socket needs no privilege: a descriptor.
            "socket_netlink" => (
                libc::SYS_socket,
                [libc::AF_NETLINK.into(), libc::SOCK_RAW.into(), 0, 0, 0],
            ),
            // Without a VM transport: EAFNOSUPPORT.
            "socket_vsock" => (
                libc::SYS_socket,
                [libc::AF_VSOCK.into(), libc::SOCK_STREAM.into(), 0, 0, 0],
            ),
            // A nested user namespace: allowed in a user namespace, EINVAL
            // in a multithreaded process.
            "unshare_user" => (libc::SYS_unshare, [libc::CLONE_NEWUSER.into(), 0, 0, 0, 0]),
            // No arguments: EFAULT or EINVAL; never a process.
            "clone3" => (libc::SYS_clone3, none),
            // No vectors, at the parent: 0 or ESRCH.
            "process_vm_readv" => (
                libc::SYS_process_vm_readv,
                [libc::c_long::from(sys::parent_pid()), 0, 0, 0, 0],
            ),
            // `/` without flags needs no privilege: a descriptor.
            "open_tree" => (
                libc::SYS_open_tree,
                [
                    libc::AT_FDCWD.into(),
                    c"/".as_ptr() as libc::c_long,
                    0,
                    0,
                    0,
                ],
            ),
            _ => return None,
        };
        Some(sys::syscall_errno(nr, args))
    }

    /// The errno of sending `signal` to `pid` (0 if it was sent).
    pub fn kill_errno(pid: u32, signal: i32) -> i32 {
        sys::syscall_errno(
            libc::SYS_kill,
            [libc::c_long::from(pid), libc::c_long::from(signal), 0, 0, 0],
        )
    }

    /// The errno of emptying the file at `path` by `route` (0 if the call
    /// succeeded): `truncate` (by path), `rdonly` and `noaccess` (`openat`
    /// with `O_TRUNC` and the read-only or the empty access mode), `openat2`
    /// (read-only with `O_TRUNC`), or `open` (read-only with `O_TRUNC`,
    /// x86_64 only). `None` for an unknown route.
    pub fn truncate_errno(route: &str, path: &std::path::Path) -> Option<i32> {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
        let p = path.as_ptr() as libc::c_long;
        let at = libc::c_long::from(libc::AT_FDCWD);
        let trunc = libc::c_long::from(libc::O_TRUNC);
        // `struct open_how`: flags, mode, resolve.
        let how: [u64; 3] = [(libc::O_RDONLY | libc::O_TRUNC) as u64, 0, 0];
        let (nr, args) = match route {
            "truncate" => (libc::SYS_truncate, [p, 0, 0, 0, 0]),
            "rdonly" => (libc::SYS_openat, [at, p, trunc, 0, 0]),
            "noaccess" => (libc::SYS_openat, [at, p, 3 | trunc, 0, 0]),
            "openat2" => (
                libc::SYS_openat2,
                [at, p, how.as_ptr() as libc::c_long, 24, 0],
            ),
            #[cfg(target_arch = "x86_64")]
            "open" => (libc::SYS_open, [p, trunc, 0, 0, 0]),
            _ => return None,
        };
        Some(sys::syscall_errno(nr, args))
    }

    /// A new pseudo-terminal: the controller and the path of the device.
    pub fn open_pty() -> std::io::Result<(std::os::fd::OwnedFd, std::path::PathBuf)> {
        sys::open_pty()
    }

    /// Makes the terminal `fd` the caller's controlling terminal
    /// (`TIOCSCTTY`); the errno, or 0.
    pub fn make_controlling(fd: i32) -> i32 {
        sys::tty_ioctl_errno(fd, None)
    }

    /// Pushes `byte` into the input of terminal `fd` (`TIOCSTI`); the
    /// errno, or 0.
    pub fn tiocsti_errno(fd: i32, byte: u8) -> i32 {
        sys::tty_ioctl_errno(fd, Some(byte))
    }

    /// One direct route to `127.0.0.1:port`: `fastopen`, `mptcp`, `raw` or
    /// `tcp6` (`::1`); the errno, or 0 when it got through.
    pub fn net_errno(kind: &str, port: u16) -> i32 {
        sys::net_errno(kind, port)
    }

    /// Sends one byte on the UDP socket `fd` to `127.0.0.1:port`; the
    /// errno, or 0.
    pub fn udp_send_errno(fd: i32, port: u16) -> i32 {
        sys::udp_send_errno(fd, port)
    }

    /// Calls `umount2(path, 0)` and returns the errno (0 on success).
    pub fn umount(path: &str) -> i32 {
        let Ok(c) = std::ffi::CString::new(path) else {
            return libc::EINVAL;
        };
        sys::syscall_errno(libc::SYS_umount2, [c.as_ptr() as libc::c_long, 0, 0, 0, 0])
    }

    /// Calls `mount(NULL, path, NULL, MS_REMOUNT|MS_BIND, NULL)` (a remount
    /// that drops read-only) and returns the errno (0 on success).
    pub fn remount_rw(path: &str) -> i32 {
        let Ok(c) = std::ffi::CString::new(path) else {
            return libc::EINVAL;
        };
        sys::syscall_errno(
            libc::SYS_mount,
            [
                0,
                c.as_ptr() as libc::c_long,
                0,
                (libc::MS_REMOUNT | libc::MS_BIND) as libc::c_long,
                0,
            ],
        )
    }

    /// Installs, on the calling thread, a filter with a listener that
    /// notifies `kcmp` (which nothing here calls), as an outer sandbox using
    /// notification would; children spawned from this thread inherit it.
    /// Returns the listener, which must stay open.
    pub fn install_outer_listener() -> std::io::Result<std::os::fd::OwnedFd> {
        use procage_policy::linux::{Action, Condition, SeccompRule, Syscall};
        let rule = SeccompRule {
            syscall: Syscall::Kcmp,
            condition: Condition::Always,
            action: Action::Eperm,
            reason: None,
        };
        let filter = super::seccomp::build(&[rule], &super::seccomp::NATIVE, true)
            .map_err(std::io::Error::other)?;
        sys::install_outer_listener(filter).map_err(std::io::Error::from_raw_os_error)
    }
}

/// Whether the child shares the caller's network namespace, so the caller's
/// abstract sockets are reachable.
fn abstract_visible(plan: &LinuxPlan) -> bool {
    plan.namespaces.is_none_or(|ns| !ns.net)
}

/// What lifts a socket class's gap: tier T2 cannot keep out one socket, tier
/// T1 covers it (the lowering does not see these gaps, which come from the
/// host at spawn). No Landlock ABI lifts it: Unix-socket rules allow, they
/// cannot deny one socket inside an allowed tree.
fn socket_lift(gap: &procage_policy::CapabilityGap) -> Option<procage_policy::Lift> {
    let socket = matches!(
        gap.construct,
        Construct::HdServiceHandoff | Construct::HdContainerEngines
    );
    let t2 = matches!(gap.target, Target::Linux { tier: Tier::T2, .. });
    (socket && t2 && !gap.subject.as_deref().unwrap_or("").starts_with('@')).then_some(
        procage_policy::Lift {
            tier1: true,
            landlock_abi: None,
        },
    )
}

/// What the receipts of a cage made for `policy` start from.
fn facts(
    policy: &Policy,
    options: &CageOptions,
    plan: &LinuxPlan,
    relaxed: &[Relaxed],
) -> crate::receipt::CageFacts {
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|k| k.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    crate::receipt::CageFacts::new(
        policy,
        options.policy_in_receipt,
        crate::ReceiptBackend::Linux {
            tier: plan.tier.to_string(),
            landlock_abi: plan.landlock_abi,
            errata: probe().errata,
            kernel,
        },
        crate::receipt::approximations(&plan.degradations),
        relaxed,
    )
}

/// The audits of a cage for `policy`: the link check's targets, with the
/// class paths in force in every home, and the handoff audit's trees.
fn cage_audit(
    policy: &Policy,
    options: &CageOptions,
    plan: &LinuxPlan,
    homes: &[PathBuf],
) -> Result<crate::audit::CageAudit, SpawnError> {
    use std::os::unix::ffi::OsStrExt;
    let to_path =
        |p: &procage_policy::AbsPath| PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes()));
    let mut class_paths = Vec::new();
    for class in &plan.classes {
        let rels: Vec<&str> = class.home.iter().map(String::as_str).collect();
        let system: Vec<PathBuf> = class.system.iter().map(to_path).collect();
        class_paths.extend(crate::audit::class_paths(homes, &rels, &system, class.hide));
    }
    let exempt = crate::audit::exemptions(&options.link_exempt, |p| std::fs::canonicalize(p).ok())
        .map_err(|setting| SpawnError::Unsupported(Unsupported::Setting { setting }))?;
    let targets = crate::audit::Targets::new(policy, class_paths, sys::ids().0).exempting(exempt);
    let handoff = options.handoff_audit.then(|| {
        let trees = policy
            .fs
            .iter()
            .filter(|r| r.access == procage_policy::Access::Write)
            .filter_map(|r| match &r.target {
                procage_policy::FsTarget::Subpath(p) => Some(to_path(p)),
                _ => None,
            })
            .collect();
        let home = homes
            .iter()
            .flat_map(|h| {
                procage_policy::presets::HANDOFF_HOME
                    .iter()
                    .map(move |r| h.join(r))
            })
            .collect();
        (
            trees,
            procage_policy::presets::HANDOFF_ANYWHERE
                .iter()
                .map(|n| n.to_string())
                .collect(),
            home,
        )
    });
    Ok(crate::audit::CageAudit::new(
        options.link_audit,
        targets,
        handoff,
        options.walk_limit,
    ))
}
