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
//! `tests/spawn_macos.rs` and `tests/escape_macos.rs` check this on a real
//! kernel; the [threat model](crate::threat_model) lists every escape class
//! and its evidence.
//!
//! **Limits:**
//!
//! - there are no pseudo-terminals (`Tty::NewPty`);
//! - the base profiles are curated for macOS 26.6.2;
//!   [`Base::V1`](procage_policy::Base::V1) does not run Xcode's tool shims
//!   (`/usr/bin/git`, `/usr/bin/python3`): use
//!   [`Base::V3`](procage_policy::Base::V3), see `procage_policy::base`;
//! - procage installs no helper program of its own (so R-26 does not apply);
//! - the `KERN_PROCARGS2` query gives a caged child the arguments and
//!   environment of any process of the same user: the sandbox does not
//!   mediate it, even under `(deny sysctl-read)` (macOS 26.6.2).
//!
//! With `Tty::Inherit` the child runs in its own process group, so its reads
//! from the shared terminal stop with SIGTTIN, like a background job.

mod canon;
mod child;
mod lifetime;
mod probe;
mod spawn;
mod sys;
mod violations;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};

use procage_policy::lower::GrantSlot;
use procage_policy::{
    LowerError, LowerOptions, Plan, Policy, Relax, Relaxed, SeatbeltPlan, Target, Tty, lift, lower,
};

pub use crate::unix::TMPDIR_GRANT;
pub use crate::violation::{Coverage, DeniedBy, Violation, Violations};
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
    /// A policy setting this backend cannot apply.
    Setting {
        /// The setting.
        setting: &'static str,
    },
    /// The query that finds a run's processes by their sandbox failed its
    /// probe on this release.
    RunMarker {
        /// `kern.osversion`.
        os_build: String,
        /// What the probe observed.
        detail: String,
    },
    /// `EnvPolicy::Passthrough` cannot be used: this standard library does
    /// not show whether `Command::env_clear` was called, so procage cannot
    /// tell whether the caller's environment may be passed.
    EnvClear,
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
            Unsupported::EnvClear => write!(
                f,
                "EnvPolicy::Passthrough needs to see whether Command::env_clear was called, \
                 which this Rust standard library does not show; use EnvPolicy::Allowlist"
            ),
            Unsupported::RunMarker { os_build, detail } => {
                write!(
                    f,
                    "the run-marker query failed its probe on macOS build {os_build}: {detail}"
                )
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
            GrantError::Issue { name, path } => {
                write!(f, "grant {name}: no extension token issued for {path}")
            }
        }
    }
}

/// Why no caged child runs.
#[derive(Debug)]
#[non_exhaustive]
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
    /// A protected, hidden or class file has another name (a hard link),
    /// which path rules do not cover; see [`LinkAudit`](crate::LinkAudit).
    HardLinks(Vec<crate::LinkFinding>),
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
            SpawnError::HardLinks(found) => f.write_str(&crate::audit::refusal(found)),
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
    /// Whether spawns report the operations the sandbox denies (see
    /// [`CageOptions::with_violations`]).
    pub violations: bool,
    /// Whether receipts hold the policy (see
    /// [`CageOptions::with_policy_in_receipt`]).
    pub policy_in_receipt: bool,
    /// What the link check does before each spawn (default: refuse).
    pub link_audit: crate::LinkAudit,
    /// Whether runs note what they leave behind (see
    /// [`CageOptions::with_handoff_audit`]).
    pub handoff_audit: bool,
    /// The most entries one audit walk visits (default 200,000).
    pub walk_limit: usize,
}

impl Default for CageOptions {
    fn default() -> Self {
        Self {
            lower: LowerOptions::default(),
            compile_limit: 2000,
            violations: false,
            policy_in_receipt: false,
            link_audit: crate::LinkAudit::Refuse,
            handoff_audit: false,
            walk_limit: 200_000,
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

    /// These options with the link check in `mode` (see [`crate::audit`]).
    pub fn with_link_audit(mut self, mode: crate::LinkAudit) -> Self {
        self.link_audit = mode;
        self
    }

    /// These options with the handoff audit: each run notes the trust-handoff
    /// files, symbolic links and repositories of the writable trees, and
    /// [`Child::audit`] lists what it created or changed (see [`crate::audit`]).
    pub fn with_handoff_audit(mut self) -> Self {
        self.handoff_audit = true;
        self
    }

    /// These options with audit walks of at most `limit` entries.
    pub fn with_walk_limit(mut self, limit: usize) -> Self {
        self.walk_limit = limit;
        self
    }

    /// These options with receipts that hold the policy itself and the
    /// subjects (often paths) of `fit`'s relaxations. Without it a receipt
    /// names the policy by digest only.
    pub fn with_policy_in_receipt(mut self) -> Self {
        self.policy_in_receipt = true;
        self
    }

    /// These options with violation reporting: every spawn's
    /// [`Child::violations`] lists the operations the sandbox denied it, with
    /// the kind of rule that denied each (see [`crate::violation`]).
    ///
    /// The first such spawn in a process starts one helper, `/usr/bin/log
    /// stream`, which ends with the process. Reporting needs an administrator
    /// account; where it cannot start, spawning still works and the record
    /// says why. Without this option nothing changes: no helper, and the
    /// same profile.
    pub fn with_violations(mut self) -> Self {
        self.violations = true;
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

/// The bytecode for `plan` with the run-marker parameters `marker`, from the
/// cache or compiled; `true` when it was compiled.
fn compiled(
    lib: &sys::Libsandbox,
    plan: &SeatbeltPlan,
    marker: &[(String, String)],
) -> Result<(Arc<[u8]>, bool), SpawnError> {
    let mut params = plan.params.clone();
    params.extend_from_slice(marker);
    let key = (plan.profile.clone(), params);
    let cached = cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&key)
        .cloned();
    if let Some(bytecode) = cached {
        return Ok((bytecode, false));
    }
    let bytecode: Arc<[u8]> = lib
        .compile(&plan.profile, &key.1)
        .map_err(|message| SpawnError::Compile {
            message: message.unwrap_or_else(|| "<no error text>".into()),
        })?
        .into();
    cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, bytecode.clone());
    Ok((bytecode, true))
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
    violations: bool,
    /// What every run's receipt starts from.
    facts: Arc<crate::receipt::CageFacts>,
    /// The audits every spawn runs.
    audit: Arc<crate::audit::CageAudit>,
}

impl Cage {
    /// Prepares `policy` with default options.
    pub fn new(policy: &Policy) -> Result<Cage, SpawnError> {
        Cage::with_options(policy, &CageOptions::default())
    }

    /// Prepares `policy`, giving up exactly the constructs this host cannot
    /// enforce and `relax` accepts. Returns the cage and what was relaxed,
    /// each with what would lift it (unknown on macOS, where gaps are rare).
    /// Any other gap fails as [`Cage::with_options`] does, with every
    /// remaining gap, and nothing is relaxed that `relax` does not name.
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
            relaxed.extend(done.into_iter().map(|(gap, relaxation)| Relaxed {
                lift: lift(policy, &gap, &options.lower, 0),
                gap,
                relaxation,
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
        let violations = options.violations || options.lower.violations;
        let mut lower_options = options.lower.clone();
        if violations {
            lower_options = lower_options.with_violations();
        }
        let Plan::Seatbelt(plan) = lower(&resolved, Target::MacOs, &lower_options)? else {
            unreachable!("lowering for macOS yields a Seatbelt plan");
        };
        if plan.rule_count > options.compile_limit {
            return Err(SpawnError::LimitExceeded {
                limit: options.compile_limit,
                rules: plan.rule_count,
            });
        }
        // A forking or reporting policy is compiled for the first run-marker
        // slot, the one sequential runs use.
        let marker = if plan.run_marker || violations {
            lifetime::first_params().to_vec()
        } else {
            Vec::new()
        };
        let (bytecode, compiled) = compiled(lib, &plan, &marker)?;
        let facts = Arc::new(facts(policy, options, &plan, &[]));
        let audit = Arc::new(cage_audit(&resolved, options));
        Ok(Cage {
            plan,
            bytecode,
            rewrites,
            compiled,
            violations,
            facts,
            audit,
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
        let session = if self.plan.hygiene.tty == Tty::Inherit {
            sys::Session::Group
        } else {
            sys::Session::New
        };
        let prepared = self.prepare(command, grants, fds, session)?;
        // The link check is the last step before the fork.
        let run_audit = self.audit.before_spawn().map_err(SpawnError::HardLinks)?;
        // The record is registered before the fork, so no early denial is
        // missed.
        let report = match &prepared.run {
            Some(run) if self.violations => Some(violations::register(run.marker())),
            _ => None,
        };
        // A failed spawn leaves no process behind, but the slot is retired
        // (dropped) rather than freed, to stay on the safe side.
        let inner = match command.spawn() {
            Ok(inner) => inner,
            Err(e) => {
                if let Some(run) = &prepared.run {
                    violations::unregister(run.marker());
                }
                return Err(spawn::decode(e));
            }
        };
        let tmpdir = prepared.tmpdir.disarm();
        let mut names: Vec<String> = grants.bindings.iter().map(|(n, _)| n.clone()).collect();
        if tmpdir.is_some() {
            names.push(TMPDIR_GRANT.into());
        }
        Ok(Child::new(
            inner,
            prepared.dropped,
            tmpdir,
            prepared.run,
            child::Reporting {
                forking: self.plan.run_marker,
                record: report,
            },
            crate::receipt::RunFacts::new(self.facts.clone(), names),
            run_audit,
        ))
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
    /// - descendants that stay in the process group die with that kill.
    ///   A descendant that starts its own session (which the macOS sandbox
    ///   cannot prevent) is not reached: when that matters, use
    ///   [`Cage::spawn`], whose handle finds such descendants.
    ///
    /// Everything that can be checked is checked before the process changes,
    /// and a failure leaves it as it was: a caller that is already
    /// sandboxed, the probe, grant bindings, the `tmpdir` grant (refused:
    /// nothing would remove the directory), the environment (see
    /// [`Cage::spawn`]) and a program that cannot be found. A failure after
    /// that ([`SpawnError::Apply`], or [`SpawnError::Io`] from `execvp`)
    /// leaves the process partly confined: the caller should exit.
    ///
    /// ```no_run
    /// # fn main() {
    /// use std::process::Command;
    /// use procage::native::{Cage, Grants};
    /// use procage::policy::{Base, Policy};
    ///
    /// let mut policy = Policy::default();
    /// policy.base = Base::V1;
    /// let cage = Cage::new(&policy).unwrap_or_else(|e| panic!("{e}"));
    /// let err = cage.exec(&mut Command::new("/bin/date"), &Grants::new());
    /// eprintln!("helper: {err}");
    /// std::process::exit(126);
    /// # }
    /// ```
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
        use std::os::unix::process::CommandExt;
        if self.grant_slot(TMPDIR_GRANT).is_some() {
            return SpawnError::Grant(GrantError::TmpdirWithExec);
        }
        match self.prepare(command, grants, fds, sys::Session::Keep) {
            // On success `exec` does not return; the run marker (forking
            // policies) is never searched: there is no handle.
            Ok(_prepared) => match self.audit.before_spawn() {
                Ok(_) => spawn::decode(command.exec()),
                Err(found) => SpawnError::HardLinks(found),
            },
            Err(e) => e,
        }
    }

    /// Everything before the fork (or the exec), without changing the
    /// calling process: checks, grant tokens, the environment, the run
    /// marker and the child sequence installed on `command`.
    fn prepare(
        &self,
        command: &mut Command,
        grants: &Grants,
        fds: &[BorrowedFd<'_>],
        session: sys::Session,
    ) -> Result<Prepared, SpawnError> {
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
        let dropped = crate::unix::environment(command, &self.plan.hygiene.env)
            .map_err(|_| SpawnError::Unsupported(Unsupported::EnvClear))?;
        if session == sys::Session::Keep {
            crate::unix::find_program(command).map_err(SpawnError::Io)?;
        }
        let (run, bytecode) = self.run_and_bytecode(lib)?;
        sys::ChildPlan {
            ops: lib.child_ops(),
            bytecode,
            tokens,
            limits: crate::unix::limits(&self.plan.hygiene.limits),
            session,
            keep,
            fd_buffer: sys::fd_buffer(),
        }
        .install(command);
        Ok(Prepared {
            dropped,
            tmpdir: removal,
            run,
        })
    }

    /// The run marker for a spawn of a forking policy, and the bytecode bound
    /// to it (compiled before the fork when the slot is not the first).
    fn run_and_bytecode(
        &self,
        lib: &sys::Libsandbox,
    ) -> Result<(Option<lifetime::Run>, Arc<[u8]>), SpawnError> {
        if !self.plan.run_marker && !self.violations {
            return Ok((None, self.bytecode.clone()));
        }
        if self.plan.run_marker {
            lifetime::probe(lib)?;
        }
        let run = lifetime::Run::take();
        if run.is_first() {
            return Ok((Some(run), self.bytecode.clone()));
        }
        match compiled(lib, &self.plan, &run.params()) {
            Ok((bytecode, _)) => Ok((Some(run), bytecode)),
            Err(e) => {
                run.free();
                Err(e)
            }
        }
    }
}

/// What [`Cage::prepare`] made for one spawn.
struct Prepared {
    dropped: Vec<String>,
    tmpdir: TmpdirGuard,
    run: Option<lifetime::Run>,
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

    /// Ends the violation monitor's helper, as if it had died.
    pub fn stop_violation_monitor() {
        super::violations::stop();
    }

    /// The processes `child`'s run marker finds now (none without a marker).
    pub fn run_members(child: &super::Child) -> std::io::Result<Vec<u32>> {
        let Some(run) = child.run() else {
            return Ok(Vec::new());
        };
        let lib = super::libsandbox().map_err(std::io::Error::other)?;
        let pids = super::lifetime::members(lib, run)?;
        Ok(pids.into_iter().map(i32::cast_unsigned).collect())
    }

    /// The run-marker slot of `child`.
    pub fn run_slot(child: &super::Child) -> Option<u32> {
        child.run().map(super::lifetime::Run::slot)
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

/// What the receipts of a cage made for `policy` start from.
fn facts(
    policy: &Policy,
    options: &CageOptions,
    plan: &SeatbeltPlan,
    relaxed: &[Relaxed],
) -> crate::receipt::CageFacts {
    crate::receipt::CageFacts::new(
        policy,
        options.policy_in_receipt,
        crate::ReceiptBackend::MacOs {
            apply: "path-a".into(),
            os_release: sys::os_release(),
            os_build: sys::os_build(),
        },
        crate::receipt::approximations(&plan.degradations),
        relaxed,
    )
}

/// The audits of a cage for `policy` (resolved): the link check's targets,
/// with the class paths of every home under `/Users`, and the handoff
/// audit's trees.
fn cage_audit(policy: &Policy, options: &CageOptions) -> crate::audit::CageAudit {
    use procage_policy::{HardDenyClass, presets};
    use std::os::unix::ffi::OsStrExt;
    let homes: Vec<PathBuf> = std::fs::read_dir("/Users")
        .map(|e| {
            e.flatten()
                .filter(|e| e.file_type().is_ok_and(|t| t.is_dir()))
                .map(|e| e.path())
                .collect()
        })
        .unwrap_or_default();
    let mut class_paths = Vec::new();
    if !policy.waive.contains(&HardDenyClass::Secrets) {
        class_paths.extend(crate::audit::class_paths(
            &homes,
            presets::SECRETS_HOME,
            &[],
            true,
        ));
    }
    if !policy.waive.contains(&HardDenyClass::TrustHandoff) {
        class_paths.extend(crate::audit::class_paths(
            &homes,
            presets::HANDOFF_HOME,
            &[],
            false,
        ));
    }
    if !policy.waive.contains(&HardDenyClass::Persistence) {
        let system: Vec<PathBuf> = presets::PERSISTENCE_SYSTEM
            .iter()
            .map(PathBuf::from)
            .collect();
        class_paths.extend(crate::audit::class_paths(
            &homes,
            presets::PERSISTENCE_HOME,
            &system,
            false,
        ));
    }
    let targets = crate::audit::Targets::new(policy, class_paths);
    let handoff = options.handoff_audit.then(|| {
        let trees = policy
            .fs
            .iter()
            .filter(|r| r.access == procage_policy::Access::Write)
            .filter_map(|r| match &r.target {
                procage_policy::FsTarget::Subpath(p) => {
                    Some(PathBuf::from(std::ffi::OsStr::from_bytes(p.as_bytes())))
                }
                _ => None,
            })
            .collect();
        let home = homes
            .iter()
            .flat_map(|h| presets::HANDOFF_HOME.iter().map(move |r| h.join(r)))
            .collect();
        (
            trees,
            presets::HANDOFF_ANYWHERE
                .iter()
                .map(|n| n.to_string())
                .collect(),
            home,
        )
    });
    crate::audit::CageAudit::new(options.link_audit, targets, handoff, options.walk_limit)
}
