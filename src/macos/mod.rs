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
//! - 100 children spawned while other threads load libraries are all caged.
//!
//! **Not yet done** (later features):
//!
//! - inherited file descriptors are not closed, and an inherited descriptor
//!   bypasses path rules;
//! - descendants are not killed when the run ends;
//! - there is no curated base profile: the policy must grant what the
//!   program needs to start;
//! - there is no helper process (path B).

mod canon;
mod probe;
mod spawn;
mod sys;

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex, OnceLock};

use procage_policy::lower::GrantSlot;
use procage_policy::{LowerError, LowerOptions, Plan, Policy, SeatbeltPlan, Target, Tty, lower};

pub use probe::{ApplyMethod, probe};

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
}

impl Step {
    fn from_code(code: u32) -> Option<Step> {
        Some(match code {
            sys::steps::SESSION => Step::Session,
            sys::steps::RLIMIT => Step::Rlimit,
            sys::steps::APPLY => Step::Apply,
            sys::steps::VERIFY => Step::Verify,
            sys::steps::CONSUME => Step::Consume,
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
            SpawnError::Path { error, .. } | SpawnError::Io(error) => Some(error),
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
    /// apply method failed its probe, or when a grant binding is wrong.
    pub fn spawn(&self, command: &mut Command, grants: &Grants) -> Result<Child, SpawnError> {
        let lib = libsandbox()?;
        if lib.is_sandboxed() {
            return Err(SpawnError::AlreadySandboxed);
        }
        probe()?;
        let tokens = spawn::tokens(lib, self, grants)?;
        spawn::environment(command, &self.plan.hygiene.env);
        sys::ChildPlan {
            ops: lib.child_ops(),
            bytecode: self.bytecode.clone(),
            tokens,
            limits: spawn::limits(&self.plan.hygiene.limits),
            new_session: self.plan.hygiene.tty != Tty::Inherit,
        }
        .install(command);
        command.spawn().map_err(spawn::decode)
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

    /// Contends for dyld's locks until `stop` is set.
    pub fn dyld_churn(stop: &std::sync::atomic::AtomicBool) {
        sys::dyld_churn(stop);
    }

    /// The soft limits for open files and core size.
    pub fn nofile_and_core() -> Option<(u64, u64)> {
        Some((
            sys::getrlimit(libc::RLIMIT_NOFILE)?.0,
            sys::getrlimit(libc::RLIMIT_CORE)?.0,
        ))
    }
}
