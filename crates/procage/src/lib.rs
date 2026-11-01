//! # procage
//!
//! Process sandboxing for Rust, in development. procage runs a child process
//! in a cage on macOS (Seatbelt, applied through libsandbox rather than the
//! deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock, seccomp and
//! namespaces), without helper binaries. It is meant for commands that run
//! untrusted, adaptive code as your user: an LLM agent's tool calls, a
//! project's build scripts.
//!
//! **Status.** The published 0.0.1 only reserves the name. This development
//! version (0.0.2, unreleased) can spawn a caged child on macOS (module
//! `macos`) and on Linux (module `linux`, tiers T1 and T2). Each module's
//! documentation lists what its tests observe on a real kernel and what is
//! not done yet, among them:
//!
//! - on macOS a caged child can read other same-user processes' arguments
//!   and environment (the sandbox does not mediate that query);
//! - there are no pseudo-terminals, and the macOS base profiles were
//!   measured on macOS 26.6.2;
//! - on Linux there is no PID namespace yet, loopback and proxy networks
//!   and glob rules are capability gaps, and the Linux tests have run on
//!   one kernel (7.0, aarch64, in Docker).
//!
//! Do not rely on any release before 0.1.0 to contain a process.
//!
//! Policies are written with [`policy`] (the `procage-policy` crate): a
//! portable intent layer, lowered for each backend.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use procage::native::{Cage, Grants}; // procage::macos or procage::linux
//! use procage::policy::{AbsPath, Access, Base, FsRule, FsTarget, Policy};
//!
//! let mut policy = Policy::default();
//! policy.base = Base::V2; // what ordinary programs and developer tools need
//! policy.fs.push(FsRule::new(Access::Read, FsTarget::Subpath(AbsPath::new("/tmp/project")?)));
//!
//! let cage = Cage::new(&policy)?;
//! let status = cage
//!     .spawn(&mut std::process::Command::new("/bin/ls"), &Grants::new())?
//!     .wait()?;
//! # let _ = status;
//! # Ok(())
//! # }
//! ```
//!
//! # Lifetime and hygiene
//!
//! The run ends when the [`Child`](native::Child) handle is dropped or
//! `kill_all` is called: every process the run started is killed,
//! double-forked descendants included. The child receives only standard
//! input, output and error (hand others over with `spawn_with_fds`); its
//! environment follows the policy's [`EnvPolicy`](policy::EnvPolicy) (see
//! [`hygiene`]); declaring the `tmpdir` grant gives each run a private
//! `TMPDIR`.
//!
//! # Helpers: becoming the caged command
//!
//! Sometimes other code starts the process: an MCP client, a terminal,
//! `tokio::process::Command` with `kill_on_drop`. It holds the pid, the
//! pipes and the exit status, and it kills the process when it is done.
//! Give that code a small helper program instead of the command. The helper
//! builds the cage and calls `Cage::exec`, which confines the helper itself
//! and executes the command in its place:
//!
//! ```no_run
//! # fn main() {
//! use std::process::Command;
//! use procage::native::{Cage, Grants};
//! use procage::policy::{Base, Policy};
//!
//! let mut policy = Policy::default();
//! policy.base = Base::V2;
//! let cage = Cage::new(&policy).unwrap_or_else(|e| panic!("{e}"));
//! let mut command = Command::new("/usr/bin/env");
//! command.current_dir("/tmp"); // a directory the policy lets it read
//! let err = cage.exec(&mut command, &Grants::new()); // returns only on failure
//! eprintln!("helper: {err}");
//! std::process::exit(126);
//! # }
//! ```
//!
//! On the other side, start the helper in its own process group and end it
//! by killing the group:
//!
//! ```no_run
//! # fn main() -> std::io::Result<()> {
//! use std::os::unix::process::CommandExt;
//!
//! let helper = std::process::Command::new("my-helper")
//!     .arg("--")
//!     .arg("server")
//!     .process_group(0)
//!     .spawn()?;
//! // … later: kill -9 -<pid> ends the command and the descendants in its group.
//! # let _ = helper;
//! # Ok(())
//! # }
//! ```
//!
//! The helper must be single-threaded on Linux tier T1 (call `exec` early
//! in `main`). On Linux, descendants cannot leave the process group under
//! the default [`Lifetime::Run`](policy::Lifetime::Run), and the command
//! dies with the helper's parent. On macOS a descendant that starts its own
//! session is not reached by the group kill; use `Cage::spawn`, whose handle
//! finds it, when that matters. The `examples/exec_helper.rs` program in the
//! repository is a complete helper.
//!
//! # Fitting a policy to the host
//!
//! A host that cannot enforce part of a policy refuses the cage and lists
//! each part as a capability gap: procage never runs a child under a weaker
//! policy on its own. A harness that would rather run with a known, stated
//! limit than not at all names the relaxations it accepts and calls
//! `Cage::fit`. It gets the cage and the list of what was relaxed, each with
//! what would lift it, to show its user:
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use procage::native::{Cage, CageOptions};
//! use procage::policy::{AbsPath, Access, FsRule, FsTarget, HardDenyClass, Policy, Relax};
//!
//! let mut policy = Policy::default();
//! policy.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(AbsPath::new("/w")?)));
//! policy.fs.push(FsRule::new(Access::Protect, FsTarget::Subpath(AbsPath::new("/w/.git")?)));
//!
//! let relax = Relax::new()
//!     .leave_out_protect() // e.g. `.git` inside a writable workspace
//!     .waive(HardDenyClass::TrustHandoff)
//!     .signals_same_user(); // Linux older than 6.12
//! let (cage, relaxed) = Cage::fit(&policy, &CageOptions::default(), &relax)?;
//! for r in &relaxed {
//!     eprintln!("sandbox: {r}");
//!     // fs-protect /w/.git on Linux T2 (Landlock ABI 8): the protect rule is
//!     // left out; tier T1 (user namespaces) would enforce it
//! }
//! # let _ = cage;
//! # Ok(())
//! # }
//! ```
//!
//! Each relaxation has one effect: leave out the protect or hide rule a gap
//! names, waive a hard-deny class, allow no Unix sockets or no network
//! (stricter), or let signals reach every process of the user. Any gap
//! without an accepted relaxation still fails, with every remaining gap.
//! Approximations are a different consent and stay in
//! [`LowerOptions::allow_degrade`](policy::LowerOptions::allow_degrade).
//!
//! # Violations: what the sandbox denied, and why
//!
//! A denied operation reaches the caged program as `EPERM`, which it may
//! print, swallow or misreport. A cage built with
//! `CageOptions::with_violations` also tells the harness: after the child
//! exits, `Child::violations` lists each denied operation with the process,
//! the target and the kind of rule that denied it, so the harness can
//! explain the failure or ask its user for a grant.
//!
//! ```no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use std::process::Command;
//! use procage::native::{Cage, CageOptions, Grants};
//! # let policy = procage::policy::Policy::default();
//!
//! let cage = Cage::with_options(&policy, &CageOptions::default().with_violations())?;
//! let mut child = cage.spawn(&mut Command::new("/usr/bin/make"), &Grants::new())?;
//! child.wait()?;
//! for v in &child.violations() {
//!     eprintln!("sandbox: {v}");
//!     // make (pid 812) was denied file-write-create /Users/a/out.o: not granted by the policy
//! }
//! # Ok(())
//! # }
//! ```
//!
//! On macOS the kernel logs every Seatbelt denial; the cage's profile tags
//! each with the run and the rule kind, and one helper per process
//! (`/usr/bin/log stream`, which needs an administrator account) collects
//! them. A record says whether it is complete and what it can show
//! ([`Coverage`]); identical denials by one process are reported once.
//! Linux does not report denials yet: Landlock reports them only to the
//! privileged audit subsystem. Reporting is diagnostic and best-effort.
//! Enforcement never depends on it.
//!
//! Read the [threat model](threat_model) for the adversary, the scope, the
//! limits of an OS sandbox and the status of every known escape class.

pub use procage_policy as policy;

pub mod hygiene;

#[cfg(target_os = "linux")]
pub mod linux;

#[cfg(target_os = "macos")]
pub mod macos;
pub mod threat_model;

/// The backend of the system procage is built for: `procage::macos` on macOS,
/// `procage::linux` on Linux.
///
/// Code that uses only the subset both backends share builds on both
/// without `cfg`: [`Cage::new`](native::Cage::new),
/// [`Cage::with_options`](native::Cage::with_options) and
/// [`Cage::fit`](native::Cage::fit) with
/// [`CageOptions::default`](native::CageOptions)`().with_lower(…)`,
/// [`Cage::spawn`](native::Cage::spawn),
/// [`Cage::spawn_with_fds`](native::Cage::spawn_with_fds),
/// [`Grants::new`](native::Grants::new)`().bind(…)`, and the
/// [`Child`](native::Child) methods `kill_all`, `detach`, `dropped_env` and
/// `tmpdir`. Errors are each backend's own [`SpawnError`](native::SpawnError),
/// with a `Display` message.
#[cfg(target_os = "macos")]
pub use macos as native;

/// The backend of the system procage is built for: `procage::macos` on macOS,
/// `procage::linux` on Linux.
#[cfg(target_os = "linux")]
pub use linux as native;
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod unix;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod violation;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub use violation::{Coverage, DeniedBy, Violation, Violations};
