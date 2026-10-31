//! # procage
//!
//! Process sandboxing for Rust, in development. procage is designed to run a
//! child process in a cage on macOS (Seatbelt, applied through libsandbox
//! rather than the deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock,
//! seccomp and namespaces), without helper binaries.
//!
//! **Status.** The published 0.0.1 only reserves the name. This development
//! version (0.0.2, unreleased) can spawn a caged child on macOS (module
//! `macos`) and on Linux (module `linux`, tiers T1 and T2). Each module's
//! documentation lists what its tests observe on a real kernel and what is
//! not done yet, among them:
//!
//! - on macOS a caged child can read other same-user processes' arguments
//!   and environment (the sandbox does not mediate that query);
//! - there are no pseudo-terminals, and the macOS base profile is curated
//!   for macOS 26.6.2;
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
//! policy.base = Base::V1; // what ordinary programs need to start
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
//! policy.base = Base::V1;
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
/// [`Cage::with_options`](native::Cage::with_options) with
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
