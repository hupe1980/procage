//! # procage
//!
//! Process sandboxing for Rust, in development. procage is designed to run a
//! child process in a cage on macOS (Seatbelt, applied through libsandbox
//! rather than the deprecated `/usr/bin/sandbox-exec`) and on Linux (Landlock,
//! seccomp and namespaces), without helper binaries.
//!
//! **Status.** The published 0.0.1 only reserves the name. This development
//! version (0.0.2, unreleased) can spawn a caged child on macOS. The
//! [`macos`] module documentation lists what its tests observe on a real
//! kernel and what is not done yet:
//!
//! - a double-forked descendant can outlive a run on macOS;
//! - there are no pseudo-terminals, and the base profile is curated for
//!   macOS 26.6.2;
//! - there is no Linux support.
//!
//! Do not rely on any release before 0.1.0 to contain a process.
//!
//! Policies are written with [`policy`] (the `procage-policy` crate): a
//! portable intent layer, lowered for each backend.
//!
//! ```no_run
//! # #[cfg(target_os = "macos")]
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use procage::macos::{Cage, Grants};
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
//! # #[cfg(not(target_os = "macos"))]
//! # fn main() {}
//! ```
//!
//! Read the [threat model](threat_model) for the adversary, the scope, the
//! limits of an OS sandbox and the status of every known escape class.

pub use procage_policy as policy;

pub mod hygiene;

#[cfg(target_os = "macos")]
pub mod macos;
pub mod threat_model;
