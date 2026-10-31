//! # procage-policy
//!
//! The portable half of procage: a sandbox policy written once, and its
//! lowering to a plan for each backend. It is `no_std` with `alloc` and free
//! of `unsafe`, so policies can be built, checked and fuzzed on any target.
//!
//! - **Intent layer**: [`Policy`] states what a child may do: file access by
//!   [`AbsPath`] or [`Glob`], network, process creation and signals, IPC,
//!   environment, limits, terminal, per-spawn [`Grant`]s, and waivers of the
//!   hard-deny tier. Its default effect is deny.
//! - **Backend layers**: [`seatbelt::Layer`] and [`linux::Layer`] add typed
//!   raw rules for one backend.
//! - **Lowering**: [`lower()`] produces a [`SeatbeltPlan`] or a
//!   [`LinuxPlan`], or the complete list of [`CapabilityGap`]s. The
//!   [lowering table](mod@lower#lowering-table) states, for every construct and
//!   target, whether it is expressed exactly, approximated (only with
//!   permission, then recorded) or not at all.
//!
//! This crate applies nothing to any process. A plan is data for procage's
//! spawn backends, and says nothing about enforcement by itself: what a
//! kernel enforces is established by procage's tests that cage a real child.
//!
//! ```
//! use procage_policy::{
//!     AbsPath, Access, FsRule, FsTarget, LowerOptions, Plan, Policy, Target, Tier, lower,
//! };
//!
//! let mut policy = Policy::default();
//! policy.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(AbsPath::new("/work")?)));
//! policy.fs.push(FsRule::new(Access::Protect, FsTarget::Subpath(AbsPath::new("/work/.git")?)));
//!
//! let options = LowerOptions::default();
//! let Plan::Seatbelt(plan) = lower(&policy, Target::MacOs, &options)? else { unreachable!() };
//! assert!(plan.profile.contains("(deny file-write* (subpath \"/work/.git\"))"));
//!
//! // Landlock alone cannot protect a subtree inside a writable one.
//! let t2 = Target::Linux { tier: Tier::T2, landlock_abi: 6 };
//! assert!(lower(&policy, t2, &options).is_err());
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

#![no_std]

extern crate alloc;

pub mod base;
#[cfg(feature = "serde")]
mod format;
pub mod glob;
pub mod linux;
pub mod lower;
pub mod name;
pub mod path;
pub mod policy;
pub mod presets;
pub mod sbpl;
pub mod seatbelt;

pub use glob::{Glob, GlobError};
pub use linux::LinuxPlan;
pub use lower::{
    CapabilityGap, Construct, Degradation, GapKind, LowerError, LowerOptions, Outcome, Plan,
    RUN_MARKER_PARAM, RUN_PREFIX_PARAM, SeatbeltPlan, Target, TargetError, Tier, lower,
};
pub use name::{GrantName, NameError, Port, Tag};
pub use path::{AbsPath, PathError};
pub use policy::{
    Access, Base, EnvPolicy, Exec, FsRule, FsTarget, Grant, HardDenyClass, Ipc, Lifetime, Network,
    Policy, PolicyError, Ports, PresetTag, Process, Rlimits, Signals, Tty,
};
pub use sbpl::EscapeError;
