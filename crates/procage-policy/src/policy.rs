//! The intent layer: what a child may do, independent of the backend.
//!
//! A policy states what a child may do; [`crate::lower()`] turns it into a
//! plan, and procage's spawn backends apply the plan. [`Policy::default()`]
//! allows nothing: no file access, no network, no process creation, no
//! signals, no IPC, an empty environment, no terminal. There is no way to
//! express allow-by-default.

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::glob::Glob;
use crate::linux;
use crate::name::{GrantName, Port};
use crate::path::AbsPath;
use crate::seatbelt;

/// The kind of access a file rule or grant gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Access {
    /// Read files and list directories.
    Read,
    /// Read and write (create, modify, delete).
    Write,
    /// Read and execute.
    Exec,
    /// Read-only inside a writable tree: the policy takes write access away
    /// even where another rule gives it.
    Protect,
    /// Neither readable nor writable inside a readable tree: the policy takes
    /// all access away even where another rule gives it.
    Hide,
}

/// What a file rule applies to. The kind is always chosen explicitly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum FsTarget {
    /// Exactly this path.
    Literal(AbsPath),
    /// This path and everything below it.
    Subpath(AbsPath),
    /// Every path the glob matches.
    Glob(Glob),
}

/// One file rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct FsRule {
    /// The access given (or, for protect and hide, taken away).
    pub access: Access,
    /// What it applies to.
    pub target: FsTarget,
}

impl FsRule {
    /// A rule giving `access` to `target`.
    pub fn new(access: Access, target: FsTarget) -> Self {
        Self { access, target }
    }
}

/// A set of ports.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Ports {
    /// Every port.
    Any,
    /// These ports (at least one).
    List(BTreeSet<Port>),
}

/// Network access.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub enum Network {
    /// No network at all.
    #[default]
    None,
    /// Connect to and listen on the loopback interface.
    Loopback(Ports),
    /// Connect to these unix-domain sockets (at least one).
    UnixSockets(Vec<AbsPath>),
    /// Connect only to a proxy listening on loopback.
    Proxy {
        /// HTTP (CONNECT) proxy port.
        http: Option<Port>,
        /// SOCKS5 proxy port.
        socks: Option<Port>,
    },
    /// Unrestricted network.
    All,
}

/// Where the child may execute programs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Exec {
    /// Only where an [`Access::Exec`] rule or grant allows it.
    #[default]
    Granted,
    /// Anywhere the child can read.
    Any,
    /// Nowhere (no `Exec` rule or grant may exist).
    Never,
}

/// Which processes the child may signal.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Signals {
    /// Itself and its descendants.
    SelfAndChildren,
    /// None.
    #[default]
    None,
}

/// Process creation and signals.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields, default)
)]
pub struct Process {
    /// Where programs may be executed.
    pub exec: Exec,
    /// Whether the child may create processes.
    pub fork: bool,
    /// Which processes it may signal.
    pub signals: Signals,
}

/// Inter-process communication.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields, default)
)]
pub struct Ipc {
    /// POSIX shared memory.
    pub posix_shm: bool,
    /// System V IPC (shared memory, semaphores, message queues).
    pub sysv: bool,
}

/// The child's environment. Carried into the plan for the spawn backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case", deny_unknown_fields)
)]
pub enum EnvPolicy {
    /// Only these variables are passed.
    Allowlist(Vec<String>),
    /// Every variable except these is passed.
    Passthrough {
        /// Variables that are never passed.
        deny: Vec<String>,
    },
}

impl Default for EnvPolicy {
    fn default() -> Self {
        EnvPolicy::Allowlist(Vec::new())
    }
}

/// Resource limits. Carried into the plan for the spawn backend.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields, default)
)]
pub struct Rlimits {
    /// Maximum number of processes.
    pub nproc: Option<u64>,
    /// CPU time in seconds.
    pub cpu_seconds: Option<u64>,
    /// Largest file the child may write, in bytes.
    pub fsize_bytes: Option<u64>,
    /// Maximum number of open files.
    pub nofile: Option<u64>,
    /// Core dump size in bytes (0 by default: no core dumps).
    pub core_bytes: u64,
}

/// The child's terminal. Carried into the plan for the spawn backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
pub enum Tty {
    /// No controlling terminal.
    #[default]
    None,
    /// The caller's terminal.
    Inherit,
    /// A new pseudo-terminal.
    NewPty,
}

/// A curated, frozen set of rules that lets ordinary programs start (see
/// [`crate::base`]). A policy has none unless it names a version.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
#[non_exhaustive]
pub enum Base {
    /// No base: only what the policy states.
    #[default]
    None,
    /// Base profile version 1 (measured on macOS 26.6.2). Frozen.
    V1,
}

/// A member of the hard-deny tier, emitted last in every plan.
///
/// A class can be removed only by naming it in [`Policy::waive`], and every
/// waiver is listed in the plan. Later features add data-driven classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(try_from = "String", into = "String")
)]
#[non_exhaustive]
pub enum HardDenyClass {
    /// macOS `fcntl` commands that modify a file through a read-only fd.
    FcntlModify,
    /// setuid/setgid writes and setuid/setgid execution.
    Privilege,
    /// Handing work to unsandboxed services (Launch Services, Apple events,
    /// pasteboard, XPC services).
    ServiceHandoff,
    /// Task ports, process introspection outside the sandbox, ptrace.
    ProcessAccess,
    /// Renaming a writable root or an ancestor of a protected or hidden path.
    RenameAnchors,
    /// Injecting keystrokes into a terminal (TIOCSTI, TIOCLINUX).
    TerminalInjection,
    /// Linux kernel interfaces with a large attack surface (io_uring, bpf,
    /// perf events, userfaultfd, keyrings).
    KernelSurface,
    /// Creating or entering Linux namespaces and changing mounts.
    Namespaces,
    /// Linux socket families that bypass socket and file filters (AF_VSOCK,
    /// AF_NETLINK).
    SocketFamilies,
}

impl HardDenyClass {
    /// Every class of this release, in emission order.
    pub const ALL: &'static [HardDenyClass] = &[
        HardDenyClass::FcntlModify,
        HardDenyClass::Privilege,
        HardDenyClass::ServiceHandoff,
        HardDenyClass::ProcessAccess,
        HardDenyClass::RenameAnchors,
        HardDenyClass::TerminalInjection,
        HardDenyClass::KernelSurface,
        HardDenyClass::Namespaces,
        HardDenyClass::SocketFamilies,
    ];

    /// The kebab-case name.
    pub fn as_str(self) -> &'static str {
        match self {
            HardDenyClass::FcntlModify => "fcntl-modify",
            HardDenyClass::Privilege => "privilege",
            HardDenyClass::ServiceHandoff => "service-handoff",
            HardDenyClass::ProcessAccess => "process-access",
            HardDenyClass::RenameAnchors => "rename-anchors",
            HardDenyClass::TerminalInjection => "terminal-injection",
            HardDenyClass::KernelSurface => "kernel-surface",
            HardDenyClass::Namespaces => "namespaces",
            HardDenyClass::SocketFamilies => "socket-families",
        }
    }
}

/// A name that is not a hard-deny class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownClass(pub String);

impl fmt::Display for UnknownClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown hard-deny class {:?}", self.0)
    }
}

impl core::error::Error for UnknownClass {}

impl FromStr for HardDenyClass {
    type Err = UnknownClass;

    fn from_str(name: &str) -> Result<Self, UnknownClass> {
        HardDenyClass::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == name)
            .ok_or_else(|| UnknownClass(name.into()))
    }
}

impl TryFrom<String> for HardDenyClass {
    type Error = UnknownClass;

    fn try_from(name: String) -> Result<Self, UnknownClass> {
        name.parse()
    }
}

impl From<HardDenyClass> for String {
    fn from(class: HardDenyClass) -> String {
        class.as_str().into()
    }
}

impl fmt::Display for HardDenyClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A named slot for a path that is bound per spawn.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(deny_unknown_fields)
)]
pub struct Grant {
    /// The slot's name.
    pub name: GrantName,
    /// Read, write or exec.
    pub access: Access,
}

/// The portable policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "crate::format::PolicyRepr", into = "crate::format::PolicyRepr")
)]
#[non_exhaustive]
pub struct Policy {
    /// File rules, in any order.
    pub fs: Vec<FsRule>,
    /// Network access.
    pub net: Network,
    /// Process creation and signals.
    pub process: Process,
    /// Inter-process communication.
    pub ipc: Ipc,
    /// The child's environment.
    pub env: EnvPolicy,
    /// Resource limits.
    pub limits: Rlimits,
    /// The child's terminal.
    pub tty: Tty,
    /// The base profile.
    pub base: Base,
    /// Hard-deny classes removed by name.
    pub waive: BTreeSet<HardDenyClass>,
    /// Per-spawn grants.
    pub grants: Vec<Grant>,
    /// Raw Seatbelt rules (macOS only).
    pub seatbelt: Option<seatbelt::Layer>,
    /// Raw Linux additions (Linux only).
    pub linux: Option<linux::Layer>,
}

/// A policy whose parts contradict each other.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PolicyError {
    /// `Exec::Never` together with an `Exec` rule or grant.
    ExecConflict,
    /// `Network::Proxy` with neither port set.
    EmptyProxy,
    /// `Ports::List` with no port.
    EmptyPorts,
    /// `Network::UnixSockets` with no socket.
    EmptyUnixSockets,
    /// A grant whose access is protect or hide.
    GrantAccess {
        /// The grant.
        name: GrantName,
    },
    /// Two grants with the same name.
    DuplicateGrant {
        /// The grant.
        name: GrantName,
    },
    /// A raw Seatbelt rule without operations.
    EmptyOperations {
        /// Index of the rule in the layer.
        index: usize,
    },
    /// A Linux layer path rule whose access is protect or hide.
    LandlockExtraAccess {
        /// The path.
        path: AbsPath,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicyError::ExecConflict => {
                f.write_str("exec is `never` but a rule or grant allows exec")
            }
            PolicyError::EmptyProxy => {
                f.write_str("proxy network names neither an http nor a socks port")
            }
            PolicyError::EmptyPorts => f.write_str("a port list is empty"),
            PolicyError::EmptyUnixSockets => f.write_str("unix-socket network names no socket"),
            PolicyError::GrantAccess { name } => {
                write!(f, "grant {name} must give read, write or exec")
            }
            PolicyError::DuplicateGrant { name } => write!(f, "grant {name} is defined twice"),
            PolicyError::EmptyOperations { index } => {
                write!(f, "raw Seatbelt rule {index} has no operation")
            }
            PolicyError::LandlockExtraAccess { path } => {
                write!(
                    f,
                    "Linux layer rule for {path} must give read, write or exec"
                )
            }
        }
    }
}

impl core::error::Error for PolicyError {}

fn ports_ok(ports: &Ports) -> bool {
    !matches!(ports, Ports::List(list) if list.is_empty())
}

impl Policy {
    /// Checks the rules that span several fields. [`crate::lower()`] calls it
    /// first; it returns every problem, not only the first.
    pub fn validate(&self) -> Result<(), Vec<PolicyError>> {
        let mut errors = Vec::new();
        let grants_exec = self.grants.iter().any(|g| g.access == Access::Exec);
        let rules_exec = self.fs.iter().any(|r| r.access == Access::Exec);
        if self.process.exec == Exec::Never && (grants_exec || rules_exec) {
            errors.push(PolicyError::ExecConflict);
        }
        match &self.net {
            Network::Proxy {
                http: None,
                socks: None,
            } => errors.push(PolicyError::EmptyProxy),
            Network::Loopback(ports) if !ports_ok(ports) => errors.push(PolicyError::EmptyPorts),
            Network::UnixSockets(paths) if paths.is_empty() => {
                errors.push(PolicyError::EmptyUnixSockets)
            }
            _ => {}
        }
        let mut names = BTreeSet::new();
        for grant in &self.grants {
            if matches!(grant.access, Access::Protect | Access::Hide) {
                errors.push(PolicyError::GrantAccess {
                    name: grant.name.clone(),
                });
            }
            if !names.insert(&grant.name) {
                errors.push(PolicyError::DuplicateGrant {
                    name: grant.name.clone(),
                });
            }
        }
        if let Some(layer) = &self.seatbelt {
            for (index, rule) in layer.rules.iter().enumerate() {
                if rule.ops.is_empty() {
                    errors.push(PolicyError::EmptyOperations { index });
                }
                for filter in &rule.filters {
                    if let seatbelt::Filter::RemoteLoopback(p) | seatbelt::Filter::LocalLoopback(p) =
                        filter
                        && !ports_ok(p)
                    {
                        errors.push(PolicyError::EmptyPorts);
                    }
                }
            }
        }
        if let Some(layer) = &self.linux {
            for (path, access) in &layer.landlock_extra {
                if matches!(access, Access::Protect | Access::Hide) {
                    errors.push(PolicyError::LandlockExtraAccess { path: path.clone() });
                }
            }
        }
        errors.sort();
        errors.dedup();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn default_denies_everything() {
        let p = Policy::default();
        assert!(p.fs.is_empty() && p.grants.is_empty() && p.waive.is_empty());
        assert_eq!(p.net, Network::None);
        assert_eq!(
            p.process,
            Process {
                exec: Exec::Granted,
                fork: false,
                signals: Signals::None
            }
        );
        assert_eq!(
            p.ipc,
            Ipc {
                posix_shm: false,
                sysv: false
            }
        );
        assert_eq!(p.env, EnvPolicy::Allowlist(vec![]));
        assert_eq!(p.limits.core_bytes, 0);
        assert_eq!(p.tty, Tty::None);
        assert!(p.validate().is_ok());
    }

    #[test]
    fn class_names_round_trip() {
        for class in HardDenyClass::ALL {
            assert_eq!(class.as_str().parse::<HardDenyClass>().unwrap(), *class);
        }
        assert!("no-such-class".parse::<HardDenyClass>().is_err());
    }
}
