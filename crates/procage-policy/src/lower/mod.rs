#![doc = include_str!("../lowering.md")]

mod fit;
mod linux;
pub(crate) mod macos;

pub use fit::{Lift, Relax, Relaxation, Relaxed, lift};

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use crate::linux::LinuxPlan;
use crate::name::GrantName;
use crate::policy::{Access, EnvPolicy, HardDenyClass, Policy, PolicyError, Rlimits, Tty};
use crate::sbpl::EscapeError;

/// A Linux tier (see the lowering table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Tier {
    /// User namespace, mounts, Landlock and seccomp.
    T1,
    /// Landlock and seccomp, without namespaces.
    T2,
}

impl Tier {
    /// The lowest Landlock ABI the tier accepts.
    pub fn min_landlock_abi(self) -> u8 {
        match self {
            Tier::T1 => 1,
            Tier::T2 => 1,
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Tier::T1 => "T1",
            Tier::T2 => "T2",
        })
    }
}

/// What a policy is lowered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Target {
    /// macOS Seatbelt.
    MacOs,
    /// Linux at a tier, with the Landlock ABI the kernel reports.
    Linux {
        /// The tier.
        tier: Tier,
        /// The Landlock ABI version.
        landlock_abi: u8,
    },
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::MacOs => f.write_str("macOS"),
            Target::Linux { tier, landlock_abi } => {
                write!(f, "Linux {tier} (Landlock ABI {landlock_abi})")
            }
        }
    }
}

macro_rules! constructs {
    ($($variant:ident => $name:literal,)*) => {
        /// A construct of the intent layer, as named in the lowering table and
        /// in [`LowerOptions::allow_degrade`].
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(
            feature = "serde",
            derive(serde::Serialize, serde::Deserialize),
            serde(try_from = "String", into = "String")
        )]
        #[non_exhaustive]
        pub enum Construct {
            $(
                #[doc = concat!("`", $name, "`")]
                $variant,
            )*
        }

        impl Construct {
            /// Every construct, in table order.
            pub const ALL: &'static [Construct] = &[$(Construct::$variant),*];

            /// The table name.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Construct::$variant => $name,)*
                }
            }
        }
    };
}

constructs! {
    FsReadSubpath => "fs-read-subpath",
    FsWriteSubpath => "fs-write-subpath",
    FsExecSubpath => "fs-exec-subpath",
    FsLiteral => "fs-literal",
    FsGlob => "fs-glob",
    FsProtect => "fs-protect",
    FsHide => "fs-hide",
    Grant => "grant",
    NetNone => "net-none",
    NetLoopback => "net-loopback",
    NetProxy => "net-proxy",
    NetIp => "net-ip",
    NetAll => "net-all",
    ExecAny => "exec-any",
    ExecNever => "exec-never",
    ForkDenied => "fork-denied",
    LifetimeRun => "lifetime-run",
    LifetimeTree => "lifetime-tree",
    SignalsSelfAndChildren => "signals-self-and-children",
    SignalsSameUser => "signals-same-user",
    SignalsNone => "signals-none",
    PosixShm => "posix-shm",
    SysvIpc => "sysv-ipc",
    IpcUnixSockets => "ipc-unix-sockets",
    SeatbeltLayer => "seatbelt-layer",
    LinuxLayer => "linux-layer",
    Hygiene => "hygiene",
    BaseV1 => "base-v1",
    BaseV2 => "base-v2",
    BaseV3 => "base-v3",
    TtyNewPty => "tty-new-pty",
    ProcOtherProcesses => "proc-other-processes",
    HdFcntlModify => "hd-fcntl-modify",
    HdPrivilege => "hd-privilege",
    HdServiceHandoff => "hd-service-handoff",
    HdProcessAccess => "hd-process-access",
    HdRenameAnchors => "hd-rename-anchors",
    HdTerminalInjection => "hd-terminal-injection",
    HdKernelSurface => "hd-kernel-surface",
    HdNamespaces => "hd-namespaces",
    HdSocketFamilies => "hd-socket-families",
    HdSecrets => "hd-secrets",
    HdTrustHandoff => "hd-trust-handoff",
    HdPersistence => "hd-persistence",
    HdContainerEngines => "hd-container-engines",
}

impl Construct {
    /// The constructs whose approximation depends on the file system as
    /// procage reads it at spawn, accepted together by
    /// [`LowerOptions::accept_spawn_snapshot`].
    pub const SPAWN_SNAPSHOT: &'static [Construct] = &[
        Construct::HdSecrets,
        Construct::HdTrustHandoff,
        Construct::HdPersistence,
        Construct::FsHide,
        Construct::IpcUnixSockets,
        Construct::HdServiceHandoff,
        Construct::HdContainerEngines,
    ];

    /// The construct of a hard-deny class.
    pub fn of_class(class: HardDenyClass) -> Construct {
        match class {
            HardDenyClass::FcntlModify => Construct::HdFcntlModify,
            HardDenyClass::Privilege => Construct::HdPrivilege,
            HardDenyClass::ServiceHandoff => Construct::HdServiceHandoff,
            HardDenyClass::ProcessAccess => Construct::HdProcessAccess,
            HardDenyClass::RenameAnchors => Construct::HdRenameAnchors,
            HardDenyClass::TerminalInjection => Construct::HdTerminalInjection,
            HardDenyClass::KernelSurface => Construct::HdKernelSurface,
            HardDenyClass::Namespaces => Construct::HdNamespaces,
            HardDenyClass::SocketFamilies => Construct::HdSocketFamilies,
            HardDenyClass::Secrets => Construct::HdSecrets,
            HardDenyClass::TrustHandoff => Construct::HdTrustHandoff,
            HardDenyClass::Persistence => Construct::HdPersistence,
            HardDenyClass::ContainerEngines => Construct::HdContainerEngines,
        }
    }
}

/// A name that is not a construct.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownConstruct(pub String);

impl fmt::Display for UnknownConstruct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown construct {:?}", self.0)
    }
}

impl core::error::Error for UnknownConstruct {}

impl FromStr for Construct {
    type Err = UnknownConstruct;

    fn from_str(name: &str) -> Result<Self, UnknownConstruct> {
        Construct::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == name)
            .ok_or_else(|| UnknownConstruct(name.into()))
    }
}

impl TryFrom<String> for Construct {
    type Error = UnknownConstruct;

    fn try_from(name: String) -> Result<Self, UnknownConstruct> {
        name.parse()
    }
}

impl From<Construct> for String {
    fn from(construct: Construct) -> String {
        construct.as_str().into()
    }
}

impl fmt::Display for Construct {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a target expresses a construct (a cell of the lowering table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Outcome {
    /// Expressed exactly.
    Exact,
    /// Only approximated; accepted when allowed by name, then recorded.
    Approximated,
    /// Not expressible: always a gap.
    Unsupported,
    /// The construct has no meaning on the target; nothing is emitted.
    NotApplicable,
}

/// Why a construct could not be lowered.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GapKind {
    /// The target can only approximate it; allow it by name to accept.
    Approximation,
    /// The target cannot express it.
    Unsupported,
    /// A value cannot be written for the target (for example a path with a
    /// control character, for Seatbelt).
    Unrepresentable(EscapeError),
}

/// A construct a target cannot express exactly.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityGap {
    /// The construct.
    pub construct: Construct,
    /// The target.
    pub target: Target,
    /// Why.
    pub kind: GapKind,
    /// The path or name concerned, for messages.
    pub subject: Option<String>,
}

impl fmt::Display for CapabilityGap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} on {}: ", self.construct, self.target)?;
        match &self.kind {
            GapKind::Approximation if Construct::SPAWN_SNAPSHOT.contains(&self.construct) => f
                .write_str(
                    "only approximated from the file system as it is at spawn (accept it with \
                     LowerOptions::accept_spawn_snapshot, or allow it by name)",
                )?,
            GapKind::Approximation => {
                f.write_str("only approximated (allow it by name to accept)")?
            }
            GapKind::Unsupported => f.write_str("not supported")?,
            GapKind::Unrepresentable(e) => write!(f, "{e}")?,
        }
        if let Some(subject) = &self.subject {
            write!(f, " ({subject})")?;
        }
        Ok(())
    }
}

/// An approximation the caller allowed, recorded in the plan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Degradation {
    /// The construct.
    pub construct: Construct,
    /// The target.
    pub target: Target,
    /// What the approximation does.
    pub note: &'static str,
}

/// A target the lowering refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TargetError {
    /// The Landlock ABI is below what the tier needs.
    LandlockTooOld {
        /// The tier.
        tier: Tier,
        /// The ABI given.
        abi: u8,
        /// The tier's minimum.
        min: u8,
    },
}

impl fmt::Display for TargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetError::LandlockTooOld { tier, abi, min } => {
                write!(
                    f,
                    "tier {tier} needs Landlock ABI {min} or later, the kernel has {abi}"
                )
            }
        }
    }
}

impl core::error::Error for TargetError {}

/// Why lowering returned no plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LowerError {
    /// The policy contradicts itself.
    Invalid(Vec<PolicyError>),
    /// The target is refused.
    Target(TargetError),
    /// Every construct the target cannot express exactly (and that was not
    /// allowed to degrade), sorted.
    Gaps(Vec<CapabilityGap>),
    /// The profile has more rules than the limit, even after the exact merge.
    LimitExceeded {
        /// The configured limit.
        limit: usize,
        /// The rule count after merging.
        rules: usize,
    },
}

impl fmt::Display for LowerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LowerError::Invalid(errors) => {
                f.write_str("invalid policy:")?;
                for e in errors {
                    write!(f, " {e};")?;
                }
                Ok(())
            }
            LowerError::Target(e) => write!(f, "{e}"),
            LowerError::Gaps(gaps) => {
                f.write_str("capability gaps:")?;
                for g in gaps {
                    write!(f, " {g};")?;
                }
                Ok(())
            }
            LowerError::LimitExceeded { limit, rules } => {
                write!(
                    f,
                    "profile has {rules} rules, more than the limit of {limit}"
                )
            }
        }
    }
}

impl core::error::Error for LowerError {}

/// Options for [`lower()`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LowerOptions {
    /// Constructs the caller accepts as approximations.
    pub allow_degrade: BTreeSet<Construct>,
    /// The most rules a Seatbelt profile may have (default 2,000).
    pub max_rules: usize,
    /// Whether denials are reported: every deny rule but the run-marker
    /// block carries a message naming the run ([`RUN_MARKER_PARAM`]) and
    /// the rule's kind ([`crate::sbpl::DenyReason`]). Off, the profile is
    /// exactly the one without reporting.
    pub violations: bool,
}

impl Default for LowerOptions {
    fn default() -> Self {
        Self {
            allow_degrade: BTreeSet::new(),
            max_rules: 2000,
            violations: false,
        }
    }
}

impl LowerOptions {
    /// These options, also accepting `construct` as an approximation.
    pub fn allow(mut self, construct: Construct) -> Self {
        self.allow_degrade.insert(construct);
        self
    }

    /// These options, also accepting every approximation that depends on
    /// the file system as procage reads it at spawn
    /// ([`Construct::SPAWN_SNAPSHOT`]):
    ///
    /// - the data-driven hard-deny classes (`secrets`, `trust-handoff`,
    ///   `persistence`): on Linux tier T1, where a rule reaches their paths,
    ///   the paths that exist at spawn are masked; on tier T2 the secrets
    ///   class, reached only by read rules, is hidden like `fs-hide`;
    /// - `fs-hide` on tier T2: the trees around a hidden path are granted
    ///   piecewise, as listed at spawn;
    /// - `ipc-unix-sockets` on tier T1 below Landlock ABI 9: listening
    ///   sockets outside the paths are masked at spawn;
    /// - `service-handoff` and `container-engines` on tier T1: the bus,
    ///   service-manager and engine sockets found at spawn, and the classes'
    ///   directories, are covered.
    ///
    /// Paths created after the spawn are not covered by a mask; entries
    /// created on the way to a hidden path are denied. No other
    /// approximation is accepted, and each accepted one is still listed in
    /// the plan's degradations. With [`Construct::ProcOtherProcesses`] it
    /// is what reading the whole file system except secrets needs on Linux.
    pub fn accept_spawn_snapshot(mut self) -> Self {
        for &construct in Construct::SPAWN_SNAPSHOT {
            self = self.allow(construct);
        }
        self
    }

    /// These options with denials reported (see [`LowerOptions::violations`]).
    pub fn with_violations(mut self) -> Self {
        self.violations = true;
        self
    }

    /// These options with a rule limit of `max_rules`.
    pub fn with_max_rules(mut self, max_rules: usize) -> Self {
        self.max_rules = max_rules;
        self
    }
}

/// Environment, limits and terminal, carried unchanged into a plan for the
/// spawn backend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hygiene {
    /// The environment policy.
    pub env: EnvPolicy,
    /// Resource limits.
    pub limits: Rlimits,
    /// Terminal mode.
    pub tty: Tty,
}

impl Hygiene {
    fn of(policy: &Policy) -> Self {
        Self {
            env: policy.env.clone(),
            limits: policy.limits.clone(),
            tty: policy.tty,
        }
    }
}

/// A grant slot in a Seatbelt plan.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GrantSlot {
    /// The grant.
    pub name: GrantName,
    /// The sandbox-extension class the profile names (`procage.<name>`).
    pub class: String,
    /// The access the profile gives the extension.
    pub access: Access,
}

/// The plan for macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeatbeltPlan {
    /// The SBPL profile.
    pub profile: String,
    /// Parameters the profile refers to, `(name, value)`.
    pub params: Vec<(String, String)>,
    /// Grant slots, sorted by name.
    pub grants: Vec<GrantSlot>,
    /// Top-level rules after `(deny default)`.
    pub rule_count: usize,
    /// Whether the limits guard merged rules.
    pub merged: bool,
    /// Allowed approximations.
    pub degradations: Vec<Degradation>,
    /// Hard-deny classes the policy waived.
    pub waivers: Vec<HardDenyClass>,
    /// Environment, limits and terminal, unchanged from the policy.
    pub hygiene: Hygiene,
    /// Whether the profile ends with the run-marker block, whose parameters
    /// [`RUN_PREFIX_PARAM`] and [`RUN_MARKER_PARAM`] the spawn backend binds
    /// (they are not in `params`).
    pub run_marker: bool,
}

/// The parameter for the run-marker prefix: the profile denies looking up
/// any service name that starts with it.
pub const RUN_PREFIX_PARAM: &str = "procage-run-prefix";

/// The parameter for the run marker, a name starting with the prefix that the
/// profile allows looking up. No service registers it; a process's sandbox
/// allowing it marks the process as one of the run's.
pub const RUN_MARKER_PARAM: &str = "procage-run-marker";

/// The sandbox-extension class of a run's own terminal device
/// (`Tty::NewPty`): each spawn issues it for its device. Grant classes are
/// `procage.<name>` without a dot in the name, so none can equal it.
pub const PTY_EXTENSION_CLASS: &str = "procage.pty.device";

/// The parameter for the address a `Network::Proxy` profile allows for HTTP
/// (`localhost:<port>`). The plan's `params` give the policy's port; a spawn
/// with a proxy of its own binds the run's.
pub const PROXY_HTTP_PARAM: &str = "procage-proxy-http";

/// The parameter for the SOCKS5 address, as [`PROXY_HTTP_PARAM`].
pub const PROXY_SOCKS_PARAM: &str = "procage-proxy-socks";

/// The result of lowering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Plan {
    /// For macOS.
    Seatbelt(SeatbeltPlan),
    /// For Linux.
    Linux(LinuxPlan),
}

impl Plan {
    /// The allowed approximations.
    pub fn degradations(&self) -> &[Degradation] {
        match self {
            Plan::Seatbelt(p) => &p.degradations,
            Plan::Linux(p) => &p.degradations,
        }
    }

    /// The waived hard-deny classes.
    pub fn waivers(&self) -> &[HardDenyClass] {
        match self {
            Plan::Seatbelt(p) => &p.waivers,
            Plan::Linux(p) => &p.waivers,
        }
    }
}

/// Lowers `policy` for `target`.
///
/// Returns the plan, or why there is none: an invalid policy, a refused
/// target, the complete list of capability gaps, or a profile over the rule
/// limit. The result depends only on the policy's content, not on the order of
/// its rules.
pub fn lower(policy: &Policy, target: Target, options: &LowerOptions) -> Result<Plan, LowerError> {
    policy.validate().map_err(LowerError::Invalid)?;
    match target {
        Target::MacOs => macos::lower(policy, options).map(Plan::Seatbelt),
        Target::Linux { tier, landlock_abi } => {
            let min = tier.min_landlock_abi();
            if landlock_abi < min {
                return Err(LowerError::Target(TargetError::LandlockTooOld {
                    tier,
                    abi: landlock_abi,
                    min,
                }));
            }
            linux::lower(policy, tier, landlock_abi, options).map(Plan::Linux)
        }
    }
}

/// Collects outcomes into gaps and degradations.
struct Ledger<'a> {
    target: Target,
    options: &'a LowerOptions,
    gaps: Vec<CapabilityGap>,
    degradations: Vec<Degradation>,
}

impl<'a> Ledger<'a> {
    fn new(target: Target, options: &'a LowerOptions) -> Self {
        Self {
            target,
            options,
            gaps: Vec::new(),
            degradations: Vec::new(),
        }
    }

    /// Records `outcome` for `construct`; returns whether to emit it.
    fn outcome(
        &mut self,
        construct: Construct,
        outcome: Outcome,
        subject: Option<String>,
        note: &'static str,
    ) -> bool {
        match outcome {
            Outcome::Exact => true,
            Outcome::NotApplicable => false,
            Outcome::Approximated if self.options.allow_degrade.contains(&construct) => {
                self.degradations.push(Degradation {
                    construct,
                    target: self.target,
                    note,
                });
                true
            }
            Outcome::Approximated => {
                self.gap(construct, GapKind::Approximation, subject);
                false
            }
            Outcome::Unsupported => {
                self.gap(construct, GapKind::Unsupported, subject);
                false
            }
        }
    }

    fn gap(&mut self, construct: Construct, kind: GapKind, subject: Option<String>) {
        self.gaps.push(CapabilityGap {
            construct,
            target: self.target,
            kind,
            subject,
        });
    }

    fn finish(mut self) -> Result<Vec<Degradation>, LowerError> {
        if !self.gaps.is_empty() {
            self.gaps.sort();
            self.gaps.dedup();
            return Err(LowerError::Gaps(self.gaps));
        }
        self.degradations.sort();
        self.degradations
            .dedup_by(|a, b| a.construct == b.construct);
        Ok(self.degradations)
    }
}

/// The construct of a file rule.
fn fs_construct(rule: &crate::policy::FsRule) -> Construct {
    use crate::policy::FsTarget;
    match (rule.access, &rule.target) {
        (Access::Protect, _) => Construct::FsProtect,
        (Access::Hide, _) => Construct::FsHide,
        (_, FsTarget::Literal(_)) => Construct::FsLiteral,
        (_, FsTarget::Glob(_)) => Construct::FsGlob,
        (Access::Read, FsTarget::Subpath(_)) => Construct::FsReadSubpath,
        (Access::Write, FsTarget::Subpath(_)) => Construct::FsWriteSubpath,
        (Access::Exec, FsTarget::Subpath(_)) => Construct::FsExecSubpath,
    }
}

fn subject_of(target: &crate::policy::FsTarget) -> String {
    use crate::policy::FsTarget;
    use alloc::string::ToString;
    match target {
        FsTarget::Literal(p) | FsTarget::Subpath(p) => p.to_string(),
        FsTarget::Glob(g) => g.as_str().into(),
    }
}
