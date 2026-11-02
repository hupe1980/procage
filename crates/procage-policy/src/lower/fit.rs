//! Fitting a policy to a host: relaxations the caller names, applied to the
//! gaps a target reports, and what would lift each gap.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::fmt;

use super::{CapabilityGap, Construct, GapKind, LowerError, LowerOptions, Target, Tier, lower};
use crate::policy::{Access, HardDenyClass, Network, Policy, Signals};

/// One way to give up a construct a host cannot enforce. Each has exactly one
/// effect; nothing else can be relaxed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Relaxation {
    /// `fs-protect`: the protect rule the gap names is left out.
    LeaveOutProtect,
    /// `fs-hide`: the hide rule the gap names is left out.
    LeaveOutHide,
    /// The class's `hd-*` construct: the class is waived.
    Waive(HardDenyClass),
    /// `ipc-unix-sockets`: no Unix socket is reachable (stricter). It also
    /// answers the `hd-service-handoff` and `hd-container-engines` gaps of
    /// [`Network::All`], which then becomes [`Network::Ip`].
    NoUnixSockets,
    /// `signals-self-and-children`: signals reach every process of the user
    /// ([`Signals::SameUser`]).
    SignalsSameUser,
    /// `net-loopback`: no network at all (stricter).
    NoLoopback,
}

impl Relaxation {
    /// The construct this relaxation is named for.
    pub fn construct(self) -> Construct {
        match self {
            Relaxation::LeaveOutProtect => Construct::FsProtect,
            Relaxation::LeaveOutHide => Construct::FsHide,
            Relaxation::Waive(class) => Construct::of_class(class),
            Relaxation::NoUnixSockets => Construct::IpcUnixSockets,
            Relaxation::SignalsSameUser => Construct::SignalsSelfAndChildren,
            Relaxation::NoLoopback => Construct::NetLoopback,
        }
    }

    /// Whether this relaxation answers a gap of `construct`.
    pub fn answers(self, construct: Construct) -> bool {
        construct == self.construct()
            || (self == Relaxation::NoUnixSockets
                && matches!(
                    construct,
                    Construct::HdServiceHandoff | Construct::HdContainerEngines
                ))
    }
}

impl fmt::Display for Relaxation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Relaxation::LeaveOutProtect => f.write_str("the protect rule is left out"),
            Relaxation::LeaveOutHide => f.write_str("the hide rule is left out"),
            Relaxation::Waive(class) => write!(f, "the {class} class is waived"),
            Relaxation::NoUnixSockets => f.write_str("no Unix socket is reachable"),
            Relaxation::SignalsSameUser => f.write_str("signals reach every process of the user"),
            Relaxation::NoLoopback => f.write_str("there is no network, not even loopback"),
        }
    }
}

/// The relaxations a caller accepts, each named explicitly.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Relax {
    accepted: BTreeSet<Relaxation>,
}

impl Relax {
    /// No relaxation: fitting behaves like preparing the cage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Accepts `relaxation`.
    pub fn accept(mut self, relaxation: Relaxation) -> Self {
        self.accepted.insert(relaxation);
        self
    }

    /// Accepts leaving out protect rules the host cannot enforce.
    pub fn leave_out_protect(self) -> Self {
        self.accept(Relaxation::LeaveOutProtect)
    }

    /// Accepts leaving out hide rules the host cannot enforce.
    pub fn leave_out_hide(self) -> Self {
        self.accept(Relaxation::LeaveOutHide)
    }

    /// Accepts waiving `class` where the host cannot enforce it.
    pub fn waive(self, class: HardDenyClass) -> Self {
        self.accept(Relaxation::Waive(class))
    }

    /// Accepts no Unix sockets where the allowed ones cannot be kept apart.
    pub fn no_unix_sockets(self) -> Self {
        self.accept(Relaxation::NoUnixSockets)
    }

    /// Accepts signals to every process of the user where they cannot be
    /// kept within the run.
    pub fn signals_same_user(self) -> Self {
        self.accept(Relaxation::SignalsSameUser)
    }

    /// Accepts no network where loopback cannot be given alone.
    pub fn no_loopback(self) -> Self {
        self.accept(Relaxation::NoLoopback)
    }

    /// The accepted relaxations.
    pub fn accepted(&self) -> impl Iterator<Item = Relaxation> + '_ {
        self.accepted.iter().copied()
    }

    fn answer(&self, gap: &CapabilityGap) -> Option<Relaxation> {
        if gap.kind != GapKind::Unsupported {
            return None;
        }
        self.accepted
            .iter()
            .copied()
            .find(|r| r.answers(gap.construct))
    }

    /// Relaxes `policy` for `gaps`: every gap must be unsupported and have
    /// an accepted relaxation, and then each is applied and returned with
    /// its relaxation. Otherwise `policy` is left unchanged and the gaps
    /// that cannot be relaxed are returned.
    pub fn apply(
        &self,
        policy: &mut Policy,
        gaps: &[CapabilityGap],
    ) -> Result<Vec<(CapabilityGap, Relaxation)>, Vec<CapabilityGap>> {
        let mut answered = Vec::new();
        let mut rest = Vec::new();
        for gap in gaps {
            match self.answer(gap) {
                Some(r) => answered.push((gap.clone(), r)),
                None => rest.push(gap.clone()),
            }
        }
        if !rest.is_empty() {
            return Err(rest);
        }
        let mut relaxed = policy.clone();
        for (gap, r) in &answered {
            if !relax_one(&mut relaxed, gap, *r) {
                // The gap names no rule of this policy: nothing to relax.
                return Err(alloc::vec![gap.clone()]);
            }
        }
        *policy = relaxed;
        Ok(answered)
    }
}

fn relax_one(policy: &mut Policy, gap: &CapabilityGap, r: Relaxation) -> bool {
    match r {
        Relaxation::LeaveOutProtect | Relaxation::LeaveOutHide => {
            let access = if r == Relaxation::LeaveOutProtect {
                Access::Protect
            } else {
                Access::Hide
            };
            let before = policy.fs.len();
            policy.fs.retain(|rule| {
                !(rule.access == access
                    && gap.subject.as_deref() == Some(&*super::subject_of(&rule.target)))
            });
            policy.fs.len() != before
        }
        Relaxation::Waive(class) => {
            policy.waive.insert(class);
            true
        }
        // A socket class's gap: only the network that leaves every Unix
        // socket reachable becomes the IP network (`Ip` after an earlier gap).
        Relaxation::NoUnixSockets if gap.construct != Construct::IpcUnixSockets => {
            if !matches!(policy.net, Network::All | Network::Ip) {
                return false;
            }
            policy.net = Network::Ip;
            policy.ipc.unix_sockets.clear();
            true
        }
        Relaxation::NoUnixSockets => {
            policy.ipc.unix_sockets.clear();
            true
        }
        Relaxation::SignalsSameUser => {
            policy.process.signals = Signals::SameUser;
            true
        }
        Relaxation::NoLoopback => {
            policy.net = Network::None;
            true
        }
    }
}

/// What would make a gap enforceable on Linux: tier T1 (user namespaces), a
/// newer Landlock ABI, or either. Neither means unknown.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Lift {
    /// Tier T1 at the same ABI lifts it.
    pub tier1: bool,
    /// The lowest Landlock ABI on the same tier that lifts it.
    pub landlock_abi: Option<u8>,
}

impl Lift {
    /// Whether anything known lifts the gap.
    pub fn is_known(&self) -> bool {
        self.tier1 || self.landlock_abi.is_some()
    }
}

impl fmt::Display for Lift {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.tier1, self.landlock_abi) {
            (true, Some(abi)) => write!(
                f,
                "tier T1 (user namespaces) or Landlock ABI {abi} would enforce it"
            ),
            (true, None) => f.write_str("tier T1 (user namespaces) would enforce it"),
            (false, Some(abi)) => write!(f, "Landlock ABI {abi} would enforce it"),
            (false, None) => f.write_str("no tier or kernel procage knows would enforce it"),
        }
    }
}

/// Whether lowering `policy` for `target` still reports `gap`.
fn still(policy: &Policy, gap: &CapabilityGap, target: Target, options: &LowerOptions) -> bool {
    match lower(policy, target, options) {
        Ok(_) => false,
        Err(LowerError::Gaps(gaps)) => gaps
            .iter()
            .any(|g| g.construct == gap.construct && g.subject == gap.subject),
        Err(_) => true,
    }
}

/// What lifts `gap`, found by lowering `policy` for tier T1 and for newer
/// Landlock ABIs up to `max_abi`. A gap lowering does not report (found at
/// spawn) has an unknown lift.
pub fn lift(policy: &Policy, gap: &CapabilityGap, options: &LowerOptions, max_abi: u8) -> Lift {
    let Target::Linux { tier, landlock_abi } = gap.target else {
        return Lift::default();
    };
    if !still(policy, gap, gap.target, options) {
        return Lift::default();
    }
    let tier1 = tier == Tier::T2
        && !still(
            policy,
            gap,
            Target::Linux {
                tier: Tier::T1,
                landlock_abi,
            },
            options,
        );
    let landlock_abi = (landlock_abi.saturating_add(1)..=max_abi).find(|&abi| {
        !still(
            policy,
            gap,
            Target::Linux {
                tier,
                landlock_abi: abi,
            },
            options,
        )
    });
    Lift {
        tier1,
        landlock_abi,
    }
}

/// A gap that fitting relaxed: what was refused, what changed, and what
/// would lift it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relaxed {
    /// The gap the host reported.
    pub gap: CapabilityGap,
    /// The change made to the policy.
    pub relaxation: Relaxation,
    /// What would make the construct enforceable.
    pub lift: Lift,
}

impl fmt::Display for Relaxed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.gap.construct)?;
        if let Some(subject) = &self.gap.subject {
            write!(f, " {subject}")?;
        }
        write!(
            f,
            " on {}: {}; {}",
            self.gap.target, self.relaxation, self.lift
        )
    }
}
