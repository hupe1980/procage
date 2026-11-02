//! What one policy's plan allows or denies that another's does not.
//!
//! Rules are compared as sets, one entry per rule and alternative
//! filter, within their block. An answer can only change if a rule that
//! matches the question is added or removed; if it became allowed, either
//! the new deciding allow was added or a later deny that matched before was
//! removed, and both loosen. So every changed answer is covered by an entry
//! with the right direction. Every other plan field that differs is listed
//! as a setting. Nothing intersects patterns: the cost is one sort.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use super::macos::{Matcher, op_matches, sbpl_op};
use super::{Context, Decider, MODELLED, Op};
use crate::glob::Glob;
use crate::linux::{AccessFs, LinuxPlan, Mount, RuleTarget};
use crate::lower::{LowerError, LowerOptions, Plan, Target, lower};
use crate::name::GrantName;
use crate::policy::{HardDenyClass, Policy};
use crate::sbpl::Filter;
use crate::seatbelt::Effect;

/// The paths an entry applies to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PathSet {
    /// Every path (an unfiltered rule).
    Every,
    /// Exactly this path.
    Literal(Vec<u8>),
    /// This path and everything below it.
    Subpath(Vec<u8>),
    /// Paths an SBPL regex matches.
    Regex(String),
    /// This path and every directory above it.
    Ancestors(Vec<u8>),
    /// The path bound to a grant, and everything below it.
    Grant(GrantName),
    /// The paths of a hard-deny class.
    Class(HardDenyClass),
    /// Paths a glob matches at spawn.
    Glob(Glob),
    /// A filter that is not a path (a service name, a socket address), as
    /// written.
    Other(String),
}

impl PathSet {
    fn of(filter: &Filter) -> PathSet {
        match filter {
            Filter::Literal(v) => PathSet::Literal(v.clone()),
            Filter::Subpath(v) => PathSet::Subpath(v.clone()),
            Filter::Regex(r) => PathSet::Regex(r.clone()),
            Filter::PathAncestors(v) => PathSet::Ancestors(v.clone()),
            Filter::Extension(class) => match class
                .strip_prefix("procage.")
                .and_then(|n| GrantName::new(n).ok())
            {
                Some(name) => PathSet::Grant(name),
                None => PathSet::Other(format!("{filter:?}")),
            },
            other => PathSet::Other(format!("{other:?}")),
        }
    }

    /// Whether `path` may be in the set: exact for paths, true for anything
    /// that is not judged by path.
    pub fn contains(&self, path: &[u8], context: &Context) -> bool {
        let sub = super::macos::subpath;
        match self {
            PathSet::Literal(v) => path == v.as_slice(),
            PathSet::Subpath(v) => sub(path, v),
            PathSet::Ancestors(v) => sub(v, path),
            PathSet::Regex(r) => Matcher::of(&Filter::Regex(r.clone()))
                .matches(path, 0, context)
                .unwrap_or(true),
            PathSet::Grant(name) => context
                .grant(name.as_str())
                .is_none_or(|g| sub(path, g.as_bytes())),
            PathSet::Glob(g) => {
                super::regex::Regex::new(&g.to_sbpl_regex()).is_none_or(|r| r.is_match(path))
            }
            PathSet::Every | PathSet::Class(_) | PathSet::Other(_) => true,
        }
    }
}

/// Whether an entry loosens or tightens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    /// The second policy allows more (an added allow, a removed deny).
    Loosens,
    /// The second policy allows less.
    Tightens,
}

/// A rule one plan has and the other lacks.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DiffEntry {
    /// The target.
    pub target: Target,
    /// Loosens or tightens.
    pub direction: Direction,
    /// The operations: the modelled ones it decides, and the rule's own
    /// operation names as [`Op::Other`].
    pub ops: Vec<Op>,
    /// The paths.
    pub paths: PathSet,
    /// Where the rule comes from (in the policy that has it).
    pub by: Decider,
}

impl DiffEntry {
    /// Whether the entry may change the answer to `op` on `path`.
    pub fn covers(&self, op: &Op, path: &[u8], context: &Context) -> bool {
        self.ops.contains(op) && self.paths.contains(path, context)
    }
}

/// The difference between two policies' plans.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Diff {
    /// Rules one plan has and the other lacks.
    pub entries: Vec<DiffEntry>,
    /// Other differences, by target and name (`base`, `waivers`,
    /// `network`, …).
    pub settings: Vec<(Target, &'static str)>,
}

impl Diff {
    /// Whether the plans are the same.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.settings.is_empty()
    }
}

/// One comparable piece of a plan: (block, effect, op names, paths) and its
/// origin.
type Key = (u8, Effect, Vec<String>, PathSet);

fn sbpl_ops(names: &[String]) -> Vec<Op> {
    let mut ops: Vec<Op> = MODELLED
        .iter()
        .filter(|op| names.iter().any(|n| op_matches(n, sbpl_op(op))))
        .cloned()
        .collect();
    ops.extend(names.iter().map(|n| Op::Other(n.clone())));
    ops
}

fn landlock_ops(access: AccessFs) -> Vec<Op> {
    let mut ops: Vec<Op> = MODELLED
        .iter()
        .filter(|op| access.contains(super::linux::right(op)))
        .cloned()
        .collect();
    ops.push(Op::Other(format!("landlock {:#x}", access.0)));
    ops
}

fn macos_keys(policy: &Policy, options: &LowerOptions) -> Result<Vec<(Key, Decider)>, LowerError> {
    let emitted = crate::lower::macos::emit(policy, options)?;
    let mut out = Vec::new();
    for (block, rules) in emitted.blocks.into_iter().enumerate() {
        for (rule, by) in rules {
            let mut ops = rule.ops.clone();
            ops.sort();
            let paths: Vec<PathSet> = if rule.filters.is_empty() {
                alloc::vec![PathSet::Every]
            } else {
                rule.filters.iter().map(PathSet::of).collect()
            };
            for p in paths {
                out.push(((block as u8, rule.effect, ops.clone(), p), by.clone()));
            }
        }
    }
    Ok(out)
}

fn linux_keys(policy: &Policy, plan: &LinuxPlan) -> Vec<(Key, Decider)> {
    let model = super::linux::Model::new(policy, plan.clone());
    let mut out = Vec::new();
    for rule in &plan.landlock.rules {
        let paths = match &rule.target {
            RuleTarget::Path(p) | RuleTarget::PathIfExists(p) => {
                PathSet::Subpath(p.as_bytes().to_vec())
            }
            RuleTarget::Grant(g) => PathSet::Grant(g.clone()),
            RuleTarget::ExpandGlob(g) => PathSet::Glob(g.clone()),
        };
        let ops = alloc::vec![format!("landlock {:#x}", rule.access.0)];
        let by = model.origin(&rule.target, AccessFs::NONE);
        out.push(((0, Effect::Allow, ops, paths), by));
    }
    for mount in &plan.mounts {
        let (name, paths) = match mount {
            Mount::Mask(p) => ("mask", PathSet::Subpath(p.as_bytes().to_vec())),
            Mount::ReadOnlyBind(p) => ("read-only", PathSet::Subpath(p.as_bytes().to_vec())),
            Mount::Pin(p) => ("pin", PathSet::Subpath(p.as_bytes().to_vec())),
            Mount::PrivateDevShm => ("private-dev-shm", PathSet::Subpath(b"/dev/shm".to_vec())),
        };
        out.push((
            (1, Effect::Deny, alloc::vec![name.to_string()], paths),
            Decider::Layer,
        ));
    }
    for hidden in &plan.hide_by_siblings {
        out.push((
            (
                1,
                Effect::Deny,
                alloc::vec!["mask".into()],
                PathSet::Subpath(hidden.as_bytes().to_vec()),
            ),
            Decider::Layer,
        ));
    }
    for class in &plan.classes {
        let name = if class.hide { "mask" } else { "read-only" };
        out.push((
            (
                2,
                Effect::Deny,
                alloc::vec![name.into()],
                PathSet::Class(class.class),
            ),
            Decider::HardDeny(class.class),
        ));
    }
    for sockets in &plan.service_sockets {
        out.push((
            (
                2,
                Effect::Deny,
                alloc::vec!["unix-connect".into()],
                PathSet::Class(sockets.class),
            ),
            Decider::HardDeny(sockets.class),
        ));
    }
    for rule in &plan.seccomp {
        out.push((
            (
                3,
                Effect::Deny,
                alloc::vec![rule.syscall.as_str().into()],
                PathSet::Other(format!("{:?} {:?}", rule.condition, rule.action)),
            ),
            match rule.reason {
                Some(crate::sbpl::DenyReason::HardDeny(c)) => Decider::HardDeny(c),
                _ => Decider::Layer,
            },
        ));
    }
    out
}

/// The ops a key's names stand for.
fn key_ops(target: Target, key: &Key) -> Vec<Op> {
    match target {
        Target::MacOs => sbpl_ops(&key.2),
        Target::Linux { .. } => match key.2.first().map(String::as_str) {
            Some(name) if name.starts_with("landlock ") => {
                let bits =
                    u64::from_str_radix(name.trim_start_matches("landlock 0x"), 16).unwrap_or(0);
                landlock_ops(AccessFs(bits))
            }
            Some("mask") => {
                let mut ops = MODELLED.to_vec();
                ops.push(Op::Other("mask".into()));
                ops
            }
            Some("read-only") => alloc::vec![Op::Write, Op::Other("read-only".into())],
            _ => key.2.iter().map(|n| Op::Other(n.clone())).collect(),
        },
    }
}

fn linux_settings(a: &LinuxPlan, b: &LinuxPlan) -> Vec<&'static str> {
    let mut out = Vec::new();
    let mut check = |name, differs: bool| {
        if differs {
            out.push(name);
        }
    };
    check("tier", a.tier != b.tier);
    check("landlock abi", a.landlock_abi != b.landlock_abi);
    check("namespaces", a.namespaces != b.namespaces);
    check(
        "handled rights",
        a.landlock.handled_fs != b.landlock.handled_fs,
    );
    check(
        "network",
        a.landlock.handled_net != b.landlock.handled_net
            || a.landlock.net_rules != b.landlock.net_rules
            || a.network != b.network,
    );
    check("scopes", a.landlock.scopes != b.landlock.scopes);
    check("no_new_privs", a.no_new_privs != b.no_new_privs);
    check(
        "ipc.unix_sockets",
        a.mask_unix_sockets != b.mask_unix_sockets || a.unix_socket_paths != b.unix_socket_paths,
    );
    check("degradations", a.degradations != b.degradations);
    check("hygiene", a.hygiene != b.hygiene);
    out
}

/// The difference between `a` and `b` on each of `targets`.
pub fn diff(
    a: &Policy,
    b: &Policy,
    targets: &[Target],
    options: &LowerOptions,
) -> Result<Diff, LowerError> {
    let mut out = Diff::default();
    for &target in targets {
        let (pa, pb) = (lower(a, target, options)?, lower(b, target, options)?);
        let (ka, kb) = match (&pa, &pb) {
            (Plan::Seatbelt(x), Plan::Seatbelt(y)) => {
                let mut settings = Vec::new();
                if x.grants != y.grants {
                    settings.push("grants");
                }
                if x.run_marker != y.run_marker {
                    settings.push("lifetime");
                }
                if x.degradations != y.degradations {
                    settings.push("degradations");
                }
                if x.hygiene != y.hygiene {
                    settings.push("hygiene");
                }
                out.settings
                    .extend(settings.into_iter().map(|s| (target, s)));
                (macos_keys(a, options)?, macos_keys(b, options)?)
            }
            (Plan::Linux(x), Plan::Linux(y)) => {
                out.settings
                    .extend(linux_settings(x, y).into_iter().map(|s| (target, s)));
                (linux_keys(a, x), linux_keys(b, y))
            }
            _ => unreachable!("both plans are for the same target"),
        };
        if a.base != b.base {
            out.settings.push((target, "base"));
        }
        if a.preset != b.preset {
            out.settings.push((target, "preset"));
        }
        if a.waive != b.waive {
            out.settings.push((target, "waivers"));
        }
        // Set difference: the profile and the plan keep one copy of each.
        let mut seen: BTreeMap<Key, (Option<Decider>, Option<Decider>)> = BTreeMap::new();
        for (k, by) in ka {
            seen.entry(k).or_default().0.get_or_insert(by);
        }
        for (k, by) in kb {
            seen.entry(k).or_default().1.get_or_insert(by);
        }
        for (key, (by_a, by_b)) in seen {
            if by_a.is_some() == by_b.is_some() {
                continue;
            }
            let added = by_b.is_some();
            let allow = key.1 == Effect::Allow;
            out.entries.push(DiffEntry {
                target,
                direction: if added == allow {
                    super::Direction::Loosens
                } else {
                    super::Direction::Tightens
                },
                ops: key_ops(target, &key),
                by: if added { by_b } else { by_a }.unwrap_or(Decider::None),
                paths: key.3,
            });
        }
    }
    out.entries.sort();
    out.entries.dedup();
    out.settings.sort();
    out.settings.dedup();
    Ok(out)
}
