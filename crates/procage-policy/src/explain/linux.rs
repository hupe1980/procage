//! Questions against a Linux plan.
//!
//! Landlock allows a right when any rule on the path or a directory above it
//! grants it, and every right the ruleset does not handle. On tier T1 the
//! mounts deny over that: masks (hide), read-only binds (protect) and the
//! covers of the data-driven classes, which exist only for paths found at
//! spawn. On tier T2 hidden paths are kept out by granting their siblings
//! as listed at spawn.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::macos::subpath;
use super::{Context, Decider, Decision, Op, Verdict};
use crate::linux::{AccessFs, ClassPaths, LinuxPlan, Mount, RuleTarget};
use crate::lower::Tier;
use crate::path::AbsPath;
use crate::policy::{Access, FsRule, FsTarget, Policy};

/// The caveat of a class cover on T1.
pub const SPAWN_COVER: &str = "covered only if it existed at spawn: class paths are \
    mounted over as found then, and names under writable trees by a walk";

/// The caveat of a piecewise hide on T2 (see the lowering's note).
pub const PIECEWISE: &str = "the tree around the hidden path is granted entry by entry as \
    listed at spawn: entries added later are denied";

/// The caveat of a glob expanded at spawn.
pub const GLOB_AT_SPAWN: &str = "the glob is expanded at spawn; later files are not covered";

pub(super) fn right(op: &Op) -> AccessFs {
    match op {
        Op::Read => AccessFs::READ_FILE,
        Op::Write => AccessFs::WRITE_FILE,
        Op::Exec | Op::Other(_) => AccessFs::EXECUTE,
    }
}

#[derive(Debug, Clone)]
pub(super) struct Model {
    plan: LinuxPlan,
    policy: Policy,
    /// The policy's read, write and exec rules on a path, by path.
    allows: BTreeMap<AbsPath, Vec<FsRule>>,
}

fn bytes(p: &AbsPath) -> &[u8] {
    p.as_bytes()
}

fn joined(base: &[u8], rel: &str) -> Vec<u8> {
    let mut out = base.to_vec();
    if out != b"/" {
        out.push(b'/');
    }
    out.extend_from_slice(rel.as_bytes());
    out
}

impl Model {
    pub(super) fn new(policy: &Policy, plan: LinuxPlan) -> Model {
        let mut allows: BTreeMap<AbsPath, Vec<FsRule>> = BTreeMap::new();
        for rule in &policy.fs {
            if let (
                Access::Read | Access::Write | Access::Exec,
                FsTarget::Subpath(p) | FsTarget::Literal(p),
            ) = (rule.access, &rule.target)
            {
                allows.entry(p.clone()).or_default().push(rule.clone());
            }
        }
        Model {
            plan,
            policy: policy.clone(),
            allows,
        }
    }

    fn t1(&self) -> bool {
        self.plan.tier == Tier::T1
    }

    /// The path a rule target stands for in this spawn.
    fn target_path<'a>(&self, target: &'a RuleTarget, context: &'a Context) -> Option<&'a [u8]> {
        match target {
            RuleTarget::Path(p) | RuleTarget::PathIfExists(p) => Some(bytes(p)),
            RuleTarget::Grant(name) => context.grant(name.as_str()).map(bytes),
            RuleTarget::ExpandGlob(_) => None,
        }
    }

    /// The trees the T1 walk searches for class names: every rule that
    /// grants writing.
    fn writable<'a>(&'a self, context: &'a Context) -> impl Iterator<Item = &'a [u8]> + 'a {
        self.plan
            .landlock
            .rules
            .iter()
            .filter(|r| r.access.contains(AccessFs::WRITE_FILE))
            .filter_map(move |r| self.target_path(&r.target, context))
    }

    /// Whether a class covers `path` (homes, system paths, and on T1 the
    /// names found under writable trees).
    fn class_covers(&self, class: &ClassPaths, path: &[u8], context: &Context) -> bool {
        let home = context.homes.iter().any(|h| {
            class
                .home
                .iter()
                .any(|rel| subpath(path, &joined(bytes(h), rel)))
        });
        let system = class.system.iter().any(|p| subpath(path, bytes(p)));
        let anywhere = self.t1()
            && class.anywhere.iter().any(|name| {
                // Some directory `d/name` above or at `path` with `d` in a
                // writable tree.
                let suffix = joined(b"", name);
                let mut end = path.len();
                loop {
                    let candidate = &path[..end];
                    if candidate.ends_with(&suffix) {
                        let dir = &candidate[..candidate.len() - suffix.len()];
                        let dir: &[u8] = if dir.is_empty() { b"/" } else { dir };
                        if self.writable(context).any(|w| subpath(dir, w)) {
                            return true;
                        }
                    }
                    match candidate.iter().rposition(|&b| b == b'/') {
                        Some(0) | None => return false,
                        Some(i) => end = i,
                    }
                }
            });
        home || system || anywhere
    }

    /// The policy rule a mount or sibling list comes from.
    fn rule_for(&self, path: &AbsPath, access: Access) -> Decider {
        self.policy
            .fs
            .iter()
            .find(|r| {
                r.access == access
                    && matches!(&r.target, FsTarget::Subpath(p) | FsTarget::Literal(p) if p == path)
            })
            .cloned()
            .map_or(Decider::Layer, Decider::Rule)
    }

    /// Who an allowing Landlock rule on `path` with `access` comes from.
    pub(super) fn origin(&self, target: &RuleTarget, need: AccessFs) -> Decider {
        let p = match target {
            RuleTarget::Grant(name) => return Decider::Grant(name.clone()),
            RuleTarget::ExpandGlob(_) => return Decider::Layer,
            RuleTarget::Path(p) | RuleTarget::PathIfExists(p) => p,
        };
        let handled = self.plan.landlock.handled_fs;
        let fs: Option<&FsRule> = self.allows.get(p).and_then(|rules| {
            rules
                .iter()
                .find(|r| crate::linux::rights(r.access, handled).contains(need))
        });
        if let Some(rule) = fs {
            return Decider::Rule(rule.clone());
        }
        if let Some(layer) = &self.policy.linux
            && layer.landlock_extra.iter().any(|(q, _)| q == p)
        {
            return Decider::Layer;
        }
        if self.policy.ipc.posix_shm && p.as_bytes() == b"/dev/shm" {
            return Decider::Setting("ipc.posix_shm");
        }
        if self.policy.ipc.unix_sockets.contains(p) {
            return Decider::Setting("ipc.unix_sockets");
        }
        Decider::Base(self.policy.base)
    }

    pub(super) fn decide(&self, op: &Op, path: &AbsPath, context: &Context) -> Verdict {
        let need = right(op);
        let p = path.as_bytes();
        let denied = |by, caveat| Verdict {
            decision: Decision::Denied,
            by,
            caveat,
        };
        // Covers deny over every Landlock rule.
        for class in &self.plan.classes {
            let applies = class.hide || need == AccessFs::WRITE_FILE;
            let covered = self.t1() || class.hide;
            if applies && covered && self.class_covers(class, p, context) {
                let caveat = if self.t1() { SPAWN_COVER } else { PIECEWISE };
                return denied(Decider::HardDeny(class.class), Some(caveat));
            }
        }
        for mount in &self.plan.mounts {
            match mount {
                Mount::Mask(m) if subpath(p, bytes(m)) => {
                    return denied(self.rule_for(m, Access::Hide), None);
                }
                Mount::ReadOnlyBind(m) if need == AccessFs::WRITE_FILE && subpath(p, bytes(m)) => {
                    return denied(self.rule_for(m, Access::Protect), None);
                }
                _ => {}
            }
        }
        for hidden in &self.plan.hide_by_siblings {
            if subpath(p, bytes(hidden)) {
                return denied(self.rule_for(hidden, Access::Hide), Some(PIECEWISE));
            }
        }
        if !self.plan.landlock.handled_fs.contains(need) {
            return Verdict {
                decision: Decision::Allowed,
                by: Decider::Unhandled,
                caveat: None,
            };
        }
        let mut best: Option<(Decider, Option<&'static str>)> = None;
        for rule in &self.plan.landlock.rules {
            if !rule.access.contains(need) {
                continue;
            }
            let (root, caveat) = match &rule.target {
                RuleTarget::ExpandGlob(g) => {
                    let Some(re) = super::regex::Regex::new(&g.to_sbpl_regex()) else {
                        return Verdict::not_modelled();
                    };
                    if !re.is_match(p) {
                        continue;
                    }
                    (None, Some(GLOB_AT_SPAWN))
                }
                target => match self.target_path(target, context) {
                    Some(root) if subpath(p, root) => (Some(root), None),
                    _ => continue,
                },
            };
            let caveat = caveat.or_else(|| {
                // A tree split around a hidden path on T2.
                let split = root.is_some_and(|root| {
                    self.hidden_piecewise(context)
                        .any(|h| subpath(&h, root) && h.as_slice() != root)
                });
                split.then_some(PIECEWISE)
            });
            let by = self.origin(&rule.target, need);
            let rank = |d: &Decider| match d {
                Decider::Rule(_) => 0,
                Decider::Grant(_) => 1,
                Decider::Layer => 2,
                Decider::Setting(_) => 3,
                _ => 4,
            };
            if best.as_ref().is_none_or(|(b, _)| rank(&by) < rank(b)) {
                best = Some((by, caveat));
            }
        }
        match best {
            Some((by, caveat)) => Verdict {
                decision: Decision::Allowed,
                by,
                caveat,
            },
            None => denied(Decider::Default, None),
        }
    }

    /// The paths hidden piecewise on T2: hide rules and the hidden classes'
    /// paths in the homes and on the system.
    fn hidden_piecewise<'a>(&'a self, context: &'a Context) -> impl Iterator<Item = Vec<u8>> + 'a {
        let t2 = !self.t1();
        let rules = self
            .plan
            .hide_by_siblings
            .iter()
            .map(|p| p.as_bytes().to_vec());
        let classes = self
            .plan
            .classes
            .iter()
            .filter(move |c| t2 && c.hide)
            .flat_map(move |c| {
                let homes = context
                    .homes
                    .iter()
                    .flat_map(move |h| c.home.iter().map(move |rel| joined(bytes(h), rel)));
                homes.chain(c.system.iter().map(|p| p.as_bytes().to_vec()))
            });
        rules.chain(classes)
    }
}
