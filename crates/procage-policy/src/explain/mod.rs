//! Why a lowered policy allows or denies an operation, and what one policy
//! allows that another does not.
//!
//! An [`Explainer`] lowers a policy for one target and answers questions
//! about opening a file for reading or writing and executing a file
//! ([`MODELLED`]): allowed or denied, by which rule, with what a spawn-time
//! caveat, and the narrowest change that would flip a denial. Any other
//! operation, and any rule the evaluator cannot read for the operation
//! asked, answers [`Decision::NotModelled`], never a guess. [`diff()`] lists
//! the rules one policy's plan has and the other's lacks.
//!
//! The answers follow the plan, not the kernel. procage's oracle suite asks
//! the kernel the same questions through caged children on every target and
//! fails on any disagreement; the operations in [`MODELLED`] are the ones it
//! proves.
//!
//! An answer names the policy's rules. It is meant for the user deciding
//! about the policy; a harness should not relay it into the cage unfiltered.
//!
//! ```
//! use procage_policy::explain::{Change, Context, Decider, Decision, Explainer, Op, Question};
//! use procage_policy::{AbsPath, Access, FsRule, FsTarget, HardDenyClass, LowerOptions, Policy, Target};
//!
//! let mut policy = Policy::default();
//! policy.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(AbsPath::new("/work")?)));
//! let ex = Explainer::new(&policy, Target::MacOs, &LowerOptions::default())?;
//!
//! let answer = ex.explain(&Question::new(Op::Write, "/work/.git/hooks/pre-commit"), &Context::default())?;
//! assert_eq!(answer.decision, Decision::Denied);
//! assert_eq!(answer.by, Decider::HardDeny(HardDenyClass::TrustHandoff));
//! assert_eq!(answer.remedy.unwrap().changes, [Change::Waive(HardDenyClass::TrustHandoff)]);
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

mod diff;
mod linux;
mod macos;
pub(crate) mod regex;

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

pub use diff::{Diff, DiffEntry, Direction, PathSet, diff};
pub use linux::{GLOB_AT_SPAWN, PIECEWISE, SPAWN_COVER};

use crate::lower::{Construct, GapKind, LowerError, LowerOptions, Plan, Target, lower};
use crate::name::GrantName;
use crate::path::AbsPath;
use crate::policy::{Access, Base, FsRule, FsTarget, HardDenyClass, Policy};

/// An operation a question asks about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Op {
    /// Open a file for reading.
    Read,
    /// Open an existing file for writing (without truncating it).
    Write,
    /// Execute a file.
    Exec,
    /// Any other operation, by its Seatbelt operation or Landlock right
    /// name. Always answered [`Decision::NotModelled`].
    Other(String),
}

/// The operations [`Explainer::explain`] models, which the oracle suite
/// proves on every target.
pub const MODELLED: &[Op] = &[Op::Read, Op::Write, Op::Exec];

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::Read => f.write_str("read"),
            Op::Write => f.write_str("write"),
            Op::Exec => f.write_str("exec"),
            Op::Other(name) => f.write_str(name),
        }
    }
}

impl Op {
    fn access(&self) -> Option<Access> {
        match self {
            Op::Read => Some(Access::Read),
            Op::Write => Some(Access::Write),
            Op::Exec => Some(Access::Exec),
            Op::Other(_) => None,
        }
    }
}

/// A question: may the child perform `op` on `path`?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    /// The operation.
    pub op: Op,
    /// The path, which must be canonical for the target.
    pub path: Vec<u8>,
    /// The file's mode bits, for rules on set-user-ID files (default
    /// `0o755` for exec, `0o644` otherwise).
    pub mode: u32,
}

impl Question {
    /// A question about `op` on `path` with the default mode.
    pub fn new(op: Op, path: impl Into<Vec<u8>>) -> Self {
        let mode = if op == Op::Exec { 0o755 } else { 0o644 };
        Self {
            op,
            path: path.into(),
            mode,
        }
    }

    /// This question about a file with `mode`.
    pub fn with_mode(mut self, mode: u32) -> Self {
        self.mode = mode;
        self
    }
}

/// What a spawn binds and finds: the grants' paths and, on Linux, the homes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Context {
    /// Each grant and the canonical path it is bound to.
    pub grants: Vec<(GrantName, AbsPath)>,
    /// The homes whose class paths are covered (Linux).
    pub homes: Vec<AbsPath>,
}

impl Context {
    fn grant(&self, name: &str) -> Option<&AbsPath> {
        self.grants
            .iter()
            .find(|(n, _)| n.as_str() == name)
            .map(|(_, p)| p)
    }
}

/// The decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decision {
    /// The plan allows the operation.
    Allowed,
    /// The plan denies it.
    Denied,
    /// The operation, or a rule deciding it, is outside what is modelled.
    NotModelled,
}

/// The rule that decides a question.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Decider {
    /// A file rule of the policy (an allow, or a protect or hide rule).
    Rule(FsRule),
    /// A per-spawn grant.
    Grant(GrantName),
    /// A hard-deny class.
    HardDeny(HardDenyClass),
    /// The base profile.
    Base(Base),
    /// The raw Seatbelt or Linux layer.
    Layer,
    /// A policy setting, by name (`exec`, `network`, `ipc.posix_shm`, …).
    Setting(&'static str),
    /// Linux: the ruleset does not handle the right, so Landlock allows it.
    Unhandled,
    /// Nothing allows it: the default denies.
    Default,
    /// Not modelled: nothing decided.
    None,
}

/// An answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    /// Allowed, denied or not modelled.
    pub decision: Decision,
    /// The deciding rule.
    pub by: Decider,
    /// Set when the answer holds only for what existed at spawn.
    pub caveat: Option<&'static str>,
    /// For a denial: the narrowest change found that allows it.
    pub remedy: Option<Remedy>,
}

/// A change to a policy.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Change {
    /// Add this file rule.
    Add(FsRule),
    /// Remove this protect or hide rule.
    Remove(FsRule),
    /// Waive this hard-deny class.
    Waive(HardDenyClass),
}

/// What would allow a denied question, checked by lowering the changed
/// policy and asking again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remedy {
    /// The changes, applied in order.
    pub changes: Vec<Change>,
    /// Approximations the changed policy needs accepted by name.
    pub accept: Vec<Construct>,
    /// Everything the changes allow or deny besides the question.
    pub diff: Diff,
}

/// Why a question has no answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    /// The path is not canonical for the target; `canonical` is its
    /// canonical spelling (`None` for a relative path).
    NotCanonical {
        /// The canonical spelling.
        canonical: Option<AbsPath>,
    },
}

impl fmt::Display for ExplainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExplainError::NotCanonical { canonical: Some(p) } => {
                write!(f, "the path is not canonical; ask about {p}")
            }
            ExplainError::NotCanonical { canonical: None } => {
                f.write_str("the path is not absolute")
            }
        }
    }
}

impl core::error::Error for ExplainError {}

/// The macOS spellings that are links into `/private`.
const MACOS_ALIASES: &[&[u8]] = &[b"etc", b"tmp", b"var"];

/// `path` if it is canonical for `target`, else its canonical spelling.
fn canonical(target: Target, path: &[u8]) -> Result<AbsPath, ExplainError> {
    if path.first() != Some(&b'/') {
        return Err(ExplainError::NotCanonical { canonical: None });
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for part in path.split(|&b| b == b'/') {
        match part {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            _ => parts.push(part),
        }
    }
    if target == Target::MacOs && parts.first().is_some_and(|p| MACOS_ALIASES.contains(p)) {
        parts.insert(0, b"private");
    }
    let mut out = Vec::with_capacity(path.len() + 8);
    for part in &parts {
        out.push(b'/');
        out.extend_from_slice(part);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    let canonical =
        AbsPath::new(out).map_err(|_| ExplainError::NotCanonical { canonical: None })?;
    if canonical.as_bytes() == path {
        Ok(canonical)
    } else {
        Err(ExplainError::NotCanonical {
            canonical: Some(canonical),
        })
    }
}

/// A decision before the remedy.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Verdict {
    decision: Decision,
    by: Decider,
    caveat: Option<&'static str>,
}

impl Verdict {
    fn not_modelled() -> Self {
        Verdict {
            decision: Decision::NotModelled,
            by: Decider::None,
            caveat: None,
        }
    }
}

#[derive(Debug, Clone)]
enum Model {
    MacOs(macos::Model),
    Linux(alloc::boxed::Box<linux::Model>),
}

/// Answers questions about one policy on one target.
#[derive(Debug, Clone)]
pub struct Explainer {
    policy: Policy,
    target: Target,
    options: LowerOptions,
    model: Model,
}

/// The most changes a remedy combines.
const MAX_CHANGES: usize = 3;

impl Explainer {
    /// Lowers `policy` for `target` with `options`.
    pub fn new(
        policy: &Policy,
        target: Target,
        options: &LowerOptions,
    ) -> Result<Self, LowerError> {
        let plan = lower(policy, target, options)?;
        let model = match plan {
            Plan::Seatbelt(_) => Model::MacOs(macos::Model::new(policy, options)?),
            Plan::Linux(plan) => {
                Model::Linux(alloc::boxed::Box::new(linux::Model::new(policy, plan)))
            }
        };
        Ok(Self {
            policy: policy.clone(),
            target,
            options: options.clone(),
            model,
        })
    }

    /// The target.
    pub fn target(&self) -> Target {
        self.target
    }

    /// Answers `question` for a spawn with `context`.
    pub fn explain(&self, question: &Question, context: &Context) -> Result<Answer, ExplainError> {
        let path = canonical(self.target, &question.path)?;
        let verdict = self.decide(&question.op, &path, question.mode, context);
        let remedy = if verdict.decision == Decision::Denied {
            self.remedy(question, &path, context, &verdict)
        } else {
            None
        };
        Ok(Answer {
            decision: verdict.decision,
            by: verdict.by,
            caveat: verdict.caveat,
            remedy,
        })
    }

    fn decide(&self, op: &Op, path: &AbsPath, mode: u32, context: &Context) -> Verdict {
        if !MODELLED.contains(op) {
            return Verdict::not_modelled();
        }
        match &self.model {
            Model::MacOs(m) => m.decide(op, path, mode, context),
            Model::Linux(m) => m.decide(op, path, context),
        }
    }

    fn remedy(
        &self,
        question: &Question,
        path: &AbsPath,
        context: &Context,
        verdict: &Verdict,
    ) -> Option<Remedy> {
        let access = question.op.access()?;
        let mut policy = self.policy.clone();
        let mut options = self.options.clone();
        let mut changes = Vec::new();
        let mut accept = Vec::new();
        let mut by = verdict.by.clone();
        while changes.len() < MAX_CHANGES {
            let change = match &by {
                Decider::Default | Decider::Base(_) => {
                    Change::Add(FsRule::new(access, FsTarget::Literal(path.clone())))
                }
                Decider::HardDeny(class) => Change::Waive(*class),
                Decider::Rule(rule) if matches!(rule.access, Access::Protect | Access::Hide) => {
                    Change::Remove(rule.clone())
                }
                _ => return None,
            };
            if changes.contains(&change) {
                return None;
            }
            match &change {
                Change::Add(rule) => policy.fs.push(rule.clone()),
                Change::Remove(rule) => policy.fs.retain(|r| r != rule),
                Change::Waive(class) => {
                    policy.waive.insert(*class);
                }
            }
            changes.push(change);
            let next = loop {
                match Explainer::new(&policy, self.target, &options) {
                    Ok(next) => break next,
                    Err(LowerError::Gaps(gaps))
                        if gaps.iter().all(|g| g.kind == GapKind::Approximation) =>
                    {
                        for gap in gaps {
                            if accept.contains(&gap.construct) {
                                return None;
                            }
                            accept.push(gap.construct);
                            options.allow_degrade.insert(gap.construct);
                        }
                    }
                    Err(_) => return None,
                }
            };
            let after = next.decide(&question.op, path, question.mode, context);
            match after.decision {
                Decision::Allowed => {
                    let diff = diff(&self.policy, &policy, &[self.target], &options).ok()?;
                    return Some(Remedy {
                        changes,
                        accept,
                        diff,
                    });
                }
                Decision::Denied => by = after.by,
                Decision::NotModelled => return None,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn canonical_forms() {
        let ok = |t, p: &str| canonical(t, p.as_bytes()).unwrap();
        let named = |t, p: &str| match canonical(t, p.as_bytes()) {
            Err(ExplainError::NotCanonical { canonical }) => canonical.map(|c| c.to_string()),
            Ok(_) => panic!("{p} accepted"),
        };
        let linux = Target::Linux {
            tier: crate::Tier::T2,
            landlock_abi: 6,
        };
        assert_eq!(
            ok(Target::MacOs, "/private/etc/hosts").to_string(),
            "/private/etc/hosts"
        );
        assert_eq!(ok(linux, "/etc/hosts").to_string(), "/etc/hosts");
        assert_eq!(ok(linux, "/").to_string(), "/");
        assert_eq!(
            named(Target::MacOs, "/etc/hosts").as_deref(),
            Some("/private/etc/hosts")
        );
        assert_eq!(
            named(Target::MacOs, "/tmp").as_deref(),
            Some("/private/tmp")
        );
        assert_eq!(named(linux, "/a/../b").as_deref(), Some("/b"));
        assert_eq!(named(linux, "/a//b/./c/").as_deref(), Some("/a/b/c"));
        assert_eq!(named(linux, "/..").as_deref(), Some("/"));
        assert_eq!(named(linux, "a/b"), None);
        assert_eq!(named(linux, ""), None);
    }
}
