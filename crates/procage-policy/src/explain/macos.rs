//! Questions against the emitted Seatbelt rules.
//!
//! The profile is `(deny default)` followed by the rules in blocks; the last
//! rule that matches an operation decides it. Inside a block every rule has
//! the same effect, so neither the order there nor merging changes a
//! decision, and the tagged rules can be read before either happens.

use alloc::string::String;
use alloc::vec::Vec;

use super::regex::Regex;
use super::{Context, Decider, Decision, Op, Verdict};
use crate::lower::{LowerError, LowerOptions};
use crate::path::AbsPath;
use crate::policy::Policy;
use crate::sbpl::Filter;
use crate::seatbelt::Effect;

/// How a filter of a rule matches a file question.
#[derive(Debug, Clone)]
pub(super) enum Matcher {
    Literal(Vec<u8>),
    Subpath(Vec<u8>),
    Regex(Regex),
    /// `path-ancestors`: the value and every directory above it.
    Ancestors(Vec<u8>),
    /// A grant's extension.
    Grant(String),
    /// `file-mode`: the file has these mode bits.
    Mode(u32),
    /// Any other filter: it never applies to a file, or cannot be judged.
    Unknown,
}

pub(super) fn subpath(path: &[u8], base: &[u8]) -> bool {
    base == b"/"
        || path == base
        || (path.len() > base.len() && path.starts_with(base) && path[base.len()] == b'/')
}

impl Matcher {
    pub(super) fn of(filter: &Filter) -> Matcher {
        match filter {
            Filter::Literal(v) => Matcher::Literal(v.clone()),
            Filter::Subpath(v) => Matcher::Subpath(v.clone()),
            Filter::Regex(r) => Regex::new(r).map_or(Matcher::Unknown, Matcher::Regex),
            Filter::PathAncestors(v) => Matcher::Ancestors(v.clone()),
            Filter::Extension(class) => class
                .strip_prefix("procage.")
                .map_or(Matcher::Unknown, |n| Matcher::Grant(n.into())),
            Filter::FileMode(bits) => Matcher::Mode(*bits),
            _ => Matcher::Unknown,
        }
    }

    /// `Some(matched)`, or `None` when it cannot be judged.
    pub(super) fn matches(&self, path: &[u8], mode: u32, context: &Context) -> Option<bool> {
        Some(match self {
            Matcher::Literal(v) => path == v.as_slice(),
            Matcher::Subpath(v) => subpath(path, v),
            Matcher::Regex(r) => r.is_match(path),
            Matcher::Ancestors(v) => subpath(v, path),
            Matcher::Grant(name) => context
                .grant(name)
                .is_some_and(|g| subpath(path, g.as_bytes())),
            Matcher::Mode(bits) => mode & bits == *bits,
            Matcher::Unknown => return None,
        })
    }
}

/// Whether a rule's operation name covers `op`.
pub(super) fn op_matches(rule_op: &str, op: &str) -> bool {
    match rule_op.strip_suffix('*') {
        Some(prefix) => op.starts_with(prefix),
        None => rule_op == op,
    }
}

/// The Seatbelt operation a modelled question checks.
pub(super) fn sbpl_op(op: &Op) -> &'static str {
    match op {
        Op::Read => "file-read-data",
        Op::Write => "file-write-data",
        Op::Exec | Op::Other(_) => "process-exec",
    }
}

#[derive(Debug, Clone)]
struct Entry {
    effect: Effect,
    ops: Vec<String>,
    filters: Vec<Matcher>,
    by: Decider,
}

#[derive(Debug, Clone)]
pub(super) struct Model {
    /// In profile order.
    entries: Vec<Entry>,
}

impl Model {
    pub(super) fn new(policy: &Policy, options: &LowerOptions) -> Result<Model, LowerError> {
        let emitted = crate::lower::macos::emit(policy, options)?;
        let entries = emitted
            .blocks
            .into_iter()
            .flatten()
            .map(|(rule, by)| Entry {
                effect: rule.effect,
                filters: rule.filters.iter().map(Matcher::of).collect(),
                ops: rule.ops,
                by,
            })
            .collect();
        Ok(Model { entries })
    }

    pub(super) fn decide(&self, op: &Op, path: &AbsPath, mode: u32, context: &Context) -> Verdict {
        let name = sbpl_op(op);
        for entry in self.entries.iter().rev() {
            if !entry.ops.iter().any(|o| op_matches(o, name)) {
                continue;
            }
            let matched = if entry.filters.is_empty() {
                Some(true)
            } else {
                let mut unknown = false;
                let mut any = false;
                for f in &entry.filters {
                    match f.matches(path.as_bytes(), mode, context) {
                        Some(true) => {
                            any = true;
                            break;
                        }
                        Some(false) => {}
                        None => unknown = true,
                    }
                }
                if any {
                    Some(true)
                } else if unknown {
                    None
                } else {
                    Some(false)
                }
            };
            match matched {
                Some(true) => {
                    return Verdict {
                        decision: match entry.effect {
                            Effect::Allow => Decision::Allowed,
                            Effect::Deny => Decision::Denied,
                        },
                        by: entry.by.clone(),
                        caveat: None,
                    };
                }
                Some(false) => {}
                None => return Verdict::not_modelled(),
            }
        }
        Verdict {
            decision: Decision::Denied,
            by: Decider::Default,
            caveat: None,
        }
    }
}
