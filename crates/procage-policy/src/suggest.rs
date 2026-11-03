//! Suggestions: the narrowest change to a policy that would allow one
//! denied operation on the next spawn.
//!
//! A suggestion never changes a running child: [`Suggestion::apply`]
//! returns a new policy, and the caller spawns again with it. The caller
//! decides whether to apply one; procage neither asks nor remembers.
//! `procage::suggest` derives a suggestion from a reported violation.

use core::fmt;

use crate::explain::regex::Regex;
use crate::path::AbsPath;
use crate::policy::{Access, FsRule, FsTarget, HardDenyClass, Policy, Signals};

/// One policy change. [`Suggestion::weakens`] says whether it lifts a
/// protection rather than granting.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(rename_all = "kebab-case")
)]
#[non_exhaustive]
pub enum Suggestion {
    /// Add this rule: a literal path with read, write or exec access.
    Allow(FsRule),
    /// Add this path to `ipc.unix_sockets`.
    UnixSocket(AbsPath),
    /// Remove this protect or hide rule (weakens a protection).
    LeaveOut(FsRule),
    /// Waive this hard-deny class (weakens a hard deny).
    Waive(HardDenyClass),
    /// Let signals reach every process of the user (weakens).
    SignalsSameUser,
}

impl Suggestion {
    /// Whether the change lifts a protection, a hard deny or the signal
    /// scope rather than granting a path.
    pub fn weakens(&self) -> bool {
        !matches!(self, Suggestion::Allow(_) | Suggestion::UnixSocket(_))
    }

    /// `policy` with exactly this change. The policy given is not changed.
    pub fn apply(&self, policy: &Policy) -> Policy {
        let mut out = policy.clone();
        match self {
            Suggestion::Allow(rule) => out.fs.push(rule.clone()),
            Suggestion::UnixSocket(path) => out.ipc.unix_sockets.push(path.clone()),
            Suggestion::LeaveOut(rule) => {
                if let Some(i) = out.fs.iter().position(|r| r == rule) {
                    out.fs.remove(i);
                }
            }
            Suggestion::Waive(class) => {
                out.waive.insert(*class);
            }
            Suggestion::SignalsSameUser => out.process.signals = Signals::SameUser,
        }
        out
    }
}

impl fmt::Display for Suggestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Suggestion::Allow(rule) => {
                let verb = match rule.access {
                    Access::Read => "reading",
                    Access::Write => "writing",
                    Access::Exec => "executing",
                    Access::Protect | Access::Hide => "using",
                };
                write!(f, "allow {verb} {}", Target(&rule.target))
            }
            Suggestion::UnixSocket(path) => write!(f, "allow connecting to the Unix socket {path}"),
            Suggestion::LeaveOut(rule) => {
                let kind = match rule.access {
                    Access::Hide => "hide",
                    _ => "protect",
                };
                write!(
                    f,
                    "leave out the {kind} rule on {} (weakens a protection)",
                    Target(&rule.target)
                )
            }
            Suggestion::Waive(class) => {
                write!(f, "waive the {class} class (weakens a hard deny)")
            }
            Suggestion::SignalsSameUser => f.write_str(
                "let signals reach every process of the user (weakens the signal scope)",
            ),
        }
    }
}

struct Target<'a>(&'a FsTarget);

impl fmt::Display for Target<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            FsTarget::Literal(p) => write!(f, "{p}"),
            FsTarget::Subpath(p) => write!(f, "{p} and below"),
            FsTarget::Glob(g) => write!(f, "{g}"),
        }
    }
}

/// Whether `rule`'s target covers `path`: an equal literal, a subpath above
/// it, or a glob matching it.
pub fn covers(rule: &FsRule, path: &AbsPath) -> bool {
    match &rule.target {
        FsTarget::Literal(p) => p == path,
        FsTarget::Subpath(p) => path.starts_with_path(p),
        FsTarget::Glob(g) => {
            Regex::new(&g.to_sbpl_regex()).is_some_and(|re| re.is_match(path.as_bytes()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::glob::Glob;
    use alloc::string::ToString;

    fn abs(p: &str) -> AbsPath {
        AbsPath::new(p).unwrap()
    }

    fn literal(access: Access, p: &str) -> FsRule {
        FsRule::new(access, FsTarget::Literal(abs(p)))
    }

    #[test]
    fn apply_changes_exactly_one_thing() {
        let mut p = Policy::default();
        p.fs.push(literal(Access::Protect, "/w/.git"));
        p.fs.push(FsRule::new(Access::Write, FsTarget::Subpath(abs("/w"))));
        let grant = literal(Access::Write, "/o/f");
        let cases = [
            (Suggestion::Allow(grant.clone()), {
                let mut q = p.clone();
                q.fs.push(grant.clone());
                q
            }),
            (Suggestion::UnixSocket(abs("/s")), {
                let mut q = p.clone();
                q.ipc.unix_sockets.push(abs("/s"));
                q
            }),
            (Suggestion::LeaveOut(literal(Access::Protect, "/w/.git")), {
                let mut q = p.clone();
                q.fs.remove(0);
                q
            }),
            (Suggestion::Waive(HardDenyClass::TrustHandoff), {
                let mut q = p.clone();
                q.waive.insert(HardDenyClass::TrustHandoff);
                q
            }),
            (Suggestion::SignalsSameUser, {
                let mut q = p.clone();
                q.process.signals = Signals::SameUser;
                q
            }),
        ];
        for (s, want) in cases {
            assert_eq!(s.apply(&p), want, "{s}");
            assert_ne!(s.apply(&p), p, "{s}");
        }
    }

    #[test]
    fn only_grants_do_not_weaken() {
        assert!(!Suggestion::Allow(literal(Access::Read, "/f")).weakens());
        assert!(!Suggestion::UnixSocket(abs("/s")).weakens());
        assert!(Suggestion::LeaveOut(literal(Access::Hide, "/f")).weakens());
        assert!(Suggestion::Waive(HardDenyClass::Persistence).weakens());
        assert!(Suggestion::SignalsSameUser.weakens());
    }

    #[test]
    fn sentences() {
        assert_eq!(
            Suggestion::Allow(literal(Access::Write, "/o/f")).to_string(),
            "allow writing /o/f"
        );
        assert_eq!(
            Suggestion::Waive(HardDenyClass::TrustHandoff).to_string(),
            "waive the trust-handoff class (weakens a hard deny)"
        );
    }

    #[test]
    fn covering_rules() {
        let a = literal(Access::Protect, "/w/a");
        let d = FsRule::new(Access::Protect, FsTarget::Subpath(abs("/w/d")));
        let pem = FsRule::new(
            Access::Hide,
            FsTarget::Glob(Glob::new("/w/**/*.pem").unwrap()),
        );
        assert!(covers(&a, &abs("/w/a")));
        assert!(!covers(&a, &abs("/w/a/b")));
        assert!(covers(&d, &abs("/w/d/x/y")));
        assert!(!covers(&d, &abs("/w/dd")));
        assert!(covers(&pem, &abs("/w/k/c.pem")));
        assert!(!covers(&pem, &abs("/w/k/c.txt")));
    }
}
