//! From a reported denial to a policy change the caller may approve.

use std::path::Path;

use procage_policy::path::AbsPath;
use procage_policy::suggest::covers;
use procage_policy::{Access, FsRule, FsTarget, HardDenyClass, Policy, Signals, Suggestion};

use crate::violation::{DeniedBy, Violation};

/// The narrowest change to `policy` that would allow the operation
/// `violation` reports on the next spawn, or `None`.
///
/// - Not granted: a literal rule on the denied path with the operation's
///   access (read, write or exec), the socket path for a denied connect,
///   or wider signals for a denied signal.
/// - A hard-deny class: its waiver, except `secrets`, which yields none.
/// - A protect or hide rule: leaving out that rule, when exactly one rule
///   of the policy covers the path.
/// - The raw layer, `Lifetime::Run`, the older-kernel guard, the proxy and
///   unknown kinds: none, as for denials without a path where one is
///   needed.
///
/// Apply it with [`Suggestion::apply`] and spawn again: a running child is
/// never widened. [`Suggestion::weakens`] marks the changes that lift a
/// protection rather than grant a path.
///
/// The child chooses what it attempts, so it can provoke denials meant to
/// draw an approval (a shell start-up file, a hook directory). Show the
/// suggestion as it is ([`Suggestion`] displays as a sentence naming the
/// path and the access) and treat a weakening one as such. On Linux only
/// seccomp denials are reported, so file suggestions come from macOS.
pub fn suggest(policy: &Policy, violation: &Violation) -> Option<Suggestion> {
    let path = violation
        .target
        .as_deref()
        .and_then(|t| AbsPath::new(t).ok());
    let op = violation.operation.as_str();
    match &violation.denied_by {
        DeniedBy::NotGranted if op.starts_with("signal") => {
            (policy.process.signals != Signals::SameUser).then_some(Suggestion::SignalsSameUser)
        }
        DeniedBy::NotGranted => {
            let path = path?;
            let access = if op.starts_with("file-read") {
                Access::Read
            } else if op.starts_with("file-write") {
                Access::Write
            } else if op.starts_with("process-exec") || op == "file-map-executable" {
                Access::Exec
            } else if op == "network-outbound" {
                return Some(Suggestion::UnixSocket(path));
            } else {
                return None;
            };
            Some(Suggestion::Allow(FsRule::new(
                access,
                FsTarget::Literal(path),
            )))
        }
        DeniedBy::HardDeny(HardDenyClass::Secrets) => None,
        DeniedBy::HardDeny(class) => Some(Suggestion::Waive(*class)),
        DeniedBy::Protect => leave_out(policy, Access::Protect, &path?),
        DeniedBy::Hide => leave_out(policy, Access::Hide, &path?),
        _ => None,
    }
}

/// Leaving out the one protect or hide rule that covers `path`, as written
/// or with its path resolved (the kernel reports resolved paths).
fn leave_out(policy: &Policy, access: Access, path: &AbsPath) -> Option<Suggestion> {
    let found: Vec<&FsRule> = policy
        .fs
        .iter()
        .filter(|r| r.access == access)
        .filter(|r| covers(r, path) || resolved(r).is_some_and(|r| covers(&r, path)))
        .collect();
    match found.as_slice() {
        [rule] => Some(Suggestion::LeaveOut((*rule).clone())),
        _ => None,
    }
}

/// `rule` with a literal or subpath target resolved, when it exists.
fn resolved(rule: &FsRule) -> Option<FsRule> {
    let resolve = |p: &AbsPath| {
        let real = std::fs::canonicalize(Path::new(&*p.to_string())).ok()?;
        AbsPath::new(&*real.to_string_lossy()).ok()
    };
    let target = match &rule.target {
        FsTarget::Literal(p) => FsTarget::Literal(resolve(p)?),
        FsTarget::Subpath(p) => FsTarget::Subpath(resolve(p)?),
        FsTarget::Glob(_) => return None,
    };
    Some(FsRule::new(rule.access, target))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    fn abs(p: &str) -> AbsPath {
        AbsPath::new(p).unwrap()
    }

    fn denial(operation: &str, target: Option<&str>, denied_by: DeniedBy) -> Violation {
        Violation {
            pid: 1,
            process: "t".into(),
            operation: operation.into(),
            target: target.map(String::from),
            denied_by,
            received: SystemTime::UNIX_EPOCH,
            repeats: 1,
        }
    }

    #[test]
    fn grants_are_literal_with_the_operations_access() {
        let p = Policy::default();
        for (op, access) in [
            ("file-read-data", Access::Read),
            ("file-write-create", Access::Write),
            ("file-write-unlink", Access::Write),
            ("process-exec*", Access::Exec),
            ("file-map-executable", Access::Exec),
        ] {
            assert_eq!(
                suggest(&p, &denial(op, Some("/o/f"), DeniedBy::NotGranted)),
                Some(Suggestion::Allow(FsRule::new(
                    access,
                    FsTarget::Literal(abs("/o/f"))
                ))),
                "{op}"
            );
        }
        assert_eq!(
            suggest(
                &p,
                &denial("network-outbound", Some("/s.sock"), DeniedBy::NotGranted)
            ),
            Some(Suggestion::UnixSocket(abs("/s.sock")))
        );
    }

    #[test]
    fn nothing_without_a_safe_change() {
        let p = Policy::default();
        for d in [
            denial(
                "file-read-data",
                Some("/h/.env"),
                DeniedBy::HardDeny(HardDenyClass::Secrets),
            ),
            denial("file-read-data", None, DeniedBy::NotGranted),
            denial("file-read-data", Some("relative"), DeniedBy::NotGranted),
            denial("mach-lookup", Some("com.apple.x"), DeniedBy::NotGranted),
            denial(
                "network-outbound",
                Some("example.com:443"),
                DeniedBy::Allowlist,
            ),
            denial("setsid", None, DeniedBy::Lifetime),
            denial("file-write-data", Some("/f"), DeniedBy::Layer),
            denial("ftruncate", None, DeniedBy::OlderKernel),
            denial("x", Some("/f"), DeniedBy::Unknown("z".into())),
            // No protect rule covers it.
            denial("file-write-data", Some("/w/f"), DeniedBy::Protect),
        ] {
            assert_eq!(suggest(&p, &d), None, "{d:?}");
        }
    }

    #[test]
    fn weakening_changes() {
        let mut p = Policy::default();
        let protect = FsRule::new(Access::Protect, FsTarget::Subpath(abs("/w/.git")));
        let hide = FsRule::new(Access::Hide, FsTarget::Literal(abs("/w/k")));
        p.fs.extend([protect.clone(), hide.clone()]);
        let cases = [
            (
                denial("file-write-data", Some("/w/.git/f"), DeniedBy::Protect),
                Suggestion::LeaveOut(protect),
            ),
            (
                denial("file-read-data", Some("/w/k"), DeniedBy::Hide),
                Suggestion::LeaveOut(hide),
            ),
            (
                denial(
                    "file-write-create",
                    Some("/w/.git/hooks/x"),
                    DeniedBy::HardDeny(HardDenyClass::TrustHandoff),
                ),
                Suggestion::Waive(HardDenyClass::TrustHandoff),
            ),
            (
                denial("signal", Some("1"), DeniedBy::NotGranted),
                Suggestion::SignalsSameUser,
            ),
        ];
        for (d, want) in cases {
            let got = suggest(&p, &d).unwrap();
            assert_eq!(got, want);
            assert!(got.weakens(), "{got}");
        }
    }

    #[test]
    fn two_covering_rules_give_none() {
        let mut p = Policy::default();
        p.fs.push(FsRule::new(Access::Protect, FsTarget::Subpath(abs("/w"))));
        p.fs.push(FsRule::new(Access::Protect, FsTarget::Literal(abs("/w/f"))));
        let d = denial("file-write-data", Some("/w/f"), DeniedBy::Protect);
        assert_eq!(suggest(&p, &d), None);
    }
}
