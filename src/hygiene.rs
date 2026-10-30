//! Process hygiene shared by every backend.
//!
//! [`environment`] computes the child's environment from the caller's, the
//! policy's [`EnvPolicy`] and the variables set explicitly on the command. It
//! is a pure function: the backends apply its result.
//!
//! With [`EnvPolicy::Passthrough`], variables that commonly carry secrets or
//! inject code are dropped even when the policy does not name them:
//!
//! - names starting with `DYLD_` or `AWS_`;
//! - `LD_PRELOAD`, `LD_LIBRARY_PATH` and `SSH_AUTH_SOCK`;
//! - names ending in `_TOKEN`, `_SECRET`, `_PASSWORD` or `_API_KEY`.
//!
//! A variable set explicitly on the command is always kept. An
//! [`EnvPolicy::Allowlist`] is taken as written, because the caller named
//! every variable in it.

use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};

use procage_policy::EnvPolicy;

/// Name prefixes dropped under passthrough.
pub const DROPPED_PREFIXES: &[&str] = &["DYLD_", "AWS_"];
/// Exact names dropped under passthrough.
pub const DROPPED_NAMES: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH", "SSH_AUTH_SOCK"];
/// Name suffixes dropped under passthrough.
pub const DROPPED_SUFFIXES: &[&str] = &["_TOKEN", "_SECRET", "_PASSWORD", "_API_KEY"];

/// Whether passthrough drops `name` by default.
pub fn dropped_by_default(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    DROPPED_PREFIXES.iter().any(|p| name.starts_with(p))
        || DROPPED_NAMES.contains(&name)
        || DROPPED_SUFFIXES.iter().any(|s| name.ends_with(s))
}

/// The child's environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EnvDecision {
    /// The variables the child receives, sorted by name.
    pub set: Vec<(OsString, OsString)>,
    /// Names from the caller's environment that the default denylist
    /// dropped, sorted.
    pub dropped: Vec<String>,
}

/// Computes the child's environment.
///
/// `explicit` holds the variables set (`Some`) or removed (`None`) on the
/// command; they win over the policy.
pub fn environment(
    caller: impl IntoIterator<Item = (OsString, OsString)>,
    policy: &EnvPolicy,
    explicit: &[(OsString, Option<OsString>)],
) -> EnvDecision {
    let mut set: Vec<(OsString, OsString)> = Vec::new();
    let mut dropped = Vec::new();
    match policy {
        EnvPolicy::Allowlist(names) => {
            let names: BTreeSet<&str> = names.iter().map(String::as_str).collect();
            set.extend(
                caller
                    .into_iter()
                    .filter(|(k, _)| k.to_str().is_some_and(|k| names.contains(k))),
            );
        }
        EnvPolicy::Passthrough { deny } => {
            let deny: BTreeSet<&str> = deny.iter().map(String::as_str).collect();
            for (key, value) in caller {
                if key.to_str().is_some_and(|k| deny.contains(k)) {
                    continue;
                }
                if dropped_by_default(&key) {
                    dropped.push(key.to_string_lossy().into_owned());
                    continue;
                }
                set.push((key, value));
            }
        }
    }
    for (key, value) in explicit {
        set.retain(|(k, _)| k != key);
        if let Some(value) = value {
            set.push((key.clone(), value.clone()));
        }
    }
    let explicitly_set: BTreeSet<&OsStr> = explicit
        .iter()
        .filter(|(_, v)| v.is_some())
        .map(|(k, _)| k.as_os_str())
        .collect();
    dropped.retain(|name| !explicitly_set.contains(OsStr::new(name)));
    set.sort();
    dropped.sort();
    dropped.dedup();
    EnvDecision { set, dropped }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller() -> Vec<(OsString, OsString)> {
        [
            ("PATH", "/bin"),
            ("HOME", "/home/u"),
            ("GITHUB_TOKEN", "t"),
            ("SSH_AUTH_SOCK", "/s"),
            ("DYLD_INSERT_LIBRARIES", "/x.dylib"),
            ("AWS_PROFILE", "p"),
            ("DB_PASSWORD", "pw"),
            ("OPENAI_API_KEY", "k"),
            ("LD_PRELOAD", "/y.so"),
            ("MY_SECRET", "s"),
        ]
        .into_iter()
        .map(|(k, v)| (k.into(), v.into()))
        .collect()
    }

    fn names(d: &EnvDecision) -> Vec<String> {
        d.set
            .iter()
            .map(|(k, _)| k.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn passthrough_drops_the_default_denylist_and_reports_it() {
        let d = environment(caller(), &EnvPolicy::Passthrough { deny: vec![] }, &[]);
        assert_eq!(names(&d), ["HOME", "PATH"]);
        assert_eq!(
            d.dropped,
            [
                "AWS_PROFILE",
                "DB_PASSWORD",
                "DYLD_INSERT_LIBRARIES",
                "GITHUB_TOKEN",
                "LD_PRELOAD",
                "MY_SECRET",
                "OPENAI_API_KEY",
                "SSH_AUTH_SOCK"
            ]
        );
    }

    #[test]
    fn the_policy_deny_list_is_not_reported_as_a_default_drop() {
        let d = environment(
            caller(),
            &EnvPolicy::Passthrough {
                deny: vec!["HOME".into(), "GITHUB_TOKEN".into()],
            },
            &[],
        );
        assert_eq!(names(&d), ["PATH"]);
        assert!(!d.dropped.contains(&"GITHUB_TOKEN".to_string()));
    }

    #[test]
    fn an_allowlist_is_taken_as_written() {
        let policy = EnvPolicy::Allowlist(vec!["PATH".into(), "GITHUB_TOKEN".into()]);
        let d = environment(caller(), &policy, &[]);
        assert_eq!(names(&d), ["GITHUB_TOKEN", "PATH"]);
        assert!(d.dropped.is_empty());
    }

    #[test]
    fn explicit_variables_win() {
        let explicit = vec![
            (
                OsString::from("GITHUB_TOKEN"),
                Some(OsString::from("explicit")),
            ),
            (OsString::from("HOME"), None),
        ];
        let d = environment(
            caller(),
            &EnvPolicy::Passthrough { deny: vec![] },
            &explicit,
        );
        assert!(d.set.contains(&("GITHUB_TOKEN".into(), "explicit".into())));
        assert!(!names(&d).contains(&"HOME".to_string()));
        assert!(!d.dropped.contains(&"GITHUB_TOKEN".to_string()));
        let d = environment(caller(), &EnvPolicy::default(), &explicit);
        assert_eq!(names(&d), ["GITHUB_TOKEN"]);
    }
}
