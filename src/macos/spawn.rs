//! Preparing a spawn in the parent: grant tokens, the environment, resource
//! limits, and decoding a failed step.

use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::io;
use std::process::Command;

use procage_policy::{EnvPolicy, Rlimits};

use super::{Cage, GrantError, SpawnError, Step, canon, sys};

/// Issues one token per binding, for declared grants and existing paths.
pub(super) fn tokens(
    lib: &sys::Libsandbox,
    cage: &Cage,
    grants: &super::Grants,
) -> Result<Vec<CString>, SpawnError> {
    let mut out = Vec::with_capacity(grants.bindings.len());
    for (name, path) in &grants.bindings {
        let slot = cage
            .grant_slot(name)
            .ok_or_else(|| SpawnError::Grant(GrantError::Undeclared { name: name.clone() }))?;
        let resolved = canon::resolve_existing(path).map_err(|error| {
            SpawnError::Grant(GrantError::Missing {
                name: name.clone(),
                path: path.clone(),
                error,
            })
        })?;
        let token = lib
            .issue_file(&slot.class, resolved.as_bytes())
            .ok_or_else(|| {
                SpawnError::Grant(GrantError::Issue {
                    name: name.clone(),
                    path: resolved.to_string(),
                })
            })?;
        out.push(token);
    }
    Ok(out)
}

/// Sets the command's environment to what the policy yields, keeping the
/// variables the caller set (or removed) explicitly on the command.
pub(super) fn environment(command: &mut Command, policy: &EnvPolicy) {
    let explicit: Vec<(OsString, Option<OsString>)> = command
        .get_envs()
        .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
        .collect();
    command.env_clear();
    match policy {
        EnvPolicy::Allowlist(names) => {
            for name in names {
                if let Some(value) = std::env::var_os(name) {
                    command.env(name, value);
                }
            }
        }
        EnvPolicy::Passthrough { deny } => {
            let deny: BTreeSet<&str> = deny.iter().map(String::as_str).collect();
            for (key, value) in std::env::vars_os() {
                if !key.to_str().is_some_and(|k| deny.contains(k)) {
                    command.env(key, value);
                }
            }
        }
    }
    for (key, value) in explicit {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
}

/// The `setrlimit` calls for the policy's limits. The core size is always
/// set (0 by default).
pub(super) fn limits(limits: &Rlimits) -> Vec<(libc::c_int, u64, u64)> {
    let mut out = Vec::new();
    for (resource, value) in [
        (libc::RLIMIT_NPROC, limits.nproc),
        (libc::RLIMIT_CPU, limits.cpu_seconds),
        (libc::RLIMIT_FSIZE, limits.fsize_bytes),
        (libc::RLIMIT_NOFILE, limits.nofile),
        (libc::RLIMIT_CORE, Some(limits.core_bytes)),
    ] {
        if let Some(value) = value {
            out.push((resource, value, value));
        }
    }
    out
}

/// Turns a spawn error carrying a step code into [`SpawnError::Apply`].
pub(super) fn decode(error: io::Error) -> SpawnError {
    if let Some((step, errno)) = error.raw_os_error().and_then(sys::decode_step)
        && let Some(step) = Step::from_code(step)
    {
        return SpawnError::Apply { step, errno };
    }
    SpawnError::Io(error)
}
