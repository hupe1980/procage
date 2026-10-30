//! Preparing a spawn in the parent: grant tokens, the environment, resource
//! limits, and decoding a failed step.

use std::ffi::{CString, OsString};
use std::io;
use std::path::PathBuf;
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

/// Sets the command's environment to what the policy yields (see
/// [`crate::hygiene::environment`]); returns the names the passthrough
/// denylist dropped.
pub(super) fn environment(command: &mut Command, policy: &EnvPolicy) -> Vec<String> {
    let explicit: Vec<(OsString, Option<OsString>)> = command
        .get_envs()
        .map(|(k, v)| (k.to_owned(), v.map(|v| v.to_owned())))
        .collect();
    let decision = crate::hygiene::environment(std::env::vars_os(), policy, &explicit);
    command.env_clear();
    command.envs(decision.set);
    decision.dropped
}

/// A fresh directory, accessible only to the user, under the caller's
/// temporary directory.
pub(super) fn private_tmpdir() -> io::Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let base = std::fs::canonicalize(std::env::temp_dir())?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    let dir = base.join(format!(
        "procage-{}-{}-{nanos}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
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
