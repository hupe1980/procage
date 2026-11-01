//! Preparing a spawn in the parent: grant tokens and decoding a failed step.

use std::ffi::CString;
use std::io;

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

/// Turns a spawn error carrying a step code into [`SpawnError::Apply`].
pub(super) fn decode(error: io::Error) -> SpawnError {
    if let Some((step, errno)) = error.raw_os_error().and_then(sys::decode_step)
        && let Some(step) = Step::from_code(step)
    {
        return SpawnError::Apply { step, errno };
    }
    SpawnError::Io(error)
}
