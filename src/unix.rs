//! Spawn preparation shared by the macOS and Linux backends: the
//! environment, the private temporary directory and resource limits.

use std::ffi::OsString;
use std::io;
use std::path::PathBuf;
use std::process::Command;

use procage_policy::{EnvPolicy, Rlimits};

/// Sets the command's environment to what the policy yields (see
/// [`crate::hygiene::environment`]); returns the names the passthrough
/// denylist dropped.
pub(crate) fn environment(command: &mut Command, policy: &EnvPolicy) -> Vec<String> {
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
pub(crate) fn private_tmpdir() -> io::Result<PathBuf> {
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
pub(crate) fn limits(limits: &Rlimits) -> Vec<(libc::c_int, u64, u64)> {
    let mut out = Vec::new();
    for (resource, value) in [
        (libc::RLIMIT_NPROC, limits.nproc),
        (libc::RLIMIT_CPU, limits.cpu_seconds),
        (libc::RLIMIT_FSIZE, limits.fsize_bytes),
        (libc::RLIMIT_NOFILE, limits.nofile),
        (libc::RLIMIT_CORE, Some(limits.core_bytes)),
    ] {
        if let Some(value) = value {
            // The resource constants are `u32` on glibc and `i32` elsewhere.
            #[allow(clippy::unnecessary_cast)]
            out.push((resource as libc::c_int, value, value));
        }
    }
    out
}

/// The grant name procage binds to a private temporary directory.
pub const TMPDIR_GRANT: &str = "tmpdir";

/// Removes a private temporary directory unless the spawn succeeded.
pub(crate) struct TmpdirGuard(pub(crate) Option<PathBuf>);

impl TmpdirGuard {
    pub(crate) fn disarm(mut self) -> Option<PathBuf> {
        self.0.take()
    }
}

impl Drop for TmpdirGuard {
    fn drop(&mut self) {
        if let Some(dir) = self.0.take() {
            let _ = std::fs::remove_dir_all(dir);
        }
    }
}
