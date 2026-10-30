//! The apply-method probe, run once per process before the first spawn.

use std::process::{Command, Stdio};
use std::sync::OnceLock;

use super::{SpawnError, Unsupported, libsandbox, sys};

/// How a profile is applied in the child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyMethod {
    /// `__mac_syscall("Sandbox", 0, …)` with the compiled bytecode: system
    /// calls only.
    PathA,
}

fn unsupported(detail: String) -> SpawnError {
    SpawnError::Unsupported(Unsupported::ApplyMethod {
        os_build: sys::os_build(),
        detail,
    })
}

fn run() -> Result<ApplyMethod, String> {
    let lib = libsandbox().map_err(|e| e.to_string())?;
    let bytecode = lib
        .compile("(version 1)\n(deny default)\n", &[])
        .map_err(|e| {
            format!(
                "the probe profile does not compile: {}",
                e.unwrap_or_default()
            )
        })?;
    let mut command = Command::new("/usr/bin/true");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    sys::install_probe(&mut command, lib.child_ops(), bytecode.into());
    match command.spawn() {
        Ok(mut child) => {
            let _ = child.wait();
            Err("the probe child executed its target".into())
        }
        Err(e) => match e.raw_os_error().and_then(sys::decode_step) {
            Some((sys::PROBE_OK, _)) => Ok(ApplyMethod::PathA),
            Some((sys::PROBE_CANARY, errno)) => {
                Err(format!("the canary access was not denied (errno {errno})"))
            }
            Some((step, errno)) => Err(format!("step {step} failed with errno {errno}")),
            None => Err(format!("spawning the probe failed: {e}")),
        },
    }
}

/// Probes the in-child apply method once per process: a throwaway child
/// applies a deny-everything profile, must report itself sandboxed, and must
/// be refused a canary file. The result is cached.
pub fn probe() -> Result<ApplyMethod, SpawnError> {
    static RESULT: OnceLock<Result<ApplyMethod, String>> = OnceLock::new();
    RESULT.get_or_init(run).clone().map_err(unsupported)
}
