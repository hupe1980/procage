//! The escape suites' async mode: built with the `tokio` feature and run
//! with `PROCAGE_ASYNC=1`, the canaries spawn through `Cage::spawn_async`.

use std::os::fd::BorrowedFd;
use std::process::{Command, Output};
use std::time::Duration;

use procage::native::{Cage, Grants};

/// Whether canaries spawn through the async path.
pub fn on() -> bool {
    let asked = std::env::var_os("PROCAGE_ASYNC").is_some_and(|v| v == "1");
    assert!(
        !asked || cfg!(feature = "tokio"),
        "PROCAGE_ASYNC=1 needs `--features tokio`"
    );
    asked
}

/// Spawns `command` through the async path and collects its output; kills
/// the run and panics after `timeout`.
#[cfg(feature = "tokio")]
pub fn output(
    cage: &Cage,
    command: Command,
    grants: &Grants,
    fds: &[BorrowedFd<'_>],
    timeout: Duration,
) -> Output {
    use std::sync::OnceLock;
    use tokio::io::AsyncReadExt;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    });
    runtime.block_on(async {
        let mut command = tokio::process::Command::from(command);
        let mut child = cage
            .spawn_async_with_fds(&mut command, grants, fds)
            .unwrap_or_else(|e| panic!("spawn: {e}"));
        let (mut out, mut err) = (child.stdout.take().unwrap(), child.stderr.take().unwrap());
        let run = async {
            let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
            out.read_to_end(&mut stdout).await.unwrap();
            err.read_to_end(&mut stderr).await.unwrap();
            let status = child.wait().await.unwrap();
            Output {
                status,
                stdout,
                stderr,
            }
        };
        match tokio::time::timeout(timeout, run).await {
            Ok(output) => output,
            Err(_) => panic!("child hung for more than {timeout:?}"),
        }
    })
}

#[cfg(not(feature = "tokio"))]
pub fn output(_: &Cage, _: Command, _: &Grants, _: &[BorrowedFd<'_>], _: Duration) -> Output {
    unreachable!("`on` is false without the feature")
}
