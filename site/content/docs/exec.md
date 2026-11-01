+++
title = "Running helpers with Cage::exec"
description = "Cage::exec turns a small helper program into the caged command, for MCP clients, terminals and async runtimes that start, own and kill the process themselves."
weight = 80

[extra]
group = "Guides"
nav = "Running helpers"
+++

Sometimes other code starts the process: an MCP client, a terminal emulator, `tokio::process::Command` with `kill_on_drop`. That code holds the process id, the pipes and the exit status, and it kills the process when it is done. `Cage::spawn` does not fit, because it would make procage the parent.

Give that code a small **helper** program instead of the command. The helper builds the cage and calls `Cage::exec`, which confines the helper itself and executes the command in its place, like `std::os::unix::process::CommandExt::exec`: it does not fork and returns only on failure.

## The helper

```rust
use std::process::Command;
use procage::native::{Cage, Grants};
use procage::policy::{Base, Policy};

fn main() {
    let mut policy = Policy::default();
    policy.base = Base::V3;
    let cage = Cage::new(&policy).unwrap_or_else(|e| panic!("{e}"));
    let mut command = Command::new("/usr/bin/env");
    command.current_dir("/tmp"); // a directory the policy lets it read
    let err = cage.exec(&mut command, &Grants::new()); // returns only on failure
    eprintln!("helper: {err}");
    std::process::exit(126);
}
```

After `exec`, the helper's pid, standard streams, process group and exit status are the command's, so whatever waits for or kills the helper does so for the command. The repository's `crates/procage/examples/exec_helper.rs` is a complete helper that confines a program to a writable workspace.

## The caller

Start the helper in its own process group and end it by killing the group:

```rust
use std::os::unix::process::CommandExt;

let helper = std::process::Command::new("my-helper")
    .arg("--")
    .arg("server")
    .process_group(0)
    .spawn()?;
// later: kill -9 -<pid> ends the command and the descendants in its group.
```

## Rules and differences from spawn

The confinement is the one `Cage::spawn` gives, except that the session and process group stay the caller's and there is no `Child` handle. So:

- **Lifetime belongs to the caller.** Under the default `Lifetime::Run` on Linux, descendants cannot leave the process group (`setsid` and `setpgid` fail), so the group kill reaches all of them, and the command receives `SIGKILL` when the helper's parent exits. On macOS a descendant that starts its own session is not reached by the group kill; use `Cage::spawn`, whose handle finds it, when that matters.
- **Single-threaded on Linux tier T1.** User namespaces refuse a multi-threaded process: call `exec` early in `main`, before starting threads, or choose tier T2 with `CageOptions::with_tier`. Otherwise you get `Unsupported::ExecThreads`.
- **No `tmpdir` grant.** Nothing would remove the directory, so a policy that declares it is refused (`GrantError::TmpdirWithExec`).
- **Checks first.** Everything that can be checked is checked before the process changes: grant bindings, the `tmpdir` grant, threads, the environment, a program that cannot be found. A failure after that (`SpawnError::Apply`, or `SpawnError::Io` from `execvp`) leaves the process partly confined: exit.

`Cage::exec_with_fds` also keeps chosen descriptors open across the exec, at the same numbers; every other descriptor numbered 3 or higher is closed.
