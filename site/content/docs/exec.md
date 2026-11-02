+++
title = "Running helpers with Cage::exec"
description = "Cage::exec and Cage::exec_session turn a small helper program into the caged command, for MCP clients, terminals and async runtimes that start, own and kill the process themselves."
weight = 80

[extra]
group = "Guides"
nav = "Running helpers"
+++

When other code starts and owns the process (an MCP client, a terminal emulator, `tokio::process::Command` with `kill_on_drop`), `Cage::spawn` does not fit: it would make procage the parent. Give that code a small **helper** program instead of the command. The helper builds the cage and calls `Cage::exec`, which confines the helper itself and executes the command in its place, like `CommandExt::exec`: it does not fork and returns only on failure.

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

After `exec`, the helper's pid, standard streams, process group and exit status are the command's. `crates/procage/examples/exec_helper.rs` in the repository is a complete helper that confines a program to a writable workspace.

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

The confinement is the one `Cage::spawn` gives, except that the session and process group stay the caller's and there is no `Child` handle, so no receipt, violation record or handoff audit (the hard-link check still runs):

- **Lifetime belongs to the caller.** Under the default `Lifetime::Run` on Linux, descendants cannot leave the process group (`setsid` and `setpgid` fail), so the group kill reaches all of them, and the command receives `SIGKILL` when the helper's parent exits. On macOS a descendant that starts its own session is not reached by the group kill; use `Cage::spawn`, whose handle finds it, when that matters.
- **Single-threaded on Linux tier T1.** User namespaces refuse a multi-threaded process: call `exec` early in `main`, before starting threads, or choose tier T2 with `CageOptions::with_tier`. Otherwise you get `Unsupported::ExecThreads`.
- **No `tmpdir` grant.** Nothing would remove the directory, so a policy that declares it is refused (`GrantError::TmpdirWithExec`).
- **Checks first.** Grant bindings, the `tmpdir` grant, threads, the environment and a missing program are checked before the process changes. A failure after that (`SpawnError::Apply`, or `SpawnError::Io` from `execvp`) leaves the process partly confined: exit.

`Cage::exec_with_fds` also keeps chosen descriptors open across the exec, at the same numbers; every other descriptor numbered 3 or higher is closed.

## A session of its own

Test runners such as cargo-nextest start each test in a process group of its own, which `Cage::exec` refuses on Linux. With `Cage::exec_session` the command leads a session of its own: on Linux its descendants may start process groups but not sessions. The owner ends the run with `end_session`:

```rust
// The helper: start a session and become the command.
let err = cage.exec_session(&mut command, &Grants::new());

// The owner: start the helper as a plain child (not with `process_group(0)`,
// whose leader cannot start a session), and end the run before reaping it.
let mut helper = std::process::Command::new("my-helper").spawn()?;
procage::native::end_session(helper.id());
helper.wait()?;
```

A helper that leads a process group but no session fails with `SpawnError::GroupLeader`, and `Tty::Inherit` with `Unsupported::Setting`, before the process changes. On macOS a descendant can still start its own session, as with `Cage::exec`.
