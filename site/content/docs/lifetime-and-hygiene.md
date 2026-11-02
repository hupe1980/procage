+++
title = "Lifetime and hygiene"
description = "How procage ends a run (process groups, run markers, double-forked daemons), and the state it keeps from leaking into a child: file descriptors, environment variables, the terminal, temporary files and resource limits."
weight = 90

[extra]
group = "Guides"
+++

A sandbox profile does not by itself stop a child from inheriting state it should not see, or from outliving the run. procage handles both on every spawn.

## Lifetime

The **run** starts at spawn and ends when the `Child` handle is dropped or `Child::kill_all` is called. A child that exits by itself does not end the run: its descendants are still killed when the handle goes.

Ending the run kills the child's process group, every descendant that can still be found from the child, and, for a forking policy:

- **Linux, `Lifetime::Run` (default):** `setsid` and `setpgid` fail with `EPERM` inside the cage, so every descendant stays in the child's process group and dies with it, wherever it was reparented. Programs that daemonize or create job-control groups fail there. The common case is git: its automatic `gc --auto` detaches into a session of its own, so a caged `git commit` succeeds but prints `fatal: setsid failed: Operation not permitted`. Run caged git with `gc.autoDetach=false` (for example `GIT_CONFIG_COUNT=1`, `GIT_CONFIG_KEY_0=gc.autoDetach`, `GIT_CONFIG_VALUE_0=false` on the `Command`), and it collects in the foreground instead.
- **Linux, `Lifetime::Tree`:** programs may start their own sessions and process groups (job-control shells). The run kills the group and the descendants found from the child; a descendant whose parent exits in a session of its own outlives the run.
- **macOS:** the sandbox cannot filter those calls, so each run's processes carry a marker in their profile and are found by it, including descendants reparented to `launchd` and those of a child that already exited. `Lifetime::Tree` behaves like `Run`.

```rust
let mut child = cage.spawn(&mut command, &Grants::new())?;
// ... read its output through the std::process::Child it dereferences to ...
child.kill_all()?; // or just drop `child`
```

| `Child` method | Effect |
|---|---|
| `kill_all()` | Ends the run and waits for the child |
| `detach()` | Gives up lifetime control and returns the `std::process::Child` |
| `dropped_env()` | Environment names the passthrough denylist dropped |
| `tmpdir()` | The run's private `TMPDIR`, if declared |
| `violations()`, `violation_receiver()` | [What the sandbox denied](@/docs/violations.md) |
| `receipt()`, `audit()` | The run's [receipt](@/docs/receipts.md) and [audit](@/docs/audits.md): `None` until the child exits; reading either ends the run |

`std::process::Child::kill`, reachable through `Deref`, kills only the direct child.

## File descriptors

A descriptor opened before the sandbox was applied reads or writes past every path rule (R-21). procage marks every inherited descriptor close-on-exec in the child, so it receives only standard input, output and error, even when the caller forgot `O_CLOEXEC`. `Cage::spawn_with_fds` hands chosen descriptors over at the same numbers; every other descriptor numbered 3 or higher is closed.

## Environment

The default `EnvPolicy::Allowlist(vec![])` passes **no** variable of the caller; the child gets exactly those set on the `Command`. With an allowlist, the named variables are passed as written.

With `EnvPolicy::Passthrough { deny }`, every variable except `deny` is passed, and these are dropped even if `deny` does not name them:

- names starting with `DYLD_` or `AWS_`;
- `LD_PRELOAD`, `LD_LIBRARY_PATH` and `SSH_AUTH_SOCK`;
- names ending in `_TOKEN`, `_SECRET`, `_PASSWORD` or `_API_KEY`.

A variable set explicitly on the `Command` is always kept; `Child::dropped_env()` lists what was dropped. After `Command::env_clear`, no variable of the caller is passed under either policy. The standard library has no getter for that call, so procage reads it from the command's `Debug` output, after checking that the output still shows it; if it does not, a passthrough policy fails with `Unsupported::EnvClear` rather than pass your environment. The pure function behind this is `procage::hygiene::environment`.

## The terminal

- `Tty::None` (default): no controlling terminal; the child leads its own session.
- `Tty::Inherit`: the child shares the caller's terminal in its own process group, so its reads stop with `SIGTTIN` like a background job; keystroke injection with `TIOCSTI` (and `TIOCLINUX` on Linux) is denied (R-22).
- `Tty::NewPty`: refused; procage has no pseudo-terminals.

## A private temporary directory

Runs that share the per-user temporary directory can read or change each other's files (R-10). Declare the reserved grant `tmpdir` and each run gets its own `TMPDIR`, created at spawn and removed when the handle is dropped (not available with [`Cage::exec`](@/docs/exec.md)):

```rust
use procage::policy::{Access, Grant, GrantName};

policy.grants.push(Grant { name: GrantName::new("tmpdir")?, access: Access::Write });
```

You do not bind it; `Child::tmpdir()` returns the path. The `agent_readonly`, `agent_workspace` and `build` presets declare it.

## Resource limits

`policy.limits` (`Rlimits`) sets `nproc`, `cpu_seconds`, `fsize_bytes` and `nofile` when given, and `core_bytes`, which is 0 by default: no core dumps.
