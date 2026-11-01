+++
title = "macOS backend"
description = "How procage applies Seatbelt on macOS through libsandbox's private interface, without sandbox-exec: path resolution, compiling once, the in-child sequence, what the tests observe and what is not done yet."
weight = 50

[extra]
group = "Backends"
nav = "macOS (Seatbelt)"
+++

macOS confines processes with **Seatbelt**, the kernel sandbox behind the App Sandbox. Its command-line front end, `/usr/bin/sandbox-exec`, is deprecated. procage does not use it and needs no helper binary: it compiles and applies profiles through functions of libsandbox that Apple does not document, resolved at run time.

## Preparing a cage

`procage::macos::Cage::new` (or `with_options`):

1. refuses at once with `SpawnError::AlreadySandboxed` if the calling process is itself sandboxed: a second profile would fail or be ignored by the kernel;
2. resolves every policy path to the spelling the kernel matches (`/tmp/x` becomes `/private/tmp/x`, firmlinks and symbolic links are followed) and records each rewrite (`Cage::rewrites()`);
3. lowers the policy to a Seatbelt profile (`Cage::plan()`);
4. compiles the profile once, in process, and caches the bytecode.

To look up a path in the caller's spelling, the kernel needs the child to read the *metadata* of each symbolic link a policy path passes through, and of `/etc`, `/tmp` and `/var`. The child can therefore see where those links point, but nothing behind them.

libsandbox aborts its caller on very large profiles, so a profile with more rules than `CageOptions::compile_limit` (2,000 by default) is refused with `SpawnError::LimitExceeded`.

## Spawning

`Cage::spawn` forks a child that, using system calls only:

1. starts a new session (or, with `Tty::Inherit`, its own process group) and sets resource limits;
2. applies the compiled profile;
3. confirms that it is sandboxed;
4. consumes the spawn's grant tokens (sandbox extensions for the bound paths);
5. marks every inherited descriptor close-on-exec;

and only then executes the target. If any step fails, the target never runs and `SpawnError::Apply` names the step.

Before the first spawn, procage probes that the in-child apply method works on this macOS release (`procage::macos::probe()`); before the first forking spawn it also checks the query that finds a run's processes. Either failing is an `Unsupported` error, never a fallback to running unsandboxed.

## What the tests observe

The backend's tests cage real children on the kernel (macOS 26.6.2). Among what they observe:

- granted files work; every other file access fails with "operation not permitted"; a protected subtree inside a writable one cannot be written;
- without network access, connecting to a loopback listener fails; with loopback access for that port it succeeds;
- a grant bound for one spawn gives nothing to another;
- a descriptor left open without close-on-exec does not reach the child, even with 1,000 extra descriptors open; one handed over with `spawn_with_fds` does;
- dropping the `Child` kills the child, its process group, a grandchild that started its own session and, with a forking policy, a descendant that double-forked and was reparented to `launchd`, also after the child exited; two concurrent runs of one cage end separately;
- with environment passthrough, `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and `DYLD_*` do not reach the child;
- with read access to the whole home directory, `~/.ssh`, `~/.aws` and `~/.gnupg` (also spelled `~/.SSH`) stay unreadable; in a writable workspace, git hooks and config, shell rc files and `.vscode` cannot be written and `.git` cannot be renamed, while ordinary files and `.git/objects` can; launch agents cannot be planted even with a write grant;
- with base profile V1, `id`, `date`, `uname`, `sh`, `zsh`, `bash`, `cat`, `sed`, `awk`, `perl`, `tar`, `gzip` and Rust programs run with correct output, while the base alone still refuses the home directory, temporary files and the network;
- 100 children spawned while other threads load libraries are all caged.

## Finding a run's processes

Seatbelt cannot filter `setsid`, so a descendant can leave the child's session and process group. For a forking policy, procage gives each run's profile a marker, and when the run ends it asks libsandbox, for every process of the user, whether that process carries the marker. This query form is undocumented. Between finding a process and killing it, the process could exit and its id be reused: macOS offers no process handle that would close that window.

## Not done yet

- **Process introspection (R-25, partial).** Any process of the same user can read another's arguments and environment through the `KERN_PROCARGS2` query, which the sandbox does not mediate, even under `(deny sysctl-read)`. Do not pass secrets to the calling program through its arguments or environment. Signals to other processes and task ports are refused.
- No pseudo-terminals (`Tty::NewPty` is refused).
- The base profiles are curated for macOS 26.6.2. A later release may need a new base version.
- Apple may change or remove the private libsandbox interface in any release. procage reports a missing symbol or a failed probe as `Unsupported`, naming the macOS build.

## Useful calls

| Call | Purpose |
|---|---|
| `procage::macos::is_sandboxed()` | Whether the calling process is sandboxed |
| `procage::macos::probe()` | Checks the in-child apply method on this release |
| `Cage::plan()` | The lowered `SeatbeltPlan`: profile text, parameters, grant slots |
| `Cage::rewrites()` | Policy paths rewritten to the kernel's spelling |
| `Cage::compiled()` | Whether preparing compiled the profile or found it cached |
