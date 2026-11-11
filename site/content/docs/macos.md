+++
title = "macOS backend"
description = "How procage applies Seatbelt on macOS through libsandbox's private interface, without sandbox-exec: path resolution, compiling once, the in-child sequence, what the tests observe and its limits."
weight = 50

[extra]
group = "Backends"
nav = "macOS (Seatbelt)"
+++

macOS confines processes with **Seatbelt**, the kernel sandbox behind the App Sandbox. procage does not use the deprecated `/usr/bin/sandbox-exec` and needs no helper binary: it compiles and applies profiles through undocumented libsandbox functions, resolved at run time.

## Preparing a cage

`procage::macos::Cage::new` (or `with_options`):

1. refuses with `SpawnError::AlreadySandboxed` if the caller is itself sandboxed (a second profile would fail or be ignored);
2. resolves every policy path to the spelling the kernel matches (`/tmp/x` becomes `/private/tmp/x`, firmlinks and symbolic links are followed) and records each rewrite (`Cage::rewrites()`);
3. lowers the policy to a Seatbelt profile (`Cage::plan()`);
4. compiles the profile once, in process, and caches the bytecode.

To look up a path in the caller's spelling, the kernel needs the child to read the *metadata* of each symbolic link a policy path passes through, and of `/etc`, `/tmp` and `/var`: the child can see where those links point, but nothing behind them.

Seatbelt matches every path case- and Unicode-normalization-insensitively, on every volume. The spelling matrix (`tests/spelling_macos.rs` and the R-37 canary, measured on macOS 26.6.2 and run on every macOS lane) shows:

- on the default (case-insensitive) volume, a deny or an allow spelled in another case, or composed where the disk has the name decomposed (and the reverse), covers the file;
- a rule through nested symbolic links, a rule for a name created later in another case, and a rule spelled with the data-volume firmlink cover the file;
- on a case-sensitive volume, a deny also covers the name's case variants, and an allow rule, an allowed Unix socket, a Seatbelt-layer allow or a grant is refused with `SpawnError::CaseSensitive`, since Seatbelt would allow the variants too, which are other files there. The volume is the one of the path's longest existing prefix (`pathconf(_PC_CASE_SENSITIVE)`).

libsandbox aborts its caller on very large profiles, so a profile with more rules than `CageOptions::compile_limit` (2,000 by default) is refused with `SpawnError::LimitExceeded`; a profile libsandbox rejects is `SpawnError::Compile`.

## Spawning

`Cage::spawn` forks a child that, using system calls only:

1. resets ignored signals to their default action, starts a new session (or, with `Tty::Inherit`, its own process group) and sets resource limits;
2. applies the compiled profile;
3. confirms that it is sandboxed;
4. consumes the spawn's grant tokens (sandbox extensions for the bound paths);
5. marks every inherited descriptor close-on-exec;

and only then executes the target. If any step fails, the target never runs and `SpawnError::Apply` names the step.

Before the first spawn, procage checks that the in-child apply method works on this macOS release (`procage::macos::probe()`); before the first forking spawn, it checks the query that finds a run's processes. Either failing is an `Unsupported` error, never a fallback to running unsandboxed.

## What the tests observe

The tests (`tests/spawn_macos.rs`, `tests/escape_macos.rs`) cage real children on macOS 26.6.2; the [threat model](@/docs/threat-model.md) lists the canaries per escape class. Beyond those:

- a denied file access fails with "operation not permitted";
- under `Base::V1` alone, `id`, `date`, `uname`, `sh`, `zsh`, `bash`, `cat`, `sed`, `awk`, `perl`, `tar`, `gzip` and Rust programs run with correct output, while the home directory, temporary files and the network stay refused;
- a descriptor left open without close-on-exec does not reach the child, even with 1,000 extra descriptors open;
- two concurrent runs of one cage end separately, and 100 children spawned while other threads load libraries are all caged.

## Finding a run's processes

Seatbelt cannot filter `setsid`, so a descendant can leave the child's session and process group. For a forking policy, each run's profile carries a marker; when the run ends, procage asks libsandbox (an undocumented query) which of the user's processes carry it. Between finding a process and killing it, the process could exit and its id be reused: macOS has no process handle that would close that window.

## Limits

- **Process introspection (R-25).** Unsandboxed, any process of the same user can read another's arguments and environment through `KERN_PROCARGS2`. The `process-access` hard-deny class refuses it on every base: it denies the argument sysctls by prefix (`kern.procargs`) and other processes' information, the only rule shapes the query honours (measured on 26.6.2), and keeps the run's own processes readable (`(target same-sandbox)`). `ps` cannot list them: it is setuid, and setuid programs are refused in any cage; `pgrep` needs `sysmond` and fails in any cage. Signals to other processes and task ports are refused too. Waiving `process-access` lifts all of it.
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
