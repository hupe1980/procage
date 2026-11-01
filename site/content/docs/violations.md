+++
title = "Violations: what the sandbox denied, and why"
description = "CageOptions::with_violations: list what the sandbox denied a caged command, with the process, the target and the rule behind each: every denial on macOS, every refused system call on Linux."
weight = 75

[extra]
group = "Guides"
nav = "Violations"
+++

A denied operation reaches the caged program as `EPERM` ("Operation not permitted"). The program may print it, swallow it, or report something unrelated, and the harness is left guessing whether the sandbox was involved at all, let alone which access to grant.

A cage built with `CageOptions::with_violations` tells the harness directly. After the child exits, `Child::violations` lists each denied operation:

```rust
use std::process::Command;
use procage::native::{Cage, CageOptions, Grants};

let cage = Cage::with_options(&policy, &CageOptions::default().with_violations())?;
let mut child = cage.spawn(&mut Command::new("make"), &Grants::new())?;
child.wait()?;

let record = child.violations();
for v in &record {
    eprintln!("sandbox: {v}");
}
```

```text
sandbox: make (pid 812) was denied file-write-create /Users/me/out.o: not granted by the policy
sandbox: cat (pid 815) was denied file-read-data /Users/me/project/.env: the path is hidden
sandbox: sh (pid 816) was denied file-write-create /Users/me/project/.git/hooks/pre-commit: denied by the trust-handoff hard-deny class
```

## Quiet records

Two things keep records to what matters:

- **Base V3** refuses the probes every program makes (the logging services, the DTrace helper, `dirhelper`, group membership, `/dev/tty`) without reporting them. Measured over a set of everyday and developer commands, V3 cuts the reports by about 95 % against V2, and commands that do not go through Apple's Xcode shim leave an empty record. The shim's reads of your preferences and caches stay reported: they name your files.
- **Identical denials merge**: one entry per process, operation, target and rule, with `repeats` counting how often it happened (`xcodebuild` retries one refused lookup thousands of times; a flood of one refused system call on Linux becomes one line).

## What each violation says

| Field | Meaning |
|---|---|
| `pid`, `process` | The process that was denied: the child or any descendant |
| `operation` | The Seatbelt operation, such as `file-read-data`, `file-write-create`, `mach-lookup`, `process-exec*` |
| `target` | The path, service name or other object, when the kernel names one |
| `denied_by` | Which kind of rule denied it (below) |
| `received` | When procage received the first report |
| `repeats` | How often this exact denial happened (at least 1) |

`denied_by` decides the fix:

| `DeniedBy` | Meaning | Typical fix |
|---|---|---|
| `NotGranted` | Nothing in the policy allows it | Grant the path, if the access is legitimate |
| `Hide` | A `Hide` rule makes the path unreadable | Usually intended; remove the rule only on purpose |
| `Protect` | A `Protect` rule makes the path read-only | Usually intended (`.git`, configuration) |
| `HardDeny(class)` | A hard-deny class: secrets, trust handoff, persistence, privilege, … | Waive the class only if you accept the risk it names |
| `Layer` | A deny rule of your raw layer | Your own rule |
| `Lifetime`, `OlderKernel` | Linux only, see below | |

## Live, complete and honest

- **While it runs.** `Child::violation_receiver` yields violations as they arrive, so a harness can show them before the command ends. It buffers 1,024; when it lags, later violations are still in the record.
- **Complete.** `Violations::complete` is true once the child has exited and every denial reported before that has arrived. `Child::violations` waits up to a second for this after the exit; on a loaded host it may return an incomplete record, which you can read again.
- **Coverage.** `Violations::coverage` says what the record can show: `Observed` (macOS: every denial), `SystemCalls` (Linux: every refused system call), `Off` (the cage was built without the option), `Unavailable(reason)` (reporting could not start or stopped), or `NotObserved` (a platform that reports nothing).
- **Bounded.** A record keeps 10,000 violations and counts the rest (`Violations::dropped`).

An empty record proves nothing unless it is complete and its coverage is `Observed`.

## How it works on macOS

The kernel logs every Seatbelt denial to the unified log, followed by the message of the rule that denied it. A reporting cage's profile sets each rule's message to the run's marker and the rule's kind; nothing else in the profile changes, and without the option the profile is identical to one built without it.

One helper per process, `/usr/bin/log stream`, reads only the messages carrying this process's markers. procage runs it only after checking that `/bin/sh` and `/usr/bin/log` are owned by root, not writable by others, and on the read-only system volume, and a watchdog ends it when your process exits. The first reporting spawn waits for the helper (about 0.1 s, at most 2 s).

To know when a run's record is complete, procage makes a *fence*: a short-lived child denied one operation. Kernel denials reach the log in order, so when the fence's denial arrives, every earlier denial has too. A run's marker goes to another run only after such a fence.

Notes:

- `log stream` needs an administrator account. Elsewhere, spawning still works and the record says reporting is unavailable, and why.
- The kernel reports identical denials by one process (same operation and target) once.
- Caged code chooses the paths it is denied, so a target is untrusted text. It cannot change which run a violation belongs to: the run's marker is the last line of the kernel's message.
- `Cage::exec` has no handle, so it has no record.

## How it works on Linux

Every system call procage's seccomp filter refuses is reported, exactly: `ptrace`, `io_uring_setup`, `bpf` and the rest of the hard-deny classes, an IP socket when the policy has no network, `fork` when it does not allow forking, `setsid` under `Lifetime::Run`, and truncation on kernels below Landlock ABI 3. The record's coverage is `SystemCalls`.

With reporting on, the filter hands each refused call to a *listener* instead of failing it at once (seccomp user notification). The child passes the listener to your process before it starts the command and keeps no copy. A supervisor thread answers every call with `EPERM` (exactly what the call returns without reporting), then records the process, the call, a target where the arguments name one (`family AF_INET`, `command TIOCSTI`) and the reason:

| `DeniedBy` on Linux | Meaning |
|---|---|
| `HardDeny(class)` | A hard-deny class: process access, kernel surface, namespaces, socket families, terminal injection |
| `NotGranted` | The policy does not grant it: no network, no forking, `Signals::None`, SysV IPC |
| `Lifetime` | `setsid`/`setpgid` under `Lifetime::Run`, so that ending the run reaches every descendant |
| `OlderKernel` | Below Landlock ABI 3, truncation is refused everywhere |
| `Layer` | Your raw Linux layer's `syscalls_deny` |

A refused call waits for the answer, so the record is **exact and complete** once no process of the run is left: no log, no timing assumption, no privileges. A descendant that outlives the child keeps the record open until it exits or `kill_all` ends it.

Notes:

- File, network and signal denials come from Landlock, which reports them only to the privileged audit subsystem; they are not in the record.
- A call an outer sandbox refuses first (for example `bpf` under Docker's default seccomp profile) fails before procage's filter sees it, so it is not reported.
- Inside a sandbox whose own seccomp filter already uses a listener, the kernel refuses a second one: the run is confined exactly as without reporting, and the record's coverage is `Unavailable` with the reason.
- If your process dies, the kernel answers refused calls with `ENOSYS`: they still fail.
- `Cage::exec` has no supervisor; there the kernel answers with `EPERM` as without reporting.

## Diagnostic, not enforcement

Reporting never changes what the sandbox allows, and no decision of the sandbox depends on it. The escape suite runs with reporting both off and on.
