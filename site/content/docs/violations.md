+++
title = "Violations: what the sandbox denied, and why"
description = "CageOptions::with_violations: after a caged command fails, list every operation the sandbox denied it, with the process, the target and the kind of rule behind each."
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

## What each violation says

| Field | Meaning |
|---|---|
| `pid`, `process` | The process that was denied: the child or any descendant |
| `operation` | The Seatbelt operation, such as `file-read-data`, `file-write-create`, `mach-lookup`, `process-exec*` |
| `target` | The path, service name or other object, when the kernel names one |
| `denied_by` | Which kind of rule denied it (below) |
| `received` | When procage received the report |

`denied_by` decides the fix:

| `DeniedBy` | Meaning | Typical fix |
|---|---|---|
| `NotGranted` | Nothing in the policy allows it | Grant the path, if the access is legitimate |
| `Hide` | A `Hide` rule makes the path unreadable | Usually intended; remove the rule only on purpose |
| `Protect` | A `Protect` rule makes the path read-only | Usually intended (`.git`, configuration) |
| `HardDeny(class)` | A hard-deny class: secrets, trust handoff, persistence, privilege, … | Waive the class only if you accept the risk it names |
| `Layer` | A deny rule of your raw Seatbelt layer | Your own rule |

## Live, complete and honest

- **While it runs.** `Child::violation_receiver` yields violations as they arrive, so a harness can show them before the command ends. It buffers 1,024; when it lags, later violations are still in the record.
- **Complete.** `Violations::complete` is true once the child has exited and every denial reported before that has arrived. `Child::violations` waits up to a second for this after the exit; on a loaded host it may return an incomplete record, which you can read again.
- **Coverage.** `Violations::coverage` says what the record can show: `Observed`, `Off` (the cage was built without the option), `Unavailable(reason)` (reporting could not start or stopped), or `NotObserved` (the platform does not report denials yet).
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

## Linux

Linux does not report denials yet: Landlock reports them only to the audit subsystem, which needs privileges. The API is the same on both systems (`procage::native`), and on Linux every record's coverage is `NotObserved`. Exact reports of the system calls procage's seccomp filter refuses are planned.

## Diagnostic, not enforcement

Reporting never changes what the sandbox allows, and no decision of the sandbox depends on it. The escape suite runs with reporting both off and on.
