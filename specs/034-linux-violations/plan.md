# Implementation Plan: Linux violations

**Branch**: `034-linux-violations` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **Policy crate** (`linux.rs`, `lower/linux.rs`, `sbpl.rs`): `SeccompRule::reason`,
  set per origin; `DenyReason::{Lifetime, OlderKernel}`; `Condition::matches`.
- **procage, Linux**:
  - `seccomp::build(rules, arch, notify)`: `EPERM` verdicts become
    `SECCOMP_RET_USER_NOTIF` when `notify`.
  - `Cage` keeps the notifying filter when reporting; `spawn` creates a
    `SOCK_SEQPACKET|SOCK_CLOEXEC` pair; `ChildPlan` carries the child end,
    the notifying filter and a parent-allocated control buffer.
  - Child (`sys.rs`), after Landlock: `seccomp(NEW_LISTENER, notify)`; on
    success `sendmsg(SCM_RIGHTS)` and `close`; on failure the plain filter,
    then `sendmsg` of the errno. Then the existing verify.
  - Parent: `recvmsg` after the spawn; a supervisor thread
    (`linux/violations.rs`): `poll` → `NOTIF_RECV` → answer `-EPERM` →
    name (`/proc/<pid>/comm`, `NOTIF_ID_VALID`) → reason by
    `Condition::matches` → record; ends on `POLLHUP`, sets `done`.
  - `Child::violations` / `violation_receiver` / `kill_all` use `done`.
  - `Coverage::SystemCalls`, `DeniedBy::{Lifetime, OlderKernel}`.
- **Tests**: policy (reasons, `matches` vs interpreter), seccomp builder
  (verdict-only diff), `spawn_linux` (reasons, completeness, detach,
  fallback via an outer listener, flood, latency), escape R-32 and the suite
  with reporting on, KF-L15.
- **Docs**: crate, site violations page, README, THREAT_MODEL (R-32 row).

## Technical Context

Rust 1.99, `libc` 0.2.191 (`seccomp_notif`, `SECCOMP_IOCTL_NOTIF_*`).
Lanes: Docker T2 (default seccomp) and T1 (unconfined), Linux 7.0.14.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | No run execs unfiltered: listener failure installs the plain filter in the same step; a gone supervisor makes the kernel answer `ENOSYS`; answers never carry `CONTINUE` | PASS |
| II. Types | `DenyReason`, `DeniedBy`, `Coverage` variants; reasons from rules, not strings | PASS |
| III. Kernel oracle | KF-L15; caged tests on both tiers; R-32 canary | PASS |
| IV. fork/exec, unsafe | New child calls: `seccomp`, `sendmsg`, `close` (system calls); the control buffer and filters are allocated in the parent; unsafe only in `linux::sys`; the existing multithreaded spawn test runs with reporting on | PASS |
| V. Hygiene | The child keeps no listener (R-32); the socket pair is close-on-exec | PASS |
| VI. Private interfaces | None (documented kernel ABI) | PASS |
| VII. Library | One thread per reporting run, ending with the run's processes; no global state added | PASS |

## Project Structure

```text
crates/procage-policy/src/linux.rs, lower/linux.rs, sbpl.rs; tests/
crates/procage/src/linux/{mod.rs, child.rs, seccomp.rs, sys.rs, violations.rs (new)}
crates/procage/src/violation.rs, lib.rs
crates/procage/tests/{spawn_linux.rs, escape_linux.rs, native.rs, threat_model.rs}
crates/procage-kernel-facts (KF-L15)
crates/procage/THREAT_MODEL.md, README.md, site/content/docs/{violations,linux}.md
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| One thread per reporting run | Each run has its own listener; exact attribution | One epoll thread for all runs: shared state and lifetime coupling for no gain at this scale |
