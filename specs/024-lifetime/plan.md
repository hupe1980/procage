# Implementation Plan: Lifetime — nothing a run starts outlives it

**Branch**: `024-lifetime` (local planning; commits on `main`) |
**Date**: 2026-10-31 | **Spec**: [spec.md](spec.md)

## Summary

`Policy.process` gains `lifetime: Lifetime { Run (default), Tree }`.

- **Linux** (research R2): under `Run` with fork allowed, the lowering adds
  seccomp denies for `setsid` and `setpgid` (`EPERM`). procage's own
  `setsid`/`setpgid(0, 0)` in the child runs before the filter, so every
  descendant stays in the child's process group for life. The handle's
  existing `killpg(child)` then reaches all of them, also after the child
  was reaped (the group id stays reserved while a member lives).
- **macOS** (R1, R3, R4): when fork is allowed, the lowering appends a
  marker block last in the profile:
  `(deny mach-lookup (global-name-prefix (param "procage-run-prefix")))`
  `(allow mach-lookup (global-name (param "procage-run-marker")))`.
  The backend binds the two parameters per spawn from a process-random
  prefix and a slot from a process-wide pool, compiling through the
  existing cache keyed by (profile, params). Ending the run scans every
  process (`proc_listallpids`), skips other users and zombies, and kills
  those whose sandbox allows the marker and denies the probe name
  (`sandbox_check(pid, "mach-lookup", GLOBAL_NAME, …)`), in rounds until
  none is found (R5).
- `kill_all` returns an error naming survivors after the round limit; the
  slot is freed only after a clean kill, retired on detach or failure.
- Escape suite: the double-fork canary is un-ignored on both systems; new
  canaries for exited children, concurrent runs, detach, the Linux lock and
  the `Tree` opt-out. R-23 becomes `mitigated`.

## Technical Context

**Language/Version**: Rust 1.99, edition 2024.
**Primary Dependencies**: `libc` (existing); libsandbox's `sandbox_check`
(already resolved by `macos::sys`); `proc_listallpids`, `proc_pidinfo`
(libproc, public).
**Storage**: N/A (in-memory slot pool).
**Testing**: `cargo test` / nextest on macOS 26.6.2; Docker T1 and T2
(`just linux`, `just linux-t1`); `just ci`.
**Target Platform**: macOS 26 arm64; Linux T1/T2 (aarch64 locally;
x86_64 by the architecture-pinned seccomp tests and CI after a push).
**Project Type**: library (`procage`, `procage-policy`).
**Performance Goals**: drop of a forking macOS run ≤ 10 ms more than today
(SC-003; measured scan 1.9 ms for 716 processes); repeated spawns of one
policy compile once (SC-004).
**Constraints**: child code stays syscalls only (no new child step);
`procage-policy` stays `no_std` and free of `unsafe`; frozen presets keep
their version.
**Scale/Scope**: ~150 lines policy/lowering, ~250 lines macOS backend,
~20 lines Linux backend, ~250 lines tests, docs.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Default tightens; a survivor makes `kill_all` fail (never `Ok` with a known live process); a marker compile failure fails the spawn before fork | PASS |
| II. Types over strings | `Lifetime` enum in the policy; ledger constructs `lifetime-run`/`lifetime-tree`; seccomp `Syscall::Setsid`/`Setpgid` variants | PASS |
| III. Kernel is the oracle | Canaries on macOS, T1, T2 decide R-23's status; the marker's selectivity is a caged test against the caller, an allow-all `sandbox-exec` process and another run | PASS |
| IV. Syscalls only between fork and exec | No new child step: the marker is in the compiled profile; the lock is part of the seccomp program installed by the existing step. The scan runs in the parent. `unsafe` only in `macos::sys` | PASS |
| V. Hygiene by default | This feature implements V's lifetime clause; default on | PASS |
| VI. Private interfaces | `sandbox_check` with a pid and a global-name filter is undocumented; it is the already-resolved symbol, and a probe (a fresh cage must match its own marker and not the probe name) runs before the first marker spawn; failure is `Unsupported` | PASS |
| VII. A library, not a harness | **Amendment needed**: the slot pool and the process-random prefix are new global state, which VII's closed list does not allow. Alternative (per-cage prefix) recompiles on every `Cage::new` (~7 ms, R4) and breaks the compile cache for consumers that build a cage per command (such as a consumer harness). Amend VII (MINOR, 2.1.0) to add "the run-marker slots" to the allowed state | AMENDED (see Complexity Tracking) |

Post-design re-check: unchanged; no principle I or V waiver.

## Project Structure

### Documentation (this feature)

```text
specs/024-lifetime/
├── plan.md, research.md, data-model.md, quickstart.md
├── contracts/lifetime.md
├── threat-model.yaml / .md, security/
└── tasks.md (next step)
```

### Source Code (repository root)

```text
crates/procage-policy/src/
├── policy.rs          # Lifetime enum, Process.lifetime
├── linux.rs           # Syscall::Setsid, Syscall::Setpgid
├── lower/mod.rs       # Construct::LifetimeRun, LifetimeTree
├── lower/linux.rs     # lock rules + ledger
├── lower/macos.rs     # marker block (last) + ledger; MARKER_PARAMS consts
├── lowering.md        # table rows
└── presets.rs         # docs: presets carry Lifetime::Run
src/
├── linux/seccomp.rs   # syscall numbers for setsid/setpgid
├── linux/child.rs     # docs (group kill reaches all under Run)
├── linux/mod.rs       # testing::try_setsid (canary helper)
├── macos/lifetime.rs  # new: prefix, slot pool, Run marker, reap loop
├── macos/sys.rs       # all_pids, same-uid/zombie filter, check_name
├── macos/mod.rs       # Cage: per-slot bytecode; spawn takes a slot
└── macos/child.rs     # kill_all: marker scan, rounds, slot release
tests/
├── escape_macos.rs, escape_linux.rs   # R-23 canaries
├── spawn_macos.rs                     # marker selectivity, compile once
└── threat_model.rs                    # R-23 mitigated
THREAT_MODEL.md, README.md, src/lib.rs  # claims
```

**Structure Decision**: existing layout; one new module `src/macos/lifetime.rs`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|---|---|---|
| VII: new global state (process-random prefix + slot pool) | Concurrent runs need distinct markers, and the compile cache must keep hitting across `Cage::new` calls | Per-cage prefix: every new cage compiles (~7 ms vs ~2 ms cached spawn); per-spawn random marker: every forking spawn compiles; extension-based marker: cached, but the child could release the extension and drop out of the scan (threat.marker-evasion) |
