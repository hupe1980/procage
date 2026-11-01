# Implementation Plan: Consumer API before the freeze

**Branch**: `026-consumer-api` (local planning; commits on `main`) |
**Date**: 2026-10-31 | **Spec**: [spec.md](spec.md)

## Summary

- **Environment** (R1, R2): `crate::unix::environment` observes `env_clear` from the
  command's alternate `Debug` output (the `env: CommandEnv {` line followed
  by `clear: true,` / `clear: false,`), after a once-per-process self-check
  on three probe commands. Cleared → the caller's environment is replaced
  by an empty one before `hygiene::environment` runs (pure function
  unchanged). Unobservable → passthrough spawns fail with
  `Unsupported::EnvClear` on both backends, before forking; allowlists
  proceed. The macOS spawn computes the environment before it takes a run
  marker, so a refusal retires nothing.
- **Portable surface** (R3): `pub use crate::macos as native` / `crate::linux as native`
  in `src/lib.rs`; new test `tests/native.rs` (both systems, no `cfg` in the
  body) exercising the common subset.
- **Spawn-time masks** (R4): `LowerOptions::accept_spawn_masks()` inserts
  `HdSecrets`, `HdTrustHandoff`, `HdPersistence`; a policy test pins the set
  and shows other approximations stay refused.
- Docs: crate docs (`native`), `hygiene` (env rules incl. `env_clear`),
  `linux` module (reading everything except secrets).

## Technical Context

**Language/Version**: Rust 1.99, edition 2024.
**Primary Dependencies**: none new.
**Storage**: N/A.
**Testing**: unit tests (observer, decision), `spawn_macos`/`spawn_linux`
env tests, `tests/native.rs`, policy tests; Docker T1/T2; `just ci`.
**Target Platform**: macOS 26, Linux T1/T2.
**Project Type**: library.
**Performance Goals**: one `Debug` format per spawn (microseconds).
**Constraints**: no child-side change; `procage-policy` stays `no_std`.
**Scale/Scope**: ~150 lines code, ~150 lines tests, docs.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Unobservable `env_clear` refuses passthrough; `accept_spawn_masks` is named and recorded | PASS |
| II. Types over strings | The observer parses a string, but only as an interop shim behind a typed result and a self-check; results are `Option<bool>` and a typed `Unsupported::EnvClear` | PASS (justified: std has no getter) |
| III. Kernel is the oracle | Env tests run caged children on macOS, T1, T2 | PASS |
| IV. Syscalls only in the child | No child-side change | PASS |
| V. Hygiene by default | Strengthens env hygiene | PASS |
| VI. Private interfaces | std's `Debug` format is unstable; probed once per process, failure is a typed refusal | PASS |
| VII. Library | The self-check result is a probe result (allowed global state) | PASS |

## Project Structure

```text
src/unix.rs            # observer, self-check, environment() -> Result
src/hygiene.rs         # docs
src/macos/mod.rs       # Unsupported::EnvClear, env before run marker
src/linux/mod.rs       # Unsupported::EnvClear, docs (read everything)
src/lib.rs             # pub use … as native; docs
crates/procage-policy/src/lower/mod.rs  # accept_spawn_masks
tests/native.rs        # portable test
tests/spawn_macos.rs, tests/spawn_linux.rs   # env_clear tests
crates/procage-policy/tests/gaps.rs    # accept_spawn_masks
```

## Complexity Tracking

None.
