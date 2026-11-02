# Implementation Plan: Async integration (tokio)

**Branch**: `013-tokio` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

A `tokio` feature adds `Cage::spawn_async` and `Cage::spawn_async_with_fds`
on both backends. They take a `tokio::process::Command`, install the
unchanged child sequence on its std half (`as_std_mut`), spawn through tokio
and return `AsyncChild`. The handle shares the run logic of the std `Child`
(kill on drop, tree and marker kill, record, receipt, audit) through one
internal process type with a std and a tokio variant. Violations stream
through a `ViolationStream` (`futures_core::Stream`).

## Technical Context

- **Language**: Rust 2024, MSRV 1.99.
- **New optional dependencies** (feature `tokio`): `tokio` 1.47 with
  `process` and `sync`; `futures-core` 0.3 (the `Stream` trait).
- **Dev-dependency**: `tokio` with `rt-multi-thread`, `io-util`, `time`
  (no macros).
- **Testing**: `tests/tokio.rs` (`required-features = ["tokio"]`); the
  escape suites' helpers under `PROCAGE_ASYNC=1`.
- **Targets**: macOS, Linux T1 and T2.

## Design

1. **Spawn split.** Each backend's `spawn_with_fds` becomes
   `launch` (everything before the fork: `prepare`, the link check, the
   violation registration) and `adopt` (everything after: supervisor,
   receipt facts, the handle). `spawn_with_fds` is `launch` →
   `std::process::Command::spawn` → `adopt`; `spawn_async_with_fds` checks
   `tokio::runtime::Handle::try_current()` (`SpawnError::NoRuntime`), then
   `launch(command.as_std_mut())` → `tokio::process::Command::spawn` →
   `adopt`. A failed spawn undoes `launch` the same way in both.
2. **One handle core.** `Child` keeps an internal `Proc` enum (`Std`,
   `Tokio`) with `try_wait`, a blocking reap (std `wait`; tokio: `try_wait`
   polled every millisecond, used only after the group was killed) and the
   pid taken at spawn. Every method of `Child` works on `Proc`; `Deref`
   yields the std child. `AsyncChild` wraps a `Child` whose `Proc` is
   `Tokio`, dereferences to `tokio::process::Child`, delegates `audit`,
   `receipt`, `violations`, `violation_receiver`, `dropped_env`, `tmpdir`,
   and has `async fn kill_all` (signals, `wait().await`, then the
   synchronous end: marker search and record fence on macOS, supervisor
   hang-up on Linux), `violation_stream` and `detach` (the tokio child).
   Drop is the std drop: signals and the bounded reap, no runtime needed.
3. **Stream.** `Record`'s live sender is an enum of a std `SyncSender` and a
   tokio `mpsc::Sender` (`try_send` from the monitor or supervisor thread,
   bound 1,024 as today). `take_stream` swaps in a tokio channel and moves
   what the std channel buffered. `finish`, `interrupt` and the end of a run
   drop the sender, so the std receiver and the stream both end.
4. **Suites.** The escape suites' `finish`/`in_child_with`/`run_in`/`start`
   helpers spawn through `spawn_async` on a shared multithreaded runtime
   when `PROCAGE_ASYNC=1` and the feature is on, converting the handle's
   pipes back with `into_owned_fd` so the canaries read output as before.
5. **Gates.** `just lint`, `doc`, `test` add `--all-features` for
   `procage`; a `features` gate checks that `cargo tree -e normal` of the
   default build names no tokio, mio or futures crate; CI lanes run
   `tests/tokio.rs` and the escape suites with `PROCAGE_ASYNC=1`;
   docs.rs builds with the feature.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | Same lowering, same refusals; no runtime is a typed error before the fork | PASS |
| III | The escape suites run through the async path on every lane | PASS |
| IV | No new code between fork and exec: the child sequence is the std one, installed on the same `std::process::Command` | PASS |
| V | Hygiene unchanged; drop kills the run without a runtime | PASS |
| VII | tokio only behind the opt-in feature; default dependency tree unchanged (gate); all-features build and docs | PASS |

## Project Structure

```text
crates/procage/
├── Cargo.toml                 # feature tokio, optional deps, [[test]] tokio
├── src/violation.rs           # Live sender enum, take_stream, ViolationStream
├── src/macos/{mod,child}.rs   # launch/adopt, Proc, AsyncChild, spawn_async
├── src/linux/{mod,child}.rs   # same
└── tests/
    ├── tokio.rs               # the async handle
    └── escape_{macos,linux}.rs  # helpers switch under PROCAGE_ASYNC=1
```

## Risks

- tokio's process driver reaps children it knows (SIGCHLD). `try_wait` on
  the tokio child is the reap; procage never calls `waitpid` on it itself.
- A tokio `Child` dropped by `detach` callers follows tokio's own
  `kill_on_drop` setting; procage's handle no longer applies.
