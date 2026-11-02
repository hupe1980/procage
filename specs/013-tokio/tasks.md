# Tasks: Async integration (tokio)

## Phase 1: Setup

- [X] T001 Feature `tokio = ["dep:tokio", "dep:futures-core"]` with `tokio` 1.47 (`process`, `sync`) and `futures-core` 0.3 optional; dev-dependency `tokio` (`rt-multi-thread`, `io-util`, `time`); `[[test]] tokio` with `required-features = ["tokio"]`; docs.rs `features = ["tokio"]` — crates/procage/Cargo.toml

## Phase 2: Foundational

- [X] T002 Record: live sender as an enum (std `SyncSender`, tokio `mpsc::Sender`), `take_stream` moving what the std channel buffered, the sender dropped by `finish`, `interrupt` and a new `close`; `ViolationStream` (`next().await`, `futures_core::Stream`); unit tests: the stream yields, lags without blocking and ends on `finish` — crates/procage/src/violation.rs
- [X] T003 Handle core: internal `Proc` (`Std`, `Tokio`) with the pid at spawn, `try_wait`, bounded reap; `Child` methods on `Proc`; the run's end split into `signal` (descendants, group) and `end` (reap, marker search, record) on both backends; `close` the record when a run ends — crates/procage/src/macos/child.rs, crates/procage/src/linux/child.rs
- [X] T004 Spawn split into `launch` and `adopt` on both backends; `spawn_with_fds` unchanged in behaviour — crates/procage/src/macos/mod.rs, crates/procage/src/linux/mod.rs

## Phase 3: User Story 1 — Spawn and await a caged command (P1)

- [X] T005 [US1] `Cage::spawn_async`, `spawn_async_with_fds` (runtime check → `SpawnError::NoRuntime`, `launch` on `as_std_mut`, tokio spawn, `adopt`); `AsyncChild` (`Deref`/`DerefMut` to `tokio::process::Child`, delegated methods, `async fn kill_all`, `detach`); re-exported from `procage::native` — crates/procage/src/macos/mod.rs, crates/procage/src/linux/mod.rs, crates/procage/src/lib.rs
- [X] T006 [US1] Async tests: piped output and awaited exit; drop kills a double-forked own-session descendant; `kill_all().await` ends the run; 32 concurrent runs on a multithreaded runtime stay apart (violations, `TMPDIR`, results); outside a runtime `NoRuntime` and no process; T1 and T2 on Linux — crates/procage/tests/tokio.rs
- [X] T007 [US1] Escape suites: the spawn helpers go through `spawn_async` under `PROCAGE_ASYNC=1` with the feature — crates/procage/tests/escape_macos.rs, crates/procage/tests/escape_linux.rs

## Phase 4: User Story 2 — Violations as a stream (P2)

- [X] T008 [US2] `AsyncChild::violation_stream` (once; `None` when off, unavailable or the receiver was taken); test: a denial arrives while the child runs, the stream ends after `kill_all` — crates/procage/src/macos/child.rs, crates/procage/src/linux/child.rs, crates/procage/tests/tokio.rs

## Phase 5: Polish

- [X] T009 Gates: `--all-features` in lint, doc and test for `procage`; `just features` (default `cargo tree -e normal` has no tokio, mio or futures crate); CI: the gate, `tests/tokio.rs` and the escape suites with `PROCAGE_ASYNC=1` on every lane; `just linux`/`linux-t1`/`escape` likewise — justfile, .github/workflows/ci.yml
- [X] T010 Docs: crate docs section "Async (tokio)", site page `async.md`, README feature line, CHANGELOG Unreleased (Added; Changed: the std receiver ends when the record is complete) — crates/procage/src/lib.rs, site/content/docs/async.md, README.md, CHANGELOG.md
- [X] T011 Run `just ci`, `just escape` with and without `PROCAGE_ASYNC=1`, `just linux`, `just linux-t1`; results in specs/013-tokio/quickstart.md; spec status Implemented; commit on `main`
