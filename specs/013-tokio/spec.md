# Feature Specification: Async integration (tokio)

**Feature Branch**: `013-tokio` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented (2026-11-02)

**Input**: Agent runtimes and MCP hosts are asynchronous. With 0.1.0 they either block a thread on `wait()`, or let a `tokio::process::Command` start a helper that calls `Cage::exec`. A native async path would let them spawn caged children, await them, stream their output and violations, and keep `kill_on_drop` semantics, without a helper process.

## Context

procage is a library with no async runtime; that stays the default (an
async integration only ever sits behind an opt-in feature). The std API
(`Cage::spawn` returning a child handle that kills the run on drop, violations
on a bounded std channel) is unchanged.

## Clarifications

### Session 2026-11-01

- Q: Which runtime? → A: tokio only, behind the feature `tokio`. Other
  runtimes can use the std API or `Cage::exec`.
- Q: Same guarantees as the std path? → A: Yes: the same child sequence, the
  same hygiene, and the whole run killed when the async handle is dropped or
  killed — including descendants.

### Session 2026-11-02

- Q: What does the API look like? → A: `Cage::spawn_async` and
  `Cage::spawn_async_with_fds` take a `tokio::process::Command` and return
  `AsyncChild`: the backend's child handle over a tokio child, with the same
  methods (audit, receipt, violations, detach, dropped_env, tmpdir); it
  dereferences to `tokio::process::Child`, and `kill_all` is async. The
  child sequence is installed on the command's std half, so it is the same
  code as the std path.
- Q: Which stream type? → A: `AsyncChild::violation_stream` (once) returns a
  `ViolationStream` with `next().await` that implements
  `futures_core::Stream`. It and the std receiver end when the run's record
  is complete or reporting stops.
- Q: How are the suites run through the async path? → A: The escape suites'
  spawn helpers switch to `spawn_async` when built with the feature and run
  with `PROCAGE_ASYNC=1`; CI runs them both ways on every lane. A dedicated
  async test file covers the handle (output, drop, kill, concurrency,
  stream).
- Q: A runtime without the I/O driver? → A: No runtime is a typed error
  (`SpawnError::NoRuntime`) before anything forks. tokio itself requires
  `enable_io` for any child process and offers no way to probe it; the docs
  state the requirement.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Spawn and await a caged command (Priority: P1)

**Independent Test**: Under a tokio runtime, spawn a caged command with piped
output, read it asynchronously, await its exit; on both backends and tiers.

**Acceptance Scenarios**:

1. **Given** the feature enabled, **When** a caged command is spawned from a
   tokio `Command`, **Then** it runs caged exactly as with the std API (the
   spawn and escape tests run in both modes).
2. **Given** the async handle dropped before exit, **Then** every process of
   the run is killed.
3. **Given** many concurrent runs on a multithreaded runtime, **Then** they
   stay isolated (violations, run markers, temporary directories).

---

### User Story 2 - Violations as a stream (Priority: P2)

**Acceptance Scenarios**:

1. **Given** violation reporting, **When** the child is denied, **Then** the
   violation arrives on an async stream while the child runs, and the stream
   ends when the record is complete.

### Edge Cases

- Cancellation while the child is between fork and exec: the spawn completes
  or fails as a unit; no half-caged process.
- No tokio runtime on the calling thread: a typed error before the fork, not
  a panic. A runtime without `enable_io` is tokio's precondition for every
  child process and is documented.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: With the `tokio` feature, procage MUST spawn caged children from
  a tokio command on both backends, with the std path's guarantees.
- **FR-002**: The async handle MUST kill the whole run on drop and on kill.
- **FR-003**: Violations MUST be available as an async stream that ends when
  the run's record is complete.
- **FR-004**: Without the feature, procage MUST NOT depend on any async
  runtime (checked by the dependency tree).
- **FR-005**: CI MUST build and test the crate with and without the feature.

## Success Criteria *(mandatory)*

- **SC-001**: The escape suites pass through the async path on every lane,
  and the async test file passes on macOS and Linux T1 and T2.
- **SC-002**: The default build's dependency tree is unchanged.

## Assumptions

- tokio's process support exposes the pre-exec hook the child sequence needs
  (it wraps std's command).

## Out of Scope

- async-std, smol and other runtimes.
