# Research: Async integration (tokio)

## R1: Spawning through tokio without new child code

- **Decision**: install the child sequence on `tokio::process::Command::as_std_mut()`
  and spawn with tokio's `spawn`.
- **Rationale**: tokio's spawn calls the std command's `spawn`, so the
  `pre_exec` hook, the error pipe and the environment are the std path's
  (tokio 1.47 source, `process/unix/mod.rs`). Only the parent side differs:
  tokio registers the pipes and the exit with its driver.
- **Alternatives**: spawn with std and convert the pipes
  (`ChildStdout::from_std`) — no async exit without a thread per run or a
  pidfd/kqueue reactor of our own; a tokio `Command` built from scratch —
  the caller's stdio and arguments would be lost.

## R2: The handle

- **Decision**: one handle core with a std/tokio process enum; `AsyncChild`
  wraps it.
- **Rationale**: every rule of the run's end (group kill, descendants,
  marker search, record fence, receipt, audit) stays in one place. tokio's
  `try_wait` delegates to the std child without a runtime, so `Drop` works
  anywhere.
- **Alternatives**: a public generic `Child<P>` (needs a public sealed trait,
  noisier docs); two copies of the handle (drift).

## R3: The stream

- **Decision**: a tokio bounded channel behind `ViolationStream`, which
  implements `futures_core::Stream` and has `next().await`.
- **Rationale**: the producers are threads; `mpsc::Sender::try_send` never
  blocks them, as the std channel did. `futures-core` is the trait every
  stream adapter uses and has no dependencies.
- **Alternatives**: `tokio-stream` (pulls more than the trait); bridging the
  std receiver with a thread per run.

## R4: Runtime checks

- **Decision**: `Handle::try_current()` before anything forks;
  `SpawnError::NoRuntime` otherwise. The I/O driver is documented as
  required.
- **Rationale**: tokio panics on a missing runtime or a disabled I/O driver
  when it registers the pipes; the first is checkable through its API, the
  second is not (tokio 1.54, `runtime/driver.rs`).
