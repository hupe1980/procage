# Contract: the async API (feature `tokio`)

```rust
use procage::native::{AsyncChild, Cage, Grants};

let cage = Cage::with_options(&policy, &CageOptions::default().with_violations())?;
let mut cmd = tokio::process::Command::new("/usr/bin/make");
cmd.stdout(std::process::Stdio::piped());
let mut child: AsyncChild = cage.spawn_async(&mut cmd, &Grants::new())?;
let mut stream = child.violation_stream().expect("reporting is on");
let status = child.wait().await?;          // tokio::process::Child::wait via Deref
child.kill_all().await?;                    // ends the run; the stream ends
while let Some(v) = stream.next().await { eprintln!("sandbox: {v}"); }
let receipt = child.receipt().expect("exited");
```

- `spawn_async` / `spawn_async_with_fds(&mut tokio::process::Command,
  &Grants[, &[BorrowedFd]])`: the std path's checks, child sequence and
  errors, plus `SpawnError::NoRuntime` when no tokio runtime runs on the
  calling thread. The runtime must have the I/O driver (`enable_io`).
- `AsyncChild`: `Deref<Target = tokio::process::Child>`; `audit`,
  `receipt`, `violations`, `violation_receiver`, `dropped_env`, `tmpdir` as
  on `Child`; `async fn kill_all`; `violation_stream` (once; `None` when
  reporting is off or unavailable, or the std receiver was taken);
  `detach` returns the `tokio::process::Child`.
- Dropping an `AsyncChild` ends the run as dropping a `Child` does, inside
  or outside a runtime.
- `ViolationStream`: `async fn next(&mut self) -> Option<Violation>`;
  `impl futures_core::Stream<Item = Violation>`; ends when the run's record
  is complete or reporting stops. Buffer 1,024; when it lags, later
  violations are only in `violations()`.
- Without the feature none of these exist and procage has no async
  dependency.
