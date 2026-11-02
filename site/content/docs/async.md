+++
title = "Async: spawning on a tokio runtime"
description = "The tokio feature: Cage::spawn_async returns an awaitable caged child that still ends the whole run, and violations arrive as a stream."
weight = 79

[extra]
group = "Guides"
nav = "Async (tokio)"
+++

With the `tokio` feature, a cage spawns on a tokio runtime. Enable it in `Cargo.toml`:

```toml
procage = { version = "0.3", features = ["tokio"] }
```

`Cage::spawn_async` takes a `tokio::process::Command` and returns an `AsyncChild`. It dereferences to `tokio::process::Child`, so you await the exit and read the pipes as with any tokio child:

```rust
use std::process::Stdio;
use procage::native::{Cage, CageOptions, Grants};
use tokio::io::AsyncReadExt;

let cage = Cage::with_options(&policy, &CageOptions::default().with_violations())?;
let mut cmd = tokio::process::Command::new("make");
cmd.stdout(Stdio::piped());
let mut child = cage.spawn_async(&mut cmd, &Grants::new())?;

let mut stream = child.violation_stream().expect("reporting is on");
let mut out = String::new();
child.stdout.take().unwrap().read_to_string(&mut out).await?;
let status = child.wait().await?;
child.kill_all().await?; // ends the run; the stream ends with it

while let Some(v) = stream.next().await {
    eprintln!("sandbox: {v}");
}
let receipt = child.receipt().expect("the child exited");
```

## What stays the same

- **The cage.** The policy checks, the child sequence and the spawn errors are those of `Cage::spawn`: procage installs the sequence on the command's std half and tokio forks it.
- **The run's lifetime.** The run ends when the `AsyncChild` is dropped or `kill_all` is awaited, not when the child exits by itself; ending it kills every process of the run, double-forked daemons included. Dropping it works inside and outside the runtime. `kill`, reachable through `Deref`, kills only the direct child.
- **The record.** `audit`, `receipt`, `violations`, `dropped_env` and `tmpdir` work as on `Child`.

## The violation stream

`violation_stream` returns the run's violations as they happen, once. It is `None` when reporting is off or unavailable, or when `violation_receiver` was taken. `stream.next().await` gives the next violation, and the stream also implements `futures_core::Stream`. It ends when the record is complete or the run ended. It buffers 1,024 violations; when it lags, later ones are only in `violations()`. On macOS the reports are best effort, as described in [Violations](@/docs/violations.md).

## Errors

- `SpawnError::NoRuntime`: no tokio runtime runs on the calling thread. Nothing was forked.
- The runtime needs its I/O driver (`enable_io`, or `#[tokio::main]`), as every tokio child process does.

Without the feature, none of this exists and procage has no async dependency: `just features` checks that the default build pulls in no tokio, mio or futures crate.
