# Quickstart: validating the tokio integration

```sh
cargo test -p procage --features tokio --test tokio          # the async handle
PROCAGE_ASYNC=1 cargo test -p procage --features tokio --test escape_macos
just linux && just linux-t1                                  # includes both modes
just features                                                # default tree has no tokio
```

Expected:

- `tokio` tests: piped output read asynchronously; exit awaited; a dropped
  handle kills a tree with a double-forked, own-session descendant; 32
  concurrent runs on a multithreaded runtime keep their violations, temporary
  directories and markers apart; the stream yields a denial while the child
  runs and ends after `kill_all`; outside a runtime `spawn_async` returns
  `NoRuntime` and nothing forked.
- The escape suites pass with `PROCAGE_ASYNC=1` on macOS, T1 and T2.
- `just features` prints no async crate for the default build.

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | `tests/tokio.rs` | 8 passed, three runs in a row |
| macOS 26 (arm64) | `escape_macos`, std and `PROCAGE_ASYNC=1` | 28 passed, 1 ignored (an open class), both modes |
| Linux T2 (container, kernel 7.0, ABI 8) | `just linux`, async step | escape suite 31 passed, 1 ignored; `tokio` 8 passed |
| Linux T1 (container, kernel 7.0, ABI 8) | `just linux-t1` | every suite green; async escape suite 31 passed, 1 ignored; `tokio` 8 passed (T1 and T2 cages) |
| macOS | `just features` | the default build has no tokio, mio or futures crate |

On a loaded macOS host the denial reports are best effort: under 32
concurrent runs some reports of a run can be lost, so on macOS the
concurrency test checks that runs stay apart and that a run sees its own
denial, and on Linux that every run sees its own. The `spawn_macos`
violation tests that bound the fence at one second fail intermittently on
the same host with and without this change; the CI lanes run them on fresh
runners.
