# Quickstart: validating 005-hygiene

Run these from a plain terminal on macOS, outside any sandbox.

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Caged-child tests | `cargo test -p procage --test spawn_macos` | all pass |
| 2 | Environment filter unit tests | `cargo test -p procage --lib hygiene` | pass |
| 3 | Latency with 1,000 extra fds (SC-004) | `cargo test -p procage --release --test spawn_macos latency -- --ignored --nocapture` | overhead printed |
| 4 | All gates | `just ci` | green |

Defects to inject (each must fail a named test):

1. The fd sweep is skipped.
2. The descendant walk is skipped.
3. The passthrough denylist is empty.
4. The tmpdir is not removed on drop.

## Recorded outcomes

Recorded 2026-10-30 on macOS 26.6.2 (25G83), outside any sandbox.

| # | Outcome |
|---|---|
| 1 | Pass: 30 caged-child tests (8 new for 005). |
| 2 | Pass: 4 unit tests of the pure environment filter. |
| 3 | Recorded, release build, caller holding 1,000 extra fds with a 1,048,576 soft limit: median plain 0.80 ms, caged 1.43 ms, so 0.63 ms overhead (≤ 5 ms). |
| 4 | Pass: `just ci`, all 10 gates. The kernel facts gave 28 pass. |

Injected defects. Each was caught and restored (with the restore time
refreshed):

| Defect | Failing tests |
|---|---|
| The fd sweep is skipped | `an_inherited_descriptor_does_not_reach_the_child`, `a_thousand_open_descriptors_are_all_closed`, `resource_limits_are_set_in_the_child` |
| The descendant walk is skipped | `dropping_the_handle_kills_every_descendant` |
| The passthrough denylist is empty | `passthrough_drops_secrets_unless_set_explicitly` |
| The tmpdir is not removed | `each_run_gets_its_own_private_tmpdir` |

Notes:

- **A named fd that is not open** cannot be built in safe Rust, because
  `BorrowedFd` guarantees an open descriptor. The runtime check stays as
  defense in depth (for example, a descriptor closed by another thread), but
  no safe test can reach it.
- **`/dev/null`**: a caged process cannot open `/dev/null` (`Stdio::null()`)
  without a grant. The base profile (006) owns the `/dev` allowlist.
- **The intermediary environment test** uses `DYLD_PROCAGE_PROBE`: a real
  `DYLD_INSERT_LIBRARIES` is honoured by dyld and would crash the uncaged
  intermediary.
