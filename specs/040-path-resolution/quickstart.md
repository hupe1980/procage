# Quickstart: validating path resolution

```sh
just linux-t1 && just linux                              # T1 and T2
PROCAGE_RACE_ATTEMPTS=10000 cargo test -p procage \
  --test escape_linux r33 -- --nocapture                 # T1 host
cargo test -p procage --test spelling_macos --test escape_macos r37   # macOS
just kernel v5.15=1 v7.3.1=11                            # mainline kernels
just bench                                               # T1 in Docker
```

## R-33 before the change (2026-11-03)

The canaries ran against the 0.4.0 build (only the test hook ported) on
Linux 7.0.14-linuxkit (aarch64, Landlock ABI 8), tier T1 in a container.

| Mount kind | Link planted | Directory renamed in |
|---|---|---|
| protect | redirected: the protected directory, moved aside, was writable | redirected |
| hide (directory) | redirected: the hidden file, moved aside, was readable | redirected |
| hide (file) | redirected | redirected |
| pin and class cover (`.git`) | redirected | redirected |
| class cover (`.vscode`) | redirected | redirected |
| foreign-socket cover | redirected | redirected |

Racing: 1,000 attempts, 40 ran, and at least one of them overwrote the
protected file (it read `canary` afterwards). The race is winnable, so R-33 is a fix with a Security entry, not
hardening.

## After the change

| Check | Result |
|---|---|
| Deterministic canary, 6 kinds × 2 plants | every spawn refused with `MountMoved` naming the planned path (and the link) |
| Racing canary, 10,000 attempts | 3,130 ran, 6,870 refused, protected file unchanged |
| Multithreaded T1 test (1,000 spawns, every mount kind, 4 churning threads) | passed |
| A socket removed and rebound during 300 spawns | no spawn failed |
| `just linux-t1` and `just linux` (container, 7.0, ABI 8) | passed |
| `just kernel v5.15=1 v7.3.1=11` (mainline, Landlock ABI 1 and 11) | passed, R-33 canaries and the race included |
| macOS 26.6.2: `just test`, `just escape`, `spelling_macos` | passed |
| CI run 41632414082 (`43faa47`, released as 0.4.1): every lane, the spelling matrix on macOS 26 and 27, the 10,000-attempt race on each T1 lane, eight kernels | passed |

The first CI run (41628757579) failed on every T1 lane and kernel: a runner's
root-only `/run/podman/podman.sock` made holding its cover fail with `EACCES`.
Such a cover is skipped again, as in 0.4.0 (plan, step 2).

## Spawn latency (SC-003)

`just bench` on T1 in Docker (Linux 7.0.14-linuxkit, aarch64), median of
300 spawns of a cached `minimal::v3` cage:

| Build | T1 | T2 |
|---|---|---|
| 0.4.0 | 1.160 ms | 0.507 ms |
| 0.4.1, run 1 | 1.114 ms | 0.507 ms |
| 0.4.1, run 2 | 1.147 ms | 0.515 ms |

No measurable change (limit: +10%).
