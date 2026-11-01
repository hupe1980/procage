# Quickstart: Vanished snapshot covers and honest report loss

## Results (2026-11-01, macOS 26.6.2; Docker Linux 7.0.14 aarch64)

| Check | Result |
|---|---|
| Churn test on T1 before the fix | fails at spawn 3 |
| Churn test on T1 after the fix | 300/300, three runs |
| `just linux-t1` | lib 36, spawn 47, escape 22 (and 22 with reporting), exec 20, native 5, unsafe 2 |
| `just ci` (macOS) | every gate passes |
| macOS spawn, escape, exec, native, lib | pass; no scratch folder left behind |
| Report loss (stress probe, 16 × 40 refused writes) | 558 of 640 seen by an independent `log stream` |
| T2 lanes, kernel-fact lanes | not rerun: the change only affects T1 mounts (T2 has none) and test helpers, which compile for Linux (cross-clippy); CI runs every lane after the push |

## Run

```sh
just ci
just linux-t1        # the churn test runs on T1 only
```
