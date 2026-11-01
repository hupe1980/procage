# Quickstart

1. `just linux` and `just linux-t1`: `spawn_linux` and `escape_linux` run the
   capped-ABI tests (1, 2, 3, 5, kernel) on T2 and T1.
2. Negative control: comment out the guard in the Linux lowering →
   `r31_*` fails at ABI 1 and 2 on both tiers.
3. `just kf-linux` / `just kf-linux-t1`: KF-L14 holds.
4. `just ci` on macOS: policy fixtures, `SameUser` caged test.

## Recorded outcomes

2026-11-01, macOS 26.6.2 and Docker Desktop (Linux 7.0.14-linuxkit, aarch64,
Landlock ABI 8):

| Gate | Result |
|---|---|
| `just ci` (fmt, clippy macOS and Linux targets, tests, docs, deny, msrv, no-std, semver, planning paths) | pass |
| `just linux` (T2) | pass; `r31_*`, `older_kernels_*`, `the_abi_cap_only_lowers`, `signals_reach_*` ran |
| `just linux-t1` (T1, T2 forced too) | pass; same tests ran |
| `just kf-linux` / `just kf-linux-t1` | 6 pass / 13 pass, 0 fail; KF-L14 PASS on both (unhandled: 3 of 3 routes emptied the file; handled: 0) |
| Negative control (guard disabled, `r31` on T1) | fails as expected: `ok ok ok ok n/a ok ok ok` instead of `1 1 1 38 n/a ok ok 1` at T1 ABI 1 |
| macOS `r25` with `SameUser` | the parent stays unsignallable under `hd-process-access`; waived, `SameUser` reaches it and `SelfAndChildren` does not |

`open` (the x86_64-only syscall) reports `n/a` on aarch64; its filter is
covered by the seccomp unit test.
