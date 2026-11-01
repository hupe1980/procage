# Quickstart: validating 008

1. `just ci` on macOS — all gates, including clippy for both Linux targets.
2. `just linux` — T2 container (Docker defaults): `spawn_linux` passes, header reports `tier T2 abi 8`.
3. `just linux-t1` — T1 container (seccomp unconfined): `spawn_linux` passes, header reports `tier T1`.
4. `PROCAGE_EXPECT_TIER=T1 just linux` — fails with a tier mismatch (never skips).
5. Defect checks: (a) drop the seccomp install → `hard_deny_syscalls` fails; (b) skip the data-class masks → `t1_secrets_masked` fails; (c) skip the cap drop → `t1_no_capabilities` fails; (d) treat T2 covered classes as exact in the lowering → the gap test fails.
6. Latency: `cargo test --test spawn_linux -- --ignored latency` in each container; record the median.

## Recorded outcomes (2026-10-30, macOS 26.6.2 host; Docker 7.0.14-linuxkit aarch64, Landlock ABI 8, errata 7)

| # | Outcome |
|---|---|
| 1 | `just ci`: all 10 gates pass (lint and doc now also for aarch64 and x86_64-musl Linux) |
| 2 | `just linux`: tier T2 (userns errno 1); 17 unit + 26 caged + 2 confinement tests pass; under Docker's profile only `ptrace` (and `open_tree`) controls are informative, the rest are already denied |
| 3 | `just linux-t1`: tier T1; all pass; all nine syscall controls informative, for T1 and forced-T2 children |
| 4 | `just linux T1` in the default container: `TIER MISMATCH` (measured T2), exit 101 |
| 5 | Defects: (a1) seccomp call removed → spawn stopped at `verify sandbox`; (a2) seccomp and verify removed → `hard_deny_syscalls` fails (ptrace ESRCH); (b) class masks dropped → `t1_masks_secrets` fails; (c) cap drop removed → `t1_children_hold_no_capabilities` fails; (d) T2 covered classes exact → `t2_cannot_enforce_classes` fails |
| 6 | Latency, median of 50 spawns of `/bin/true`: T1 1.06 ms, T2 0.40 ms (SC-003 ✓) |
| 7 | First T1 run found two real issues: `/proc/<pid>/task/*/children` did not find a grandchild in its own session (tree walk now uses parent ids from `/proc/*/stat`), and killed orphans stay zombies under a non-reaping container init (the liveness probe ignores zombies) |
