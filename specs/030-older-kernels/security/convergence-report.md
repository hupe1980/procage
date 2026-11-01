## Security Convergence — 030-older-kernels

Commit `2657b32` · 2026-10-31T23:30:55Z

| Metric | Value |
|---|---|
| Threats (active) | 5 |
| Open blocking threats | 0  |
| Security requirements | 5 |
| verified | 5 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/escape_linux.rs::r31_files_outside_the_writable_paths_cannot_be_truncated` | On T1 and T2 with the ABI capped at 1 and 2, truncate, openat read-only and no-access with O_TRUNC fail with EPERM and openat2 with ENOSYS, every outside file keeps its content, and writing plus set_len inside the workspace work; at ABI 3 Landlock refuses them (EACCES). With the guard disabled the canary fails (all four routes succeed). |
| SR-002 | verified | test | `tests/spawn_linux.rs::older_kernels_keep_writes_the_network_and_hard_denies` | On T2 (and T1) at capped ABIs 1, 2, 3, 5 and 8 a workspace write works, an outside write fails with EACCES, UDP and TCP sockets and ptrace fail with EPERM. |
| SR-003 | verified | test | `tests/spawn_linux.rs::signals_reach_outside_processes_only_when_the_policy_says_so` | Capped at ABI 5 SelfAndChildren is a gap naming signals-self-and-children; at ABI 8 it refuses a signal to an outside process (EPERM); only SameUser delivers it; macOS r25 shows the hard-deny class still applies to SameUser. |
| SR-004 | verified | test | `tests/spawn_linux.rs::the_abi_cap_only_lowers` | A cap of 200 reports and plans the kernel ABI (8); a cap of 0 is Unsupported::Landlock { abi 0, needed 1 }; the r31 and matrix tests assert Cage::landlock_abi equals the cap, and one value feeds the tier check, lowering and ruleset (src/linux/mod.rs Cage::with_options). |
| SR-005 | verified | review | `src/linux/mod.rs (Kernels section), crates/procage-policy/src/lowering.md, THREAT_MODEL.md` | The Kernels table states the truncation guard and its side effect (ABI 3), passed IP sockets on T2 (ABI 4) and unscoped signals with SameUser (ABI 6); the lowering table states both tiers' minimum, the guard and the signals-same-user row; THREAT_MODEL lists the limits and R-31. |
