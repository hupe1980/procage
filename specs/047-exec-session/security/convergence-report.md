## Security Convergence — 047-exec-session

Commit `9e687c4` · 2026-11-02T21:07:49Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
| Open blocking threats | 0  |
| Security requirements | 3 |
| verified | 3 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/exec.rs::a_session_exec_allows_groups_and_ends_by_session` | A helper started as a plain child calls Cage::exec_session of a shell; a descendant's perl setpgrp(0, 0) exits 0 on macOS, T1 and T2, and on Linux /usr/bin/setsid exits 1. Passed in both container lanes (Linux 7.0) and on macOS 26, 2026-11-02. |
| SR-002 | verified | test | `crates/procage/tests/exec.rs::a_session_exec_allows_groups_and_ends_by_session` | The shell forks a sleeper that calls setpgrp(0, 0) and reports its pid; procage::native::end_session(helper pid) kills it within two seconds, and the helper is reaped afterwards, on macOS, T1 and T2. |
| SR-003 | verified | test | `crates/procage/tests/exec.rs::a_session_exec_from_a_group_leader_is_refused` | A helper started with process_group(0) calls exec_session; it prints SpawnError::GroupLeader and exits 126 with no output from the command, on macOS, T1 and T2. end_session's pid guard (> 1) is in src/linux/mod.rs and src/macos/mod.rs at the top of the function. |
