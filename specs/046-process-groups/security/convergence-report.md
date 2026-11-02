## Security Convergence — 046-process-groups

Commit `48a52d4` · 2026-11-02T19:53:38Z

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
| SR-001 | verified | test | `crates/procage/tests/escape_linux.rs::r23_sessions_are_locked` | In a forking default cage on T1 and T2, a process of the run that leads neither its session nor its group calls setsid (EPERM) and setpgid(0, 0) (ok); procage-policy/tests/gaps.rs the_linux_lifetime_lock_follows_the_setting asserts setsid denied with Tty::None and Tty::Inherit and setpgid only with Tty::Inherit. Passed in both container lanes (Linux 7.0, ABI 8), 2026-11-02. |
| SR-002 | verified | test | `crates/procage/tests/escape_linux.rs::r23_a_descendant_in_a_group_of_its_own_dies_with_the_run` | An intermediate starts /bin/sleep with process_group(0) and exits, so the sleeper is outside the child's group and tree; dropping the handle kills it within two seconds on T1 and T2. The existing R-23 canaries (double fork, exited child, descendants) pass unchanged. |
| SR-003 | verified | test | `crates/procage/tests/exec.rs::descendants_cannot_leave_the_group` | Through Cage::exec a shell's descendants run setsid (exit 1) and perl setpgrp(0, 0) (exit 1) on T1 and T2; the cage's exec filter adds the setpgid denial (src/linux/mod.rs exec_filter, chosen for Session::Keep). |
