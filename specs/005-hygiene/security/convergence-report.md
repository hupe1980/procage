## Security Convergence — 005-hygiene

Commit `1fd636f` · 2026-10-30T07:54:32Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 7 |
| verified | 7 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/spawn_macos.rs::an_inherited_descriptor_does_not_reach_the_child; tests/spawn_macos.rs::a_thousand_open_descriptors_are_all_closed` | A descriptor to a file, left inheritable by clearing close-on-exec, does not exist in the caged child (fd_is_open false). With 1,000 inheritable descriptors open, the child counts 0 fds of 3 or more. The sweep in sys.rs (mark_fds) uses only proc_info via proc_pidinfo, fcntl and getdtablesize on a parent-allocated buffer. Skipping the sweep fails both tests. |
| SR-002 | verified | test | `tests/spawn_macos.rs::an_inherited_descriptor_does_not_reach_the_child; src/macos/mod.rs::tests::a_descriptor_that_is_not_open_is_refused; specs/005-hygiene/quickstart.md#Recorded-outcomes` | A descriptor handed over with spawn_with_fds is open in the child, and naming stdout is a no-op. A closed descriptor number gives SpawnError::Fd from kept_fds; safe code cannot build a BorrowedFd for a closed fd, so the check is unit-tested. Recorded latency with 1,000 extra fds and a 1,048,576 soft limit is 0.63 ms overhead. |
| SR-003 | verified | test | `tests/spawn_macos.rs::a_failed_step_after_the_sweep_is_still_reported` | With the sweep in place, a failing rlimit step (NOFILE u64::MAX) still returns SpawnError::Apply{step Rlimit}. The sweep marks close-on-exec rather than closing, so std's error pipe keeps working. |
| SR-004 | verified | test | `tests/spawn_macos.rs::dropping_the_handle_kills_every_descendant; tests/spawn_macos.rs::a_reaped_leader_still_takes_its_group_down; tests/spawn_macos.rs::a_detached_child_keeps_running` | A caged child starts a same-group sleeper and a setsid sleeper; dropping the handle kills the child and both sleepers within 1 s. After the caller reaps the leader, dropping still kills the remaining group member. A detached child keeps running. Skipping the descendant walk fails the first test, because the setsid sleeper survives. |
| SR-005 | verified | test | `tests/spawn_macos.rs::passthrough_drops_secrets_unless_set_explicitly; src/hygiene.rs::tests::passthrough_drops_the_default_denylist_and_reports_it` | An uncaged intermediary with GITHUB_TOKEN, SSH_AUTH_SOCK and a DYLD_ variable spawns a passthrough caged child. The child sees none of them, all three are listed in dropped_env, and an explicit GITHUB_TOKEN is visible. Unit tests cover every pattern (DYLD_, AWS_, LD_*, SSH_AUTH_SOCK, the _TOKEN, _SECRET, _PASSWORD and _API_KEY suffixes). An empty denylist fails the caged test. |
| SR-006 | verified | test | `tests/spawn_macos.rs::each_run_gets_its_own_private_tmpdir` | Two spawns with a tmpdir grant get different TMPDIRs, each child writes its own, both directories are gone after the handles drop, and binding tmpdir explicitly is GrantError::Reserved. The directory is created with mode 0700 (DirBuilder). Not removing it on drop fails the test. |
| SR-007 | verified | review | `src/macos/mod.rs:21; src/lib.rs:8; THREAT_MODEL.md#Release-status; README.md:8; tests/threat_model.rs::gate` | I reviewed the docs. The macos module docs list each observed hygiene behaviour, backed by named tests, and keep the double-fork escape, pseudo-terminals, the base profile and /dev/null as not done. The crate docs, README and threat-model release status say the same. Escape-class statuses are unchanged and the catalog gate passes. |
