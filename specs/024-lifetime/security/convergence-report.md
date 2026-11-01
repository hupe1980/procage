## Security Convergence — 024-lifetime

Commit `99c653d` · 2026-10-31T18:10:34Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 8 |
| verified | 8 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/escape_linux.rs::r23_sessions_are_locked, tests/escape_linux.rs::r23_a_double_forked_descendant_dies_with_the_run` | Run in Docker T2 (default seccomp) and T1 (unconfined, T1 and T2 cages); the sessions canary asserts setsid and setpgid return EPERM (1 1) in a non-leader caged process, and the double-fork canary asserts the descendant is dead within two seconds after drop. |
| SR-002 | verified | test | `tests/escape_macos.rs::r23_a_double_forked_descendant_dies_with_the_run` | The descendant double-forks, starts its own session and is reparented to launchd; the canary asserts it is alive before drop and dead within two seconds after. With the marker kill disabled the canary fails (negative control recorded in quickstart.md). |
| SR-003 | verified | test | `tests/escape_macos.rs::r23_descendants_of_an_exited_child_die_with_the_run, tests/escape_linux.rs::r23_descendants_of_an_exited_child_die_with_the_run` | The child starts a descendant (in its own session on macOS, in the group on Linux), exits and is waited for; the canary asserts the descendant outlived the child and dies after drop, on macOS and on Linux T1 and T2. |
| SR-004 | verified | test | `tests/spawn_macos.rs::the_run_marker_matches_only_its_run, crates/procage-policy/tests/precedence.rs::a_forking_policy_ends_with_the_run_marker` | The spawn test asserts the marker search finds exactly the run's child and not a second run, the caller or an (allow default) sandbox-exec process; the lowering test asserts the marker block is last, uses only the two bound params and no extension filter, and is absent without fork. |
| SR-005 | verified | test | `tests/escape_macos.rs::r23_concurrent_runs_are_separate, tests/escape_macos.rs::r23_a_detached_run_keeps_its_marker, src/macos/lifetime.rs::tests::slots_are_reused_only_when_freed` | Two runs of one cage get different slots and dropping one leaves the other's escaped descendant alive; after detach a later run gets another slot and ending it leaves the detached run's descendant alive; the unit test asserts freed slots are reused and dropped (retired) ones are not. |
| SR-006 | verified | test | `src/macos/lifetime.rs::tests::a_run_that_keeps_living_is_reported, src/macos/child.rs:83` | The unit test drives reap with a search that always finds pid 4242 and asserts an error naming it after the round limit; kill_all calls lifetime::end (reap over the marker search) and returns its error before freeing the slot (reviewed at the cited line). A search failure is an error, never an empty result. |
| SR-007 | verified | test | `crates/procage-policy/tests/gaps.rs::the_linux_lifetime_lock_follows_the_setting, crates/procage-policy/tests/lowering_table.rs, crates/procage-policy/tests/presets.rs::presets_keep_descendants_in_the_run` | The lock appears only for fork plus Lifetime::Run and not for Tree or without fork; the lowering table test lowers lifetime-run and lifetime-tree on every target and checks the documented outcomes; every preset carries Lifetime::Run. Syscall numbers are checked natively (aarch64 here; x86_64 in CI after a push). |
| SR-008 | verified | test | `tests/threat_model.rs::statuses_are_parsed` | The catalog gate passes with R-23 mitigated; every evidence test it names exists; no R-23 canary is ignored, and the R-23 canaries passed on macOS, T1 and T2. |
