## Security Convergence — 032-fit

Commit `313b15d` · 2026-11-01T00:38:03Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
| Open blocking threats | 0  |
| Security requirements | 4 |
| verified | 4 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage-policy/tests/fit.rs::a_gap_without_a_named_relaxation_changes_nothing` | Unnamed gaps are returned and the policy is unchanged; approximations_are_never_relaxed and only_the_rule_the_gap_names_is_left_out cover the other two scenarios (a stray subject relaxes nothing); tests/spawn_linux.rs::a_fitted_cage_gives_up_only_what_was_named shows Cage::fit failing with exactly the signal gap when its relaxation is missing. |
| SR-002 | verified | test | `tests/spawn_linux.rs::a_fitted_cage_gives_up_only_what_was_named` | On T2 the list holds exactly the four relaxations applied (five below ABI 6), and Cage::fit builds the list from every applied relaxation (src/linux/mod.rs, src/macos/mod.rs). |
| SR-003 | verified | test | `crates/procage-policy/tests/fit.rs::lifts_come_from_lowering` | Signals at ABI 5 lift at ABI 6 without T1; protect lifts with T1; sockets lift with T1 only at maximum 8 and at ABI 9 with maximum 12; macOS and unreported gaps are unknown; the Linux caged test asserts the same lifts through Cage::fit. |
| SR-004 | verified | test | `tests/spawn_linux.rs::a_fitted_cage_gives_up_only_what_was_named` | The fitted T2 cage refuses an outside write (EACCES) and any socket (EPERM) while the relaxed .git is writable and .env readable. |
