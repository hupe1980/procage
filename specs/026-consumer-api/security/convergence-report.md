## Security Convergence — 026-consumer-api

Commit `89fe752` · 2026-10-31T18:35:16Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
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
| SR-001 | verified | test | `tests/spawn_macos.rs::env_clear_keeps_the_caller_environment_out, tests/spawn_linux.rs::env_clear_keeps_the_caller_environment_out` | An uncaged runner holding PROCAGE_SECRET spawns caged children whose command called env_clear and set A, under passthrough and under an allowlist naming the secret and PATH; both children see exactly A and PROCAGE_CHILD, on macOS and Linux T1/T2. With the clear ignored the test fails with the whole caller environment. |
| SR-002 | verified | test | `src/unix.rs::tests::the_decision_fails_closed_only_for_passthrough, src/macos/mod.rs:614, src/linux/mod.rs:644` | The decision returns an error for passthrough whenever the observer failed its check or saw an unknown shape, and keeps allowlists working; both spawn paths map the error to Unsupported::EnvClear before forking (macOS before taking a run marker; Linux at the environment step, which precedes the fork). |
| SR-003 | verified | test | `src/unix.rs::tests::values_cannot_fake_a_clear, src/unix.rs::tests::the_observer_works_with_this_std, src/unix.rs::tests::an_unexpected_shape_is_unknown` | Arguments, values, program name and working directory containing the marker lines do not report a clear; env_clear does; the self-check passes on std 1.99 (macOS and Linux) and an unexpected shape is unknown. |
| SR-004 | verified | test | `tests/native.rs::a_granted_file_is_read_through_the_common_subset, tests/native.rs::kill_all_and_detach_have_the_same_meaning, tests/native.rs::errors_explain_themselves` | The test file uses only procage::native with no cfg in its bodies, and passes on macOS, Linux T2 and T1. |
| SR-005 | verified | test | `crates/procage-policy/tests/gaps.rs::reading_everything_on_t1_needs_exactly_the_spawn_masks` | Reading / on T1 is refused naming hd-secrets without options; accept_spawn_masks holds exactly the three constructs; the plan lowers with them listed in its degradations; adding a glob rule is still refused. |
