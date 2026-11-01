## Security Convergence — 009-escape-suite

Commit `b295ea6` · 2026-10-30T20:43:30Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
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
| SR-001 | verified | test | `tests/escape_macos.rs::r05_modifying_fcntl_commands_are_refused, tests/escape_macos.rs::r10_runs_do_not_share_temporary_files, tests/escape_linux.rs::r22_terminal_input_injection_is_refused` | Every active canary asserts the exact errno or typed error next to a control (granted target, or class waived with access opened); r10 holds the first tmpdir alive so ENOENT cannot pass; all pass on macOS, T1 and T2. |
| SR-002 | verified | test | `tests/escape_linux.rs::r28_filter_bypassing_interfaces_are_refused, tests/escape_linux.rs::r29_nested_user_namespaces_and_mount_changes_are_refused` | syscalls() prints informative= per call and only counts calls whose waived control is not refused; on a T1 host at least two must be informative. Observed informative=false on Docker T2 and true on T1 (quickstart.md). |
| SR-003 | verified | test | `tests/threat_model.rs::mitigated_on_one_platform_only_is_caught, tests/threat_model.rs::ignored_canary_as_evidence_is_caught, tests/threat_model.rs::mitigated_with_an_open_canary_is_caught, tests/threat_model.rs::evidence_in_another_test_file_is_caught` | Each test mutates the real catalog or suite and asserts exactly the expected rule fires; all 26 gate tests pass. |
| SR-004 | verified | test | `tests/threat_model.rs::missing_canary_is_caught, tests/threat_model.rs::partial_without_a_note_is_caught, tests/threat_model.rs::gate` | Coverage and open-variant rules have defect tests; the real catalog passes with R-23/R-25 partial and noted; the release status names R-08, R-23 and R-25 (reviewed in THREAT_MODEL.md). |
| SR-005 | verified | test | `tests/escape_linux.rs::r21_an_inherited_descriptor_does_not_reach_the_child` | host_tier() asserts PROCAGE_EXPECT_TIER in every Linux canary; `just linux T1` in the T2 container failed with TIER MISMATCH; spawn errors (including AlreadySandboxed) panic, never skip; ci.yml runs escape_macos in every macOS lane and spawn_linux + escape_linux in every Linux job, with the tier set where known. |
| SR-006 | verified | test | `tests/escape_macos.rs::r23_a_double_forked_descendant_dies_with_the_run, tests/escape_macos.rs::r23_a_launch_agent_cannot_be_planted` | Open lifetime canaries kill the surviving pid before asserting (no sleeper left after the --ignored run, checked with pgrep); the launch-agent canary removes any created plist; all other writes go to scratch or fake homes; service canaries only look up names. |
| SR-007 | verified | evidence | `specs/009-escape-suite/quickstart.md#Recorded-outcomes` | Five defects (two macOS, three Linux) were injected one at a time and each made a canary fail; two canaries were strengthened until their defect was caught. |
