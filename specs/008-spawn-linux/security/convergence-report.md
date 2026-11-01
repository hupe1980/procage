## Security Convergence — 008-spawn-linux

Commit `fbf108d` · 2026-10-30T18:26:37Z

| Metric | Value |
|---|---|
| Threats (active) | 12 |
| Open blocking threats | 0  |
| Security requirements | 12 |
| verified | 12 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/spawn_linux.rs::files_outside_the_policy_are_refused` | On T1 and T2 (just linux, just linux-t1) the child reads R/f and writes W/g, and gets EACCES reading and listing outside both and writing R/h; a_grant_applies_to_its_spawn_only shows a binding grants only its spawn. |
| SR-002 | verified | test | `tests/spawn_linux.rs::hard_deny_syscalls_are_refused` | On the T1 lane all nine probed syscalls (ptrace, io_uring_setup, bpf, keyctl, unshare, setns, perf_event_open, userfaultfd, open_tree) get EPERM in T1 and forced-T2 children with informative controls; src/linux/seccomp.rs::tests::every_policy_denies_the_hard_deny_syscalls shows the filter of every policy returns EPERM for mount, umount2, pivot_root, move_mount, fsopen, fsmount and the rest, whose kernel errno is ambiguous without privilege. |
| SR-003 | verified | test | `src/linux/seccomp.rs::tests::an_x86_64_filter_kills_x32_and_i386_calls` | An x86_64 filter, built on any host, kills an x32 syscall number and an i386 call and allows a native one; a_foreign_architecture_is_killed covers the native aarch64 filter (ran in both containers). |
| SR-004 | verified | test | `tests/spawn_linux.rs::t2_cannot_protect_inside_a_writable_tree` | T2 preparation fails with an unsupported fs-protect gap and an allowed fs-literal approximation is recorded; t1_on_a_host_without_user_namespaces_is_unsupported ran on the T2 lane and got Unsupported::Tier. |
| SR-005 | verified | test | `tests/spawn_linux.rs::a_failed_step_is_named_and_the_target_does_not_run` | A limit above the hard limit gives Apply{step Rlimit} and the touch target never created its marker, on both tiers; with the seccomp call removed (defect a1) the verify step stopped the spawn. |
| SR-006 | verified | test | `tests/spawn_linux.rs::t1_masks_secrets_in_a_readable_home` | On T1 with a read rule on a home, .ssh and .aws are unreadable while the home lists, only after the approximation is accepted; waived, all succeed; t2_refuses_a_grant_that_reaches_secrets gets GrantError::CoversClass(secrets). |
| SR-007 | verified | test | `tests/spawn_linux.rs::t1_protects_trust_handoff_paths_in_a_writable_workspace` | Hooks, .git/config, .vscode and .bashrc give EROFS, renaming .git gives EBUSY, objects/index/refs/src succeed; waived hooks succeed; t2_cannot_enforce_classes_a_rule_reaches gets the hd-trust-handoff gap and the waiver is listed; t1_makes_persistence_paths_read_only refuses a systemd user unit. |
| SR-008 | verified | test | `tests/spawn_linux.rs::t1_children_hold_no_capabilities` | Effective, permitted and bounding sets are 0 in a T1 child; t1_protect_is_read_only_and_cannot_be_undone shows umount and rw remount fail and the subtree stays EROFS. |
| SR-009 | verified | test | `tests/spawn_linux.rs::without_network_nothing_is_reachable` | With Network::None a connect to a host loopback listener fails on T1 (netns) and T2, and on T2 socket creation gets EPERM. |
| SR-010 | verified | test | `tests/spawn_linux.rs::descriptors_reach_the_child_only_when_handed_over` | Leaked descriptors (200) are absent and a handed-over one is open; passthrough_drops_secret_variables, dropping_the_handle_kills_every_descendant and session_and_limits_are_the_policys cover env, lifetime and session on both tiers. |
| SR-011 | verified | test | `src/linux/classes.rs::tests::the_walk_does_not_follow_links` | A symlinked directory holding .vscode outside the tree yields no cover; tests/spawn_linux.rs::an_oversized_writable_tree_fails_the_spawn gets SpawnError::Walk with limit 10. |
| SR-012 | verified | test | `crates/procage-policy/tests/lowering_table.rs::every_row_matches_the_lowering` | Every Linux cell (data classes, gaps for relays, unix sockets below ABI 9, hide on T2, globs, signals below ABI 6) is checked against the lowering at each ABI; THREAT_MODEL.md escape statuses are unchanged (threat_model gate passes). |
