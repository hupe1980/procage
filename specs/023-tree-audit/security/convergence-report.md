## Security Convergence — 023-tree-audit

Commit `25f401e` · 2026-11-02T06:33:35Z

| Metric | Value |
|---|---|
| Threats (active) | 15 |
| Open blocking threats | 0  |
| Security requirements | 15 |
| verified | 15 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/src/audit.rs::tests::class_files_and_globs_are_examined_and_nothing_else` | A class credential file with a name outside and a glob-matched file with a name outside are findings; a multi-link file under the glob prefix that the glob does not match is not; the strict hidden count and exact glob matching are unit-tested; the R-08 canaries pass on macOS, Linux T1 and T2. |
| SR-002 | verified | test | `crates/procage/tests/audit.rs::the_receipt_says_the_link_check_mode` | Refuse is the default (canaries); Report lists the finding and the receipt says report with one link; Off says off and not complete; passes on macOS and Linux T1/T2. |
| SR-003 | verified | test | `crates/procage/src/audit.rs::a_disguised_rewrite_is_modified; crates/procage/tests/audit.rs::what_a_run_left_behind_is_listed_once; crates/procage/tests/audit.rs::a_quiet_run_is_complete_and_empty` | A same-size rewrite with the modification time set back is Modified (change time in the key); a caged run's created .vscode/settings.json, modified .git/config, link with its target and nested .git are each counted exactly once; a quiet run is empty and complete. Passed locally on macOS; the integration tests are shared with Linux. |
| SR-004 | verified | test | `crates/procage/src/audit.rs::tests::walks_stay_put_and_say_what_they_could_not_read` | A closed directory is incomplete without a caller and when the caller owns it, and skipped when another user owns it; crates/procage/tests/audit.rs::a_quiet_run_is_complete_and_empty passes with a root-owned 1730 /var/spool/cron/crontabs as uid 65534 (Docker, 2026-11-02) and failed before the change; past_the_walk_limit_the_audit_is_incomplete still holds. |
| SR-005 | verified | test | `crates/procage/src/audit.rs::walks_stay_put_and_say_what_they_could_not_read; crates/procage/tests/audit.rs::what_a_run_left_behind_is_listed_once` | A tree holding a link loop and a link to the root is walked completely in under ten entries (the shared walker never follows links); the post-run snapshot lists a created link with its target read, not resolved (build -> /etc/passwd); walks descend only real directories on the root's device (audit.rs:372). |
| SR-006 | verified | test | `crates/procage/src/macos/child.rs, crates/procage/src/linux/child.rs` | Child::audit and Child::receipt end the run (kill_all) before the second walk; a failed end makes the handoff result incomplete (RunAudit::finish(ended)); before exit both return None (tests/audit.rs, tests/receipts.rs). |
| SR-007 | verified | test | `crates/procage/tests/audit.rs::paths_round_trip_exactly` | A name with an escape character (both systems) and a non-UTF-8 name (Linux) round-trip through the receipt as text or bytes (ReceiptPath); display escapes control characters (control_characters_are_escaped_in_messages). |
| SR-008 | verified | review | `crates/procage/src/macos/mod.rs:693; crates/procage/src/linux/mod.rs:859; crates/procage/tests/spawn_macos.rs::one_cage_spawns_from_several_threads` | before_spawn runs in the parent before command.spawn in both backends and RunAudit::finish runs from Child methods in the parent; no child-side code references the audit, and the multithreaded spawn test runs with the default link check. |
| SR-009 | verified | test | `crates/procage/tests/threat_model.rs::gate` | The gate passes (run locally) and enforces non-ignored canaries per platform for R-08 (mitigated, six r08 canaries); R-07 stays harness/documented and says the audit lists findings for the harness to review; audits.md and the crate docs say an incomplete result is never clean and nowhere call an empty audit proof. |
| SR-010 | verified | test | `crates/procage/tests/escape_macos.rs::r08_a_hard_link_to_a_protected_file_is_refused; crates/procage/tests/escape_linux.rs::r08_a_hard_link_to_a_protected_file_is_refused` | The same cage spawns cleanly, a second name is then given to a file under its protect subpath, and the next spawn is refused naming it; before_spawn re-walks the Targets on every spawn with no cached result (audit.rs:530). |
| SR-011 | verified | test | `crates/procage/tests/escape_macos.rs::r08_a_hard_link_to_a_protected_file_is_refused; crates/procage/tests/escape_linux.rs::r08_a_hard_link_to_a_hidden_file_is_refused; crates/procage/src/audit.rs::a_literal_target_that_became_a_link_is_a_finding` | On macOS and on every Linux tier a literal hide target that spawned cleanly is replaced by a symbolic link and the next spawn is refused with a symbolic finding; links() reads it with symlink_metadata and never follows it. |
| SR-012 | verified | test | `crates/procage/tests/escape_linux.rs::r08_no_hard_link_can_be_made_during_the_run` | On every lane a child's attempt to link a hidden file and a protected (T1) or read-only (T2, which cannot protect) file into the writable tree is refused, next to a write that succeeds; macOS asserts the same in its canary. |
| SR-013 | verified | test | `crates/procage/tests/audit.rs::the_receipt_counts_the_findings` | Without the policy the receipt JSON (policy and paths removed) holds no finding path and paths is None; with it paths is present; findings enter the summary only as counts (receipt.rs:443) and their paths only under the same gate. |
| SR-014 | verified | test | `crates/procage/tests/audit.rs::without_the_option_nothing_is_walked; specs/023-tree-audit/quickstart.md` | Without with_handoff_audit no snapshot is taken and handoff is None; walk_limit defaults to 200,000 on both systems; the recorded latency probe puts the default link check within SC-003 on macOS and Linux T1/T2. |
| SR-015 | verified | test | `crates/procage/src/audit.rs::the_refusal_names_every_file_and_the_way_out` | The refusal text lists two files each with its link count and names LinkAudit::Report and LinkAudit::Off; SpawnError's Display for HardLinks is that text on both systems (macos/mod.rs:326, linux/mod.rs:440) and carries every finding. |
