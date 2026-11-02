## Security Convergence — 045-moves-and-link-exemptions

Commit `9348ab0` · 2026-11-02T17:37:46Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 6 |
| verified | 6 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/escape_linux.rs::r04_a_protected_file_stays_protected_when_an_ancestor_is_renamed` | On T1 renames the protected tree's ancestor in place and into another directory and asserts the protected file is unwritable under all three names and keeps its content; on T2 asserts the fs-protect gap. r30_a_protected_file_cannot_be_replaced asserts a rename from another directory onto the protected file fails with EBUSY (EXDEV at ABI 1). Both passed in the T1 and T2 container lanes (kernel 7.0, ABI 8), 2026-11-02. |
| SR-002 | verified | test | `crates/procage/tests/escape_linux.rs::r08_no_hard_link_can_be_made_during_the_run` | With REFER granted on the writable tree, links of a hidden file and of a protected one (on T2 a file of a read-only tree) into the writable tree are asserted to fail on every tier, with a write as control; passed on T1 and T2, 2026-11-02. |
| SR-003 | verified | test | `crates/procage/tests/escape_linux.rs::r04_files_move_between_writable_directories_and_gain_no_right` | Asserts rename and link between writable directories and a move from TMPDIR succeed from ABI 2 (EXDEV at ABI 1), a move into an executable directory fails with EXDEV, and moving or linking out of a read-only tree fails with the file unchanged, on T1 and T2; the unit test procage-policy/src/linux.rs refer_comes_only_with_write asserts only write carries REFER and not at ABI 1. Passed 2026-11-02. |
| SR-004 | verified | test | `crates/procage/tests/audit.rs::an_exempt_object_store_keeps_the_rest_of_the_check` | A clone with a hard-linked object and .git protected is refused naming the object, runs with .git/objects exempt with Audit::links_exempt listing it, and is refused naming .git/config once the config has a second name; ran fully on macOS and Linux T1 (T2 cannot protect, the only accepted skip), 2026-11-02. |
| SR-005 | verified | test | `crates/procage/src/audit.rs::tests::an_exempt_store_is_skipped_for_protected_files_only` | With the same tree hidden and the subtree exempt, both two-name files are findings; with it protected only the config is; exempt literal targets and tree roots are skipped. Passed on macOS and in both Linux lanes. |
| SR-006 | verified | test | `crates/procage/tests/audit.rs::an_exempt_object_store_keeps_the_rest_of_the_check` | Asserts Cage::with_options with the relative exemption .git/objects fails with SpawnError::Unsupported (Unsupported::Setting from audit::exemptions). |
