## Security Convergence — 002-threat-model

Commit `24f3263` · 2026-10-29T23:32:09Z

| Metric | Value |
|---|---|
| Threats (active) | 10 |
| Open blocking threats | 0  |
| Security requirements | 10 |
| verified | 10 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/threat_model.rs::mitigated_without_evidence_is_caught; tests/threat_model.rs::nonexistent_evidence_is_caught; tests/threat_model.rs::valid_evidence_is_accepted; review of README.md and src/lib.rs recorded in quickstart.md scenario 8` | Mutating R-10 to mitigated with an empty or unresolvable evidence field fails with exactly evidence-required or evidence-missing naming R-10, and a real test reference is accepted; the README and crate docs state that 0.0.1 enforces nothing and describe behaviour as designed or meant. |
| SR-002 | verified | test | `tests/threat_model.rs::evidence_in_library_source_is_caught; tests/threat_model.rs::kernel_fact_as_evidence_is_caught` | Evidence under src/ and under tests/kernel_facts/ each fail with evidence-location naming the id and the reference. Whether a test in tests/ truly cages a child remains a review item, as recorded in research R4. |
| SR-003 | verified | test | `tests/threat_model.rs::removed_id_is_caught; tests/threat_model.rs::duplicate_id_is_caught; tests/threat_model.rs::unknown_id_is_caught` | Deleting R-22 yields baseline-missing R-22, a second R-10 row yields duplicate-id R-10, and an R-99 row yields baseline-unknown; each test asserts no other rule fires. |
| SR-004 | verified | test | `tests/threat_model.rs::unknown_status_is_caught; tests/threat_model.rs::missing_cell_is_caught; quickstart.md scenario 3 (blank line inside the table reported as row-format, not skipped)` | Status "done" fails as value naming the id and field with the allowed values; a 7-cell row fails as row-format naming the line; rows stranded after a blank line are reported, not ignored. |
| SR-005 | verified | test | `tests/threat_model.rs::unknown_kernel_fact_is_caught; tests/threat_model.rs::gate (asserts at least 40 kernel-fact ids were read)` | Citing KF-M99 fails with kernel-fact naming R-21 and KF-M99; the clean catalog's KF-M07/M08/M12/M19/M21/M26/L09/L10 resolve against the kernel-facts catalog. |
| SR-006 | verified | test | `justfile package-docs recipe (part of just ci); quickstart.md scenario 4 (include entry removed → fails)` | src/threat_model.rs embeds THREAT_MODEL.md via include_str; the recipe checks the package list, builds docs from the unpacked package outside the workspace with -D warnings and asserts the threat_model page; removing the include entry failed the recipe. |
| SR-007 | verified | test | `tests/threat_model.rs::missing_heading_is_caught; tests/threat_model.rs::wrong_release_is_caught` | Removing the Out of scope heading fails as heading, and naming procage 0.0.0 fails as release-status with the current version; the clean document has all ten headings in order. |
| SR-008 | verified | test | `justfile planning-paths (paths include THREAT_MODEL.md and SECURITY.md); quickstart.md scenarios 6 and 8` | An injected specs/ reference in SECURITY.md failed the recipe; review and a grep for internal names, tokens and user actions found none in the published files. |
| SR-009 | verified | review | `SECURITY.md (Reporting a vulnerability, Scope, Supported versions)` | The policy names GitHub private vulnerability reporting with its URL, asks for no public issue, pull request or discussion, and links THREAT_MODEL.md for scope. Enabling the feature in repository settings is a maintainer action outside the code. |
| SR-010 | verified | review | `THREAT_MODEL.md Escape classes table, reviewed in quickstart.md scenario 8` | Every row is a one-line class description; R-11 and R-22 name the class without profile syntax, ioctl names or commands, and no row contains payloads or steps. |
