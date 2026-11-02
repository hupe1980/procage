# Tasks: Other processes stay opaque

## Phase 1: Foundational (policy crate)

- [X] T001 [SR-001] [SR-002] macOS: the `ProcessAccess` class's hard denies gain `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))`; for the class only, a quiet early `(deny process-info-pidinfo)` and `(allow process-info-pidinfo (target same-sandbox))` — crates/procage-policy/src/lower/macos.rs; filters `SysctlName`/`SysctlNamePrefix` in crates/procage-policy/src/sbpl.rs
- [X] T002 [SR-002] Policy tests: crates/procage-policy/tests/base.rs, tests/precedence.rs (the pidinfo allow is the only allow without a policy rule), tests/gaps.rs (the empty policy's only allow); preset fixtures v1–v3 regenerated, +3 lines each (crates/procage-policy/tests/fixtures/presets/*.sb)
- [X] T003 [SR-004] [SR-006] `Construct::ProcOtherProcesses`, `procage_policy::linux::reaches_other_processes` and `PROC_OTHER_PROCESSES_NOTE` (crates/procage-policy/src/linux.rs, unit test `what_reaches_other_processes`); `proc_reach` in crates/procage-policy/src/lower/linux.rs (file rules, raw Landlock rules, globs); lowering table row in crates/procage-policy/src/lowering.md

## Phase 2: User Story 1 — macOS (P1)

- [X] T004 [US1] [SR-001] [SR-003] [SR-005] `r25_other_processes_arguments_are_unreadable` un-ignored on the default policy: other process's `KERN_PROCARGS2`, `KERN_PROCARGS`, pidinfo EPERM; own and own child's readable; readable with `ProcessAccess` waived — crates/procage/tests/escape_macos.rs, helpers in crates/procage/src/macos/sys.rs
- [X] T005 [US1] [SR-005] The base program set runs with the class in force (crates/procage/tests/spawn_macos.rs `base_*`, `preset_*`); the `ps`/`pgrep` limit in the docs is T018

## Phase 3: User Story 2 — Linux (P1)

- [X] T006 [US2] [SR-006] Backend: `proc_links` at cage creation (rules that resolve to `/proc`) and the grant check in `bind` at spawn, receipt via `RunFacts::with_approximation` — crates/procage/src/linux/mod.rs, crates/procage/src/receipt.rs
- [X] T007 [US2] [SR-004] [SR-006] `escape_linux::r25_other_processes_are_opaque` and `r25_proc_through_a_link_or_a_grant_is_an_approximation` (crates/procage/tests/escape_linux.rs); `presets_do_not_reach_other_processes_on_linux` (crates/procage-policy/tests/presets.rs); existing tests that read `/` accept the construct (crates/procage/tests/spawn_linux.rs, crates/procage-policy/tests/gaps.rs, tests/fit.rs)

## Phase 4: Polish

- [X] T008 [SR-007] Docs: THREAT_MODEL R-25 mitigated, site macos/linux/threat-model pages, CHANGELOG (Security and Changed, with migrations)
- [X] T009 Gates: `cargo test --workspace`, `cargo test -p procage-policy --all-features`, `just escape`, `just linux`, `just linux-t1`; results in specs/025-introspection/quickstart.md
- [X] T010 Record the decision; commit on `main`

## Phase 5: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-01 (commit 0b8cb30), against the dropped base V4 design.

- [X] T011 [SR-001] Complete SR-001 — done: the canary now reads another process's `KERN_PROCARGS` and pidinfo and the child's own pidinfo (crates/procage/tests/escape_macos.rs)
- [X] T012 [SR-002] Complete SR-002 — moot: there is no sysctl allowlist; SR-002 now pins the class's three lines and the fixtures
- [X] T013 [SR-003] Add a test for SR-003 — done: the canary is not ignored and passes in every `just escape` variant; no V4 escape step is needed
- [X] T014 [SR-004] Add a test for SR-004 — done: `presets_do_not_reach_other_processes_on_linux` lowers every preset v1–v3 on T1 and T2 (crates/procage-policy/tests/presets.rs)
- [X] T015 [SR-005] Complete SR-005 — done: own and own child's pidinfo asserted; the allowlist part is moot; the `ps`/`pgrep` limit in the docs moved to T018
- [X] T016 [SR-006] Complete SR-006 — done: symbolic-link rules (`proc_links`) and grants at spawn (`bind`) are checked, cmdline readability and the receipt listing are asserted (crates/procage/src/linux/mod.rs, crates/procage/tests/escape_linux.rs)
- [X] T017 [SR-007] Complete SR-007 — done: the crate module note is removed, R-25 is mitigated, the Linux change is under Changed; the presets pages need no change since there is no v4

## Phase 6: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-02 (commit 0b8cb30).

- [X] T018 [SR-005] Complete SR-005 (With the class in force the run's own processes MUST stay readable (the pidinfo allow is same-sandbox, not self and children) and the base program set MUST work as before; ps (setuid, refused in any cage) and pgrep (needs sysmond) MUST be documented as limits) — touchpoints: crates/procage/tests/escape_macos.rs, crates/procage/tests/spawn_macos.rs, site/content/docs/macos.md [converge: partial; Own and own child's procargs and pidinfo are asserted readable (canary, green) and the program set passes with the class in force (spawn_macos base_runs_ordinary_programs, base_v2_runs_developer_tools, preset_* green); but the third scenario fails: site/content/docs/macos.md:61 says "so ps of the run works", while ps is setuid and refused in any cage, and no doc states the ps or pgrep (needs sysmond) limit.] — done: site/content/docs/macos.md states both limits
