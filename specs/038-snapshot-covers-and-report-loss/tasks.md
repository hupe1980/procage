# Tasks: Vanished snapshot covers and honest report loss

## Phase 1: User Story 1 (P1)

- [X] T001 [US1] [SR-001] Regression test `a_socket_removed_during_the_spawn_does_not_fail_it` in crates/procage/tests/spawn_linux.rs (T1; fails at spawn 3 without the fix)
- [X] T002 [US1] [SR-001] `ChildMount` `optional` and the child loop in crates/procage/src/linux/sys.rs; `mounts()` and `optional()` in crates/procage/src/linux/spawn.rs

## Phase 2: User Story 2 (P2)

- [X] T003 [P] [US2] [SR-002] Docs in crates/procage/src/violation.rs and site/content/docs/violations.md

## Phase 3: Found in this row

- [X] T006 Test hygiene: the caged tests left about 2,350 scratch folders in the temp directories (each run a few more). `tests/support/scratch.rs` `Scratch` removes its directory on drop; every `scratch`/`tmp_dir`/`repo`/`workspace`/`fake_home` helper returns it; the two tests that detach a child remove its private TMPDIR (`detach` keeps it, by design). Checked: a macOS spawn, escape, exec and native run leaves no folder
- [X] T007 CI on free runners: 5 jobs (gates; macOS 26 arm64; Linux T1 and T2 on ubuntu-24.04; fuzz 60 s per target) instead of about 10; no scheduled workflows; the getting-started page no longer mentions a Rosetta lane

## Phase 4: Polish

- [X] T004 Gates: `just ci`, the four Linux lanes; results in specs/038-snapshot-covers-and-report-loss/quickstart.md
- [ ] T005 Commit on `main`
