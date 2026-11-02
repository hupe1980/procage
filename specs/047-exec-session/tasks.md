# Tasks: A helper's command in a session of its own

## Phase 1: User Story 1 — Test runners through a helper (P1)

- [X] T001 [SR-001] [US1] `Session::Lead`, `sys::leads`, `Cage::exec_session(_with_fds)` with the spawn filter on Linux — crates/procage/src/linux/{mod,sys}.rs, crates/procage/src/macos/{mod,sys}.rs
- [X] T002 [SR-002] [US1] `end_session(pid)` on both backends (Linux shares `kill_session` with a run's end) — crates/procage/src/linux/{mod,child}.rs, crates/procage/src/macos/{mod,sys}.rs
- [X] T003 [SR-003] [US1] `SpawnError::GroupLeader`; `Tty::Inherit` refused — crates/procage/src/{linux,macos}/mod.rs
- [X] T004 [SR-001] [SR-002] [SR-003] [US1] Tests: process groups allowed, sessions refused on Linux, a grouped sleeper ended by `end_session`, a group leader refused — crates/procage/tests/exec.rs

## Phase 2: Polish

- [X] T005 Docs: exec guide, exec rustdoc, lowering table, changelog — site/content/docs/exec.md, crates/procage/src/{linux,macos}/mod.rs, crates/procage-policy/src/lowering.md, CHANGELOG.md
- [X] T006 Run `just ci`, `just linux-t1`, `just linux`; CI; quickstart; status Implemented; commit on `main`
