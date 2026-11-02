# Tasks: Process groups under `Lifetime::Run` on Linux

## Phase 1: User Story 1 — Test runners group their children (P1)

- [X] T001 [SR-001] [US1] Lowering denies `setsid`, and `setpgid` only with `Tty::Inherit`; lowering test — crates/procage-policy/src/lower/linux.rs, crates/procage-policy/tests/gaps.rs
- [X] T002 [SR-002] [US1] Ending a run kills the child's session (live members, repeated for members forked meanwhile) — crates/procage/src/linux/child.rs
- [X] T003 [SR-001] [SR-002] [US1] Canaries: `setpgid` allowed and `setsid` refused; a grouped, reparented descendant dies with the run — crates/procage/tests/escape_linux.rs

## Phase 2: User Story 2 — The caller's session stays the boundary (P1)

- [X] T004 [SR-003] [US2] `Cage::exec` filter with `setpgid` denied; exec test — crates/procage/src/linux/mod.rs, crates/procage/tests/exec.rs

## Phase 3: Polish

- [X] T005 Docs: lowering table, `Lifetime::Run`, presets, lifetime guide, violations, `Child` rustdoc, threat model R-23, changelog — crates/procage-policy/src/{lowering.md,policy.rs,presets.rs}, site/content/docs/{lifetime-and-hygiene,violations}.md, crates/procage/src/linux/child.rs, crates/procage/THREAT_MODEL.md, CHANGELOG.md
- [X] T006 Run `just ci`, `just linux-t1`, `just linux`; CI; quickstart; status Implemented; commit on `main`
