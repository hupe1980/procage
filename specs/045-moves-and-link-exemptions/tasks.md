# Tasks: Moves between writable directories, and link-check exemptions

## Phase 1: User Story 1 — Builds move files between directories (P1)

- [X] T001 [SR-003] [US1] `rights(Write)` includes `REFER` (intersected with the handled set); unit test that only write carries it and not at ABI 1 — crates/procage-policy/src/linux.rs
- [X] T002 [SR-003] [US1] Canary: moves and links between writable directories and from `TMPDIR` (EXDEV at ABI 1), a move gaining execute refused, moves out of a read-only tree refused; op `tmpdir-move` — crates/procage/tests/escape_linux.rs

## Phase 2: User Story 2 — Protected and hidden files stay out of reach (P1)

- [X] T003 [SR-001] [SR-002] [US2] r04 renames the ancestor into another directory; r30 renames from another directory onto the protected file (EBUSY, EXDEV at ABI 1); r08 doc comment — crates/procage/tests/escape_linux.rs
- [X] T004 [US2] Lowering note for `hd-rename-anchors` and the lowering table — crates/procage-policy/src/lower/linux.rs, crates/procage-policy/src/lowering.md

## Phase 3: User Story 3 — A local clone runs in place (P2)

- [X] T005 [SR-004] [SR-005] [SR-006] [US3] `Targets::exempting`, skipping exempt protected trees, literals, classes and globs; `exemptions` refusing relative paths; `Audit::links_exempt`; refusal message; unit test — crates/procage/src/audit.rs
- [X] T006 [SR-004] [SR-006] [US3] `CageOptions::with_link_exemption` and `link_exempt` on both backends; `cage_audit` resolves and returns a `Result` — crates/procage/src/linux/mod.rs, crates/procage/src/macos/mod.rs
- [X] T007 [SR-004] [SR-006] [US3] Integration test: a clone refused, exempt, config still refused, relative exemption refused — crates/procage/tests/audit.rs

## Phase 4: Polish

- [X] T008 Docs: Linux limits and options, audits, lifetime and `Lifetime::Run` (`gc.autoDetach`), crate docs, threat model R-04 and R-08, changelog — site/content/docs/{linux,audits,lifetime-and-hygiene}.md, crates/procage-policy/src/policy.rs, crates/procage/src/lib.rs, crates/procage/THREAT_MODEL.md, CHANGELOG.md
- [X] T009 Run `just ci`, `just linux-t1`, `just linux`, the kernel lane on ABI 1 and a newer kernel; quickstart results; status Implemented; commit on `main`
