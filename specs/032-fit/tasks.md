# Tasks: Fitting a policy to the host

## Phase 1: Foundational

- [X] T001 [SR-001] `Relaxation`, `Relax` and `apply` (all-or-nothing, unsupported only, by subject) in crates/procage-policy/src/lower/fit.rs; re-exports in crates/procage-policy/src/lower/mod.rs and lib.rs
- [X] T002 [SR-003] `Lift`, `lift()` by re-lowering, `Relaxed` with `Display` in crates/procage-policy/src/lower/fit.rs
- [X] T003 [P] [SR-001] [SR-003] Policy tests in crates/procage-policy/tests/fit.rs: unrelaxable gap → unchanged + returned; approximation not relaxed; only the named rule dropped; each relaxation's effect; lifts (signals ABI 6, protect T1, sockets T1 with max 8, macOS unknown)

## Phase 2: User Stories 1–2 (P1)

- [X] T004 [US1] [SR-002] `Cage::fit` in src/linux/mod.rs and src/macos/mod.rs
- [X] T005 [US1] [US2] [SR-002] [SR-004] tests/spawn_linux.rs: T2 (forced) with the consumer-harness-shaped policy and four relaxations: list of four with lifts; a missing relaxation fails with gaps; the fitted cage refuses an outside write and an IP socket, and the left-out `.git` is writable; cap 5 + `signals_same_user` lift ABI 6; host tier with nothing to relax → empty list
- [X] T006 [US1] tests/spawn_macos.rs: fit with relaxations on a policy macOS enforces → empty list and the same profile

## Phase 3: User Story 3 (P2)

- [X] T007 [US3] Crate docs section with an example in src/lib.rs; THREAT_MODEL.md sentence

## Phase 4: Polish

- [X] T008 Gates (`just ci`, `just linux`, `just linux-t1`); record in specs/032-fit/quickstart.md
- [X] T009 Record the decision; commit on `main`
