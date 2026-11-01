# Tasks: Older Linux kernels

**Input**: spec.md, plan.md, research.md, data-model.md, contracts/api.md

## Phase 1: Setup

- [X] T001 Kernel fact KF-L14 (observation, both tiers): a ruleset handling only ABI 2 rights lets `truncate(path)` and `open(O_RDONLY|O_TRUNC)` empty a readable file outside the writable rule; ABI 3 rights refuse both, in tests/kernel_facts/tests/kernel_facts.rs

## Phase 2: Foundational

- [X] T002 [SR-004] ABI cap: `CageOptions::landlock_abi` + `with_landlock_abi`, effective ABI `min(kernel, cap, BACKEND_MAX_ABI)` for tier check, lowering and ruleset; `Cage::landlock_abi()`; in src/linux/mod.rs

## Phase 3: User Story 1 — truncation guard (P1)

- [X] T003 [P] [US1] [SR-001] `Syscall::{Truncate, Open, Openat, Openat2}`, `Condition::TruncWithoutWrite { flags_arg }`, `O_TRUNC`/`O_ACCMODE` constants in crates/procage-policy/src/linux.rs
- [X] T004 [US1] [SR-001] Lowering below ABI 3 on both tiers adds the four denies (contract order) in crates/procage-policy/src/lower/linux.rs; fixtures in crates/procage-policy/tests/
- [X] T005 [US1] [SR-001] seccomp compiler: `BPF_ALU|BPF_AND|BPF_K`, numbers (`open` x86_64 only), the condition; interpreter unit tests in src/linux/seccomp.rs
- [X] T006 [US1] [SR-001] Escape canaries `r31_*` in tests/escape_linux.rs: per tier, ABI capped at 1, 2, 3: four truncation routes outside the workspace fail and the size is kept; `>` and `ftruncate` on a write descriptor inside the workspace work; R-31 row in THREAT_MODEL.md and tests/threat_model.rs

## Phase 4: User Story 2 — T2 from ABI 1 (P1)

- [X] T007 [US2] [SR-002] `Tier::T2.min_landlock_abi()` = 1 in crates/procage-policy/src/lower/mod.rs; probe assertion in tests/spawn_linux.rs (`>= 1`)
- [X] T008 [US2] [SR-002] Caged matrix in tests/spawn_linux.rs: T2 (and T1) at capped ABIs 1, 2, 3, 5 and the kernel's: writes outside refused, `AF_INET` socket refused, `ptrace` refused, a workspace write works; cap 0 refused; cap above the kernel reports the kernel ABI

## Phase 5: User Story 3 — Signals::SameUser (P2)

- [X] T009 [US3] [SR-003] `Signals::SameUser` (serde `same-user`) in crates/procage-policy/src/policy.rs; `Construct::SignalsSameUser`; Linux lowering (nothing added) and macOS lowering (`allow signal`, hard deny still applies) in crates/procage-policy/src/lower/{linux,macos}.rs; fixtures and format test
- [X] T010 [US3] [SR-003] Caged tests: Linux, cap 5 + `SelfAndChildren` → gap; `SameUser` signals a same-user process outside the cage; kernel ABI ≥ 6 + `SelfAndChildren` refuses it (tests/spawn_linux.rs); macOS `SameUser` spawns and the outside signal is still refused (tests/spawn_macos.rs)

## Phase 6: User Story 4 — the cap for developers (P2)

- [X] T011 [US4] [SR-004] Covered by T002/T008/T010; rustdoc example for `with_landlock_abi` in src/linux/mod.rs

## Phase 7: Polish

- [X] T012 [SR-005] Docs: "Kernels" section (per-ABI table, guard and its side effect, `SameUser`, cap, passed IP sockets below ABI 4) in src/linux/mod.rs; tier text in src/linux/mod.rs header; crates/procage-policy/src/lowering.md (T2 minimum, `signals-same-user` row, guard); THREAT_MODEL.md tier text; README.md Linux line
- [X] T013 Gates: `just ci`, `just linux`, `just linux-t1`, `just kf-linux`, `just kf-linux-t1`; negative control (guard removed → r31 fails); record in specs/030-older-kernels/quickstart.md
- [X] T014 Record the decision; commit on `main`

## Dependencies

T002 before T006/T008/T010. T003 → T004 → T005 → T006. T007 before T008. T009 before T010.
