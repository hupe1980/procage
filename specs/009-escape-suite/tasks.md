# Tasks: The escape suite

**Input**: spec.md, plan.md, research.md, data-model.md, contracts/catalog.md, quickstart.md

## Phase 1: Setup (testing helpers)

- [X] T001 [P] Add doc-hidden macOS testing helpers in src/macos/sys.rs and src/macos/mod.rs (`testing`): `mach_lookup(name) -> i32` (kern_return of `bootstrap_look_up`), `fcntl_errno(fd, cmd) -> i32`, `procargs_errno(pid) -> i32` (`KERN_PROCARGS2`), `kill_errno(pid, sig) -> i32`, `open_pty() -> (OwnedFd, PathBuf)`, `make_controlling(fd) -> i32` (`TIOCSCTTY`), `tiocsti_errno(fd) -> i32`; each `unsafe` with a `SAFETY:` comment
- [X] T002 [P] Add doc-hidden Linux testing helpers in src/linux/sys.rs and src/linux/mod.rs (`testing`): `syscall_errno` names `socket_netlink`, `socket_vsock`, `unshare_user`, `clone3`, `process_vm_readv`; `open_pty() -> (OwnedFd, PathBuf)`; `tiocsti_errno(fd) -> i32`

## Phase 2: Foundational (catalog grammar and gate)

- [X] T003 [SR-003] [SR-004] Extend tests/threat_model.rs per contracts/catalog.md: status `partial` (allowed for mitigate and detect), evidence restricted to `tests/escape_macos.rs` / `tests/escape_linux.rs` with the row-id prefix, new rules `evidence-ignored`, `evidence-platform`, `canary-missing`, `open-canary`, `open-variant-note` (`### Open variants` entries `- **R-NN** …`); `evidence-required` covers partial; parse `#[ignore` on the attribute lines above each `fn`
- [X] T004 [SR-003] [SR-004] Add defect-injection tests in tests/threat_model.rs, one per new rule (mitigated with one platform's evidence only, ignored evidence, missing canary, open canary on a mitigated row, partial without a note, evidence in another test file), each asserting exactly that rule fires; update the existing `valid_evidence_is_accepted` and `evidence_in_library_source_is_caught` fixtures to the new location rule

## Phase 3: User Story 1 — canaries (P1) 🎯 MVP

**Independent test**: `cargo test --test escape_macos`; `just linux`; `just linux-t1`.

- [X] T005 [US1] [SR-001] [SR-005] [SR-006] Create tests/escape_macos.rs: module docs (what a canary is, positive control, `open:` ignores, fails on `AlreadySandboxed`), harness (`scratch`, `base_v1`, `child_policy`, `child_command`, `finish`, `in_child`, `child_entry` with ops), and canaries for R-02, R-03, R-04, R-05, R-06, R-07, R-09, R-10, R-11, R-12 per research.md R5, each with its control
- [X] T006 [US1] [SR-001] [SR-006] Add macOS canaries for R-21, R-22, R-23 (kill, persistence; double fork open), R-24, R-25 and open canaries R-08, R-26 in tests/escape_macos.rs; open canaries kill every pid they learn before asserting
- [X] T007 [US1] [SR-001] [SR-002] [SR-005] [SR-006] Create tests/escape_linux.rs: module docs, harness (tiers, `PROCAGE_EXPECT_TIER` check via the probe, `child_entry` with ops), and canaries for R-02, R-04, R-07, R-09, R-10, R-21, R-22, R-24, R-30 per research.md R5 on every tier the host offers (typed refusal on T2 where the construct is a gap)
- [X] T008 [US1] [SR-001] [SR-002] [SR-006] Add Linux canaries for R-23 (kill, persistence via fake home; double fork open), R-25, R-28, R-29 (waived-class controls printing `informative=`), and open canaries R-08, R-26 in tests/escape_linux.rs
- [X] T009 [US1] Run the macOS suite and both Linux containers (including `--ignored`); fix any defect in an existing mitigation the canaries expose (FR-009), or record the variant as open; record results per canary and lane in specs/009-escape-suite/quickstart.md
- [X] T010 [US1] [SR-007] Defect injection per quickstart.md step 5 (a–e), one at a time, reverted after; record which canary failed in specs/009-escape-suite/quickstart.md

## Phase 4: User Story 2 — the catalog tells the truth (P1)

- [X] T011 [US2] [SR-003] [SR-004] Update THREAT_MODEL.md: the status field text (adds `partial`), each row's status and evidence from T009, a `### Open variants` subsection with an entry per partial (and open planned) class, the "In this version none has" sentence, and the release-status list of open variants
- [X] T012 [P] [US2] Update README.md and the crate docs in src/lib.rs so release claims match the catalog (no claim beyond it; open variants named)
- [X] T013 [US2] Run `cargo test --test threat_model` against the updated catalog; fix until the gate passes

## Phase 5: User Story 3 — every CI lane (P2)

- [X] T014 [P] [US3] [SR-005] Update .github/workflows/ci.yml: macOS lanes run `--test escape_macos`; Linux lanes (Ubuntu shipped T2, Ubuntu lifted T1, Debian container T2) run `--test spawn_linux --test escape_linux` with `PROCAGE_EXPECT_TIER`; the preview lane runs them without an expected tier
- [X] T015 [P] [US3] [SR-005] Update justfile: an `escape` recipe for macOS; `linux` and `linux-t1` run `escape_linux` too; keep `ci-all` complete

## Phase 6: Polish

- [X] T016 Record the per-class states and the decision on the escape suite contract (canary naming, `partial`, open canaries, positive controls); record follow-ups for the open variants (023-hardlink-audit, 024-lifetime).
- [X] T017 Run `just ci`, `just linux`, `just linux-t1`; confirm no published file cites planning paths and the suite runs under 60 s per platform and tier

## Dependencies

- T001, T002 → T005–T008; T003 → T004 → T013; T005–T008 → T009 → T010, T011 → T012, T013; T014, T015 independent after T005/T007; T016, T017 last.

## Parallel examples

- T001 ∥ T002; T005 ∥ T007 (different files); T012 ∥ T014 ∥ T015.

## Implementation strategy

MVP is US1 on macOS plus the gate (T001, T003–T006). Then Linux, catalog, and CI.

## Phase 7: Convergence

- [X] T018 Name the open R-26 variant (no helper in this release) in the release status of THREAT_MODEL.md per FR-010 (partial)
