# Tasks: Base profile V2

## Phase 1: Foundational

- [X] T001 [SR-003] `Base::V2` in crates/procage-policy/src/policy.rs, construct `base-v2` (crates/procage-policy/src/lower/mod.rs), lowering on macOS and Linux (crates/procage-policy/src/lower/{macos,linux}.rs)
- [X] T002 [SR-001] [SR-002] Final V2 content and docs in crates/procage-policy/src/base.rs (table, reasons, omissions incl. dirhelper, "Running developer tools"); `linux_v2` = V1

## Phase 2: User Story 1 + 2 (P1)

- [X] T003 [US1] [SR-003] Policy tests in crates/procage-policy/tests/base.rs: V2 pinned, V1 unchanged, no unfiltered base rule, V2 names no service beyond V1, Linux V2 = V1; lowering table row `base-v2` (crates/procage-policy/src/lowering.md, tests/common reference policy)
- [X] T004 [US1] [SR-001] Caged test in tests/spawn_macos.rs `base_v2_runs_developer_tools` (installed tools only: git with GIT_CONFIG_GLOBAL, clang build, make, xcrun, python3, ruby, perl, node, rg, jq; output vs uncaged; per-user temp dir = private TMPDIR; warm shim < 200 ms)
- [X] T005 [US2] [SR-002] Caged test `base_v2_grants_nothing_personal` in tests/spawn_macos.rs (home listing, ~/Library/Preferences, ~/.ssh, /opt/homebrew/etc other file, writes to /usr/local and /opt/homebrew, network refused; home stat allowed)

## Phase 3: User Story 3 (P2)

- [X] T006 [US3] [SR-003] Presets v2 in crates/procage-policy/src/presets.rs (+ module docs), fixtures crates/procage-policy/tests/fixtures/presets/*-v2.sb pinned in crates/procage-policy/tests/presets.rs; caged check that `agent_workspace::v2` builds with clang (tests/spawn_macos.rs)
- [X] T007 [P] Docs: crate docs and README (V2 for developer tools), examples/exec_helper.rs on V2, macOS module docs

## Phase 4: Polish

- [X] T008 Docker T1/T2 (Base::V2 policies lower and run); macOS suites; record in quickstart.md
- [X] T009 `just ci`; record the decision; commit on `main`
