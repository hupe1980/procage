# Tasks: CI lanes for the releases people run

## Phase 1: Foundational

- [X] T001 [SR-004] Expected macOS major version and architecture in the kernel-facts runner (`PROCAGE_KF_EXPECT_MACOS`, `PROCAGE_KF_EXPECT_ARCH`, a `MISMATCH` line naming expected and measured) — crates/procage-kernel-facts/tests/kernel_facts.rs
- [X] T002 [SR-001] [SR-002] [SR-003] [SR-005] [SR-006] `workflows` gate (full-SHA pins with version comments, read-only token, no job permissions or secrets in ci.yml, no `pull_request_target`/`workflow_run`, no `github.event`/`github.head_ref` in run scripts, no caches, no `continue-on-error`, runner labels equal the README table), in `ci` and the CI gates job — justfile, .github/workflows/ci.yml

## Phase 2: User Story 1 — macOS 27 (P1)

- [X] T003 [SR-004] [SR-007] [US1] macOS matrix `macos-26`, `xcode-27` with expected major version and arch; every suite on each lane. If a base program fails on 27, measure the cause and add a new frozen base version; V1 to V3 fixtures stay unchanged — .github/workflows/ci.yml, crates/procage-policy/src/base.rs

## Phase 3: User Story 2 — Ubuntu 26.04 (P1)

- [X] T004 [SR-004] [SR-008] [US2] Linux matrix adds `ubuntu-26.04` shipped (T2) and with the documented sysctl (T1, kept only if measured); expected arch per lane; the T1 step logged, tests as the runner user — .github/workflows/ci.yml

## Phase 4: User Story 3 — arm64 Linux and macOS 15 (P2)

- [X] T005 [US3] `ubuntu-24.04-arm` T1 and T2, `macos-15` in the matrices — .github/workflows/ci.yml

## Phase 5: Polish

- [X] T006 [SR-006] [SR-008] Docs from the measured lanes: README platform table (label, release and build or kernel, arch, tier, date; untested releases named), SECURITY supported version 0.4.x and a link to the table, site testing and getting-started — README.md, SECURITY.md, site/content/docs/{testing,getting-started,macos}.md
- [ ] T007 Run `just ci`; push; CI green on every lane or the lane removed and named untested; quickstart; status Implemented; changelog; commit on `main` — CHANGELOG.md, specs/039-ci-lanes/{spec,quickstart}.md
