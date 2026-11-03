# Tasks: Grant on denial

## Phase 1: Foundational

- [X] T001 [SR-004] [SR-005] `Suggestion` and `Change` with `apply` (a new policy, exactly one change), `Display`, serde; unit tests per change — crates/procage-policy/src/suggest.rs, crates/procage-policy/src/lib.rs

## Phase 2: User Story 1 — A denial becomes an approvable suggestion (P1)

- [X] T002 [SR-001] [SR-002] [SR-003] [US1] `procage::suggest(&Policy, &Violation)`: the derivation table (literal grants with the operation's access, Unix sockets, leave-out of the covering protect or hide rule, waivers, signals; none for secrets, layer, lifetime, older kernel, proxy, unknown); unit tests per row; rustdoc on provoked denials — crates/procage/src/suggest.rs, crates/procage/src/lib.rs
- [X] T003 [SR-001] [SR-002] [SR-003] [SR-004] [SR-005] [US1] [US2] macOS kernel tests: each row denied, suggested, applied, respawned; a sibling stays denied; diff shows only the change; a waiver shows in the receipt — crates/procage/tests/suggest_macos.rs
- [X] T004 [SR-002] [SR-003] [US1] Linux kernel tests (T1, T2): a seccomp hard-deny gives its waiver and the respawn succeeds; `setsid` under `Lifetime::Run` gives none — crates/procage/tests/spawn_linux.rs

## Phase 3: Polish

- [X] T005 Docs: site violations page "From a denial to a grant", README feature line, CHANGELOG; `just` and CI run the new tests — site/content/docs/violations.md, README.md, CHANGELOG.md, justfile, .github/workflows/ci.yml
- [X] T006 `just ci`, `just linux-t1`, `just linux`; quickstart; status Implemented; commit on `main` — specs/017-grant-on-denial/{spec,quickstart}.md
