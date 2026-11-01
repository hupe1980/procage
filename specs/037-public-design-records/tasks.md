# Tasks: Public design records

## Phase 1: Foundational

- [X] T001 [SR-003] Gate in justfile (`planning-paths`): crates never cite planning paths; README, SECURITY, site never cite the private notes; `specs/` and `.specify/` free of the forbidden patterns (plan); a planted pattern fails it
- [X] T002 Constitution 2.2.0 in .specify/memory/constitution.md (public design records, private notes, consumers unnamed, product never depends on planning files)
- [X] T003 .gitignore: track `specs/` and `.specify/`; ignore `.specify/extensions/.cache/` and `specs/**/security/incoming-*`

## Phase 2: User Story 1 (P1)

- [X] T004 [P] [US1] [SR-001] Rewrite rows 001–005 by the rulebook (specs/001-kernel-facts … specs/005-hygiene)
- [X] T005 [P] [US1] [SR-001] Rewrite rows 006–010 (specs/006-base-profile … specs/010-violations)
- [X] T006 [P] [US1] [SR-001] Rewrite rows 024, 026, 027, 028, 029
- [X] T007 [P] [US1] [SR-001] Rewrite rows 030, 032, 034, 036, 037, 038
- [X] T008 [US1] [SR-001] Re-merge, render and check every threat model; remove `security/incoming-*`; full scan (gate plus e-mail and token patterns)

## Phase 3: User Story 2 (P2)

- [X] T009 [US2] [SR-002] specs/README.md: what a record holds, records are history, ThreatSpec, the authoritative documents
- [X] T010 [US2] Links: README ("Design records"), site/content/docs/testing.md

## Phase 4: Polish

- [X] T011 Gates: `just ci`, `just site`; planted-pattern check; results in quickstart.md
- [ ] T012 Commit on `main` (the records become public on the next push)
