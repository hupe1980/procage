# Tasks: Path resolution that cannot be redirected or mis-spelled

## Phase 1: Measure first

- [X] T001 [SR-001] [US1] R-33 canaries: a deterministic `pre_exec` hook that replaces a planned component (link, or another directory moved in) for protect, a hidden directory, a hidden file, a data-class cover, a socket cover and a pin; a racing test over `PROCAGE_RACE_ATTEMPTS` spawns; record the outcome before the change — crates/procage/tests/escape_linux.rs, specs/040-path-resolution/quickstart.md

## Phase 2: User Story 1 — A planted link cannot move a mount (P1)

- [X] T002 [SR-002] [SR-003] [SR-005] [US1] Child sequence by identity: `openat2` with `RESOLVE_NO_SYMLINKS`, `fstat` against the planned `(dev, ino)`, `open_tree`/`fsopen`+`fsmount`, `mount_setattr` before attaching, `move_mount` onto the descriptor; the remount step and `locked_flags` removed — crates/procage/src/linux/sys.rs
- [X] T003 [SR-002] [SR-006] [US1] Plan: identities from `lstat`, canonical socket-cover and `/dev/shm` paths; `SpawnError::MountMoved { path, link }` from a walk of the plan after `ELOOP`/`ESTALE` — crates/procage/src/linux/{spawn,mod}.rs
- [X] T004 [SR-004] [US1] The T1 probe makes the same calls — crates/procage/src/linux/sys.rs
- [X] T010 [SR-005] [US1] Multithreaded T1 test: 1,000 spawns of a policy with every mount kind while other threads allocate and lock — crates/procage/tests/spawn_linux.rs
- [X] T005 [SR-001] [SR-006] [US1] Canaries assert the refusal and `MountMoved`; racing test with zero redirected mounts; `just linux-t1`, `just linux`, `just kernel` green; T1 latency before and after (`just bench` in Docker) — crates/procage/tests/escape_linux.rs

## Phase 3: User Story 2 — A rule's spelling never silently misses (P2)

- [X] T006 [SR-008] [US2] `SpawnError::CaseSensitive { path }`: allow rules, allowed sockets, Seatbelt-layer allows and bound grants on a case-sensitive volume (`pathconf(_PC_CASE_SENSITIVE)` of the longest existing prefix) — crates/procage/src/macos/{canon,spawn,mod,sys}.rs
- [X] T007 [SR-007] [SR-008] [SR-009] [US2] Spelling matrix: default volume (case, NFC/NFD, nested links, missing leaf, firmlink) and a case-sensitive APFS image (deny covers variants, allow and grant refused); fails when the image cannot be created; on every macOS lane — crates/procage/tests/spelling_macos.rs, .github/workflows/ci.yml, justfile

## Phase 4: Polish

- [X] T008 [SR-010] R-33 and R-37 in the threat model with their canaries; canonicalisation claim from the matrix, Linux case-folding untested; changelog Security entries; README known limits — crates/procage/THREAT_MODEL.md, site/content/docs/{macos,linux,threat-model}.md, CHANGELOG.md
- [X] T009 Version 0.4.1; `just ci`, `just linux-t1`, `just linux`, `just kernel`; CI green; quickstart; status Implemented; commit on `main`; tag and release — Cargo.toml, specs/040-path-resolution/{spec,quickstart}.md

## Phase 5: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-03 (commit 412ed89).

- [X] T011 [SR-009] Add a test for SR-009 (The spelling matrix MUST run as caged tests on the default volume and on a case-sensitive APFS image with case and Unicode variants, nested links, missing leaves and firmlinks; a macOS lane that cannot create the image MUST fail, not skip. Linux case-folding directories are untested and the docs MUST say so) — touchpoints: .github/workflows/ci.yml, crates/procage/tests/spelling_macos.rs [converge: implemented-unverified; The matrix passes locally on macOS 26.6.2 and fails if the image cannot be made, and CI runs it on the macOS 15, 26 and 27 lanes, but those lanes have not run this commit yet.]
