# Tasks: Violations — what the sandbox denied, and why

## Phase 1: Foundational (policy crate and portable types)

- [X] T001 [SR-003] `DenyReason` with `code`/`from_code`, `Rule::reason`, and `write_profile` rendering messages only with reporting on (run-marker parameter, `string-append` for explicit denies) in crates/procage-policy/src/sbpl.rs; `LowerOptions::with_violations` replacing `tag`/`with_tag` in crates/procage-policy/src/lower/mod.rs; re-exports in crates/procage-policy/src/lib.rs
- [X] T002 [SR-003] Set reasons in crates/procage-policy/src/lower/macos.rs: hard-deny rules and data-class paths → `HardDeny(class)`, protect/hide fs and hidden-socket denies → `Protect`/`Hide`, raw layer denies → `Layer`; the run-marker block none
- [X] T003 [P] [SR-003] Policy tests in crates/procage-policy/tests: code round-trip; every lowering fixture renders byte-identical without the option; with it, stripping messages gives the same text; the marker block carries no message; update tests that used `Tag` with `LowerOptions`
- [X] T004 [P] [SR-001] `Violation`, `DeniedBy`, `Coverage`, `Violations` (cap 10,000, dropped count) and the pure parser (last line = exact live marker; target may contain newlines; unknown code kept) with unit tests incl. a newline-forged target, in src/violation.rs; exports in src/lib.rs and `procage::native`
- [X] T005 [P] KF-M29 in tests/kernel_facts: a parameter message and a `string-append` message appear on the denial's last line; a run's denials arrive before a later process's denial, the fence (20 rounds; stalls rerun)

## Phase 2: User Stories 1–2 (P1, macOS)

- [X] T006 [US1] [SR-006] [SR-007] Monitor in src/macos/violations.rs: `/bin/sh` watchdog running absolute `/usr/bin/log stream --style ndjson` with the predicate (marker prefix), empty environment, reader thread with `serde_json`, sinks by marker, ready handshake (≤ 2 s), fences (≤ 1 s), integrity check of `/bin/sh` and `/usr/bin/log` (root-owned, not group/world-writable, read-only volume) via `on_read_only_volume` in src/macos/sys.rs, `Down(reason)` and restart; fences as denials of a forked child (`install_fence` in src/macos/sys.rs; multithreaded-parent test); `serde_json` macOS dependency in Cargo.toml
- [X] T007 [US1] [SR-002] [SR-005] Wiring in src/macos/mod.rs and src/macos/child.rs: `CageOptions::with_violations`; slot 0 compiled for reporting cages; a run slot per spawn for every reporting spawn; sink registered before the fork; `Child::violations` (fence after exit, complete flag), `violation_receiver` (bounded 1,024, once); `kill_all` runs the marker search only for forking policies and fences before freeing, retiring the slot on timeout
- [X] T008 [US1] [US2] [SR-001] [SR-002] [SR-005] tests/spawn_macos.rs: hidden read + outside write listed with `Hide`/`NotGranted`, complete within 1 s of exit; a `secrets`-class path read → `HardDeny(Secrets)`; protect write → `Protect`; set-user-id exec → `HardDeny(Privilege)`; two concurrent runs keep their own; a running child's record is incomplete; a cage without the option reports `Off` and starts no helper; a newline-forged path stays with its run; slot reuse after a late denial keeps it in the first record; no violation from the lifetime probe
- [X] T009 [US1] [SR-003] tests/escape_macos.rs: run the escape canaries also with reporting on

## Phase 3: User Story 3 (P2) and Linux

- [X] T010 [US3] [SR-004] [SR-006] [SR-007] tests/spawn_macos.rs: the first reporting spawn is ready within 2 s; the receiver yields a violation before exit; the integrity check refuses a group-writable or user-owned binary (unit test on a temp file) with `Unavailable`; a detached run's slot is not reused; more denials than a lowered test cap counts dropped; a helper killed mid-run marks the record incomplete with `Unavailable` and the next spawn restarts it; a process that started the helper and is killed leaves no helper (exec harness or subprocess test)
- [X] T011 [SR-005] Linux: `CageOptions::with_violations`, `Child::violations` (`Off`/`NotObserved`), `violation_receiver` → `None` in src/linux/mod.rs and src/linux/child.rs; tests/native.rs shape test on both

## Phase 4: Polish

- [X] T012 [SR-005] Docs: crate section "Violations" with the example in src/lib.rs (best-effort, diagnostic, dedup, admin accounts, `Cage::exec` has none), README, THREAT_MODEL.md (R-17 status, reporting is not a control)
- [X] T013 Gates (`just ci`, `just kf`, `just linux`, `just linux-t1`); record results in specs/010-violations/quickstart.md
- [X] T014 Record the decision; note Linux reporting as follow-up 034-linux-violations; commit on `main`
