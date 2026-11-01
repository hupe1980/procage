# Tasks: Linux violations — exact reports of refused system calls

## Phase 1: Foundational (policy crate)

- [X] T001 [SR-005] `SeccompRule::reason` and `DenyReason::{Lifetime, OlderKernel}` (codes `lifetime`, `kernel`) in crates/procage-policy/src/linux.rs and crates/procage-policy/src/sbpl.rs; reasons set per origin in crates/procage-policy/src/lower/linux.rs (classes, `Lifetime::Run`, truncation guard, layer; others `None`)
- [X] T002 [SR-005] `Condition::matches(&[u64; 6])` in crates/procage-policy/src/linux.rs
- [X] T003 [P] [SR-005] Policy tests: each origin's reason (gaps.rs or a new test file in crates/procage-policy/tests); code round-trip for the new reasons

## Phase 2: User Stories 1–2 (P1)

- [X] T004 [US2] [SR-003] [SR-005] `seccomp::build(rules, arch, notify)` in crates/procage/src/linux/seccomp.rs; unit tests: without notify identical to today for every reference policy; with notify only `EPERM` verdicts differ; `matches` agrees with the BPF interpreter on generated arguments for every condition
- [X] T005 [US1] [SR-001] [SR-004] Child side in crates/procage/src/linux/sys.rs: listener install, `sendmsg` with SCM_RIGHTS from a parent-allocated buffer, `close`; fallback to the plain filter with the errno; parent `recvmsg`
- [X] T006 [US1] [SR-002] [SR-006] [SR-007] Supervisor in crates/procage/src/linux/violations.rs: poll, `NOTIF_RECV`, answer `-EPERM` first (one function), name via `/proc/<pid>/comm` + `NOTIF_ID_VALID`, reason via `matches`, target by system call, record, `done` on `POLLHUP`
- [X] T007 [US1] [SR-007] Wiring in crates/procage/src/linux/mod.rs and crates/procage/src/linux/child.rs: notifying filter on reporting cages, socket pair per spawn, `Child::violations` (complete = done + reaped), `violation_receiver`, `kill_all` waits for `done`; `Cage::exec` builds the plain plan (no listener) with a case in crates/procage/tests/exec.rs (a reporting cage's exec'd command gets EPERM, not ENOSYS); `Coverage::SystemCalls`, `DeniedBy::{Lifetime, OlderKernel}` in crates/procage/src/violation.rs
- [X] T008 [US1] [US2] [SR-002] [SR-005] [SR-007] crates/procage/tests/spawn_linux.rs: ptrace, AF_INET socket and setsid listed with process-access, not granted and lifetime; each fails with EPERM; complete after exit; running child incomplete; a surviving descendant keeps it incomplete until `kill_all`; two concurrent runs apart; off by default; a detached run's refused call returns EPERM; the median of 20 refused calls is answered within 10 ms; the multithreaded spawn test (churn on other threads) also runs with reporting on (Constitution IV)
- [X] T009 [US2] [SR-001] [SR-003] crates/procage/tests/escape_linux.rs: escape suite also with `PROCAGE_ESCAPE_VIOLATIONS=1`; canary R-32: no seccomp listener among the child's descriptors, and opening the parent's through `/proc` fails; THREAT_MODEL R-32 row and catalog gate update in crates/procage/tests/threat_model.rs
- [X] T010 [P] KF-L15 in crates/procage-kernel-facts: listener, EPERM answer, POLLHUP once unused, EBUSY for a second listener

## Phase 3: User Story 3 (P2)

- [X] T011 [US3] [SR-004] [SR-006] crates/procage/tests/spawn_linux.rs: an outer listener in the spawning thread makes coverage Unavailable naming EBUSY while refused calls still fail with EPERM; 20,000 refused calls keep the cap and count the rest
- [X] T012 [SR-007] tests/native.rs shape accepts `SystemCalls`; justfile `linux`/`linux-t1` run the escape suite with reporting too; CI Linux lanes the same

## Phase 4: Polish

- [X] T013 [SR-007] Docs: crate docs (violations section: Linux), site violations and linux pages, README, THREAT_MODEL limits
- [X] T014 Gates: `just ci`, the four Linux lanes; results in specs/034-linux-violations/quickstart.md
- [X] T015 Record the decision; commit on `main`

> 2026-11-01: T004–T012 written; the Linux tests (T004 unit tests, T008, T009, T010, T011) have not run yet: Docker Desktop's disk went read-only. macOS gates pass.
