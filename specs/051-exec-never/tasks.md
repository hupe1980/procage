# Tasks: `Exec::Never` and `Exec::Program`

**Input**: [plan.md](plan.md), [spec.md](spec.md), [research.md](research.md), [data-model.md](data-model.md), [contracts/api.md](contracts/api.md), [quickstart.md](quickstart.md)

Tests are part of each story: the constitution (III) requires a caged test
for every enforcement claim, and every SR has acceptance scenarios.

## Phase 1: Setup

- [X] T001 Confirm the baseline is green before changes: `cargo test -p procage-policy` and `cargo test -p procage --test spawn_macos --test escape_macos` — crates/procage-policy, crates/procage

## Phase 2: Foundational (blocks every story)

- [X] T002 Add `Exec::Program` (serde `"program"`, doc: "the program only, as often as it likes"); `validate` refuses `Exec` rules/grants with `Program` as with `Never` (`ExecConflict`, message names the setting); rewrite the `Exec::Never` doc ("the program only, no exec after start; on macOS the program may execute itself again, since Seatbelt cannot count executions") — crates/procage-policy/src/policy.rs
- [X] T003 [P] Add `Construct::ExecProgram` (`"exec-program"`) to the `constructs!` list; map it in the reference policies — crates/procage-policy/src/lower/mod.rs, crates/procage-policy/tests/common/mod.rs
- [X] T004 [P] [SR-007] Add `Syscall::{Execve, Execveat}` (names `execve`, `execveat`), `Action::Supervise`, `DenyReason::Exec` (code `"exec"`) with `from_code`; numbers in `native_number` for x86_64 and aarch64 — crates/procage-policy/src/linux.rs, crates/procage-policy/src/sbpl.rs, crates/procage/src/linux/seccomp.rs
- [X] T005 [P] Add `RuleTarget::Program` with doc "the program of this spawn and, for an ELF file, its interpreter" — crates/procage-policy/src/linux.rs
- [X] T006 [SR-006] Add `elf::interpreter(file_start: &[u8]) -> Result<Option<&[u8]>, ElfError>` (`#[doc(hidden)] pub`, safe, `no_std`): ELF32/64, both endiannesses, "≤ 64 program headers", "`PT_INTERP` ≤ 4096 bytes, NUL-terminated", offsets checked against the slice; unit tests on `/bin/sh`-like fixtures, a static header, truncations — crates/procage-policy/src/elf.rs, crates/procage-policy/src/lib.rs
- [X] T007 [P] [SR-006] Fuzz target `elf` (arbitrary bytes, never panics) — crates/procage-policy/fuzz/fuzz_targets/elf.rs, crates/procage-policy/fuzz/Cargo.toml
- [X] T008 [SR-003] [SR-006] `unix::program_allowance(command) -> Result<Allowance, SpawnErrorKind>`: `find_program` after the environment is final, canonicalise, read at most 64 KiB once, `#!` → script, on Linux `elf::interpreter` → absolute regular file (canonicalised) or an interpreter error (program headers outside the 64 KiB read → "unreadable program headers"); unit tests — crates/procage/src/unix.rs
- [X] T009 [SR-003] [SR-006] `SpawnError::Script { program }` and `SpawnError::Interpreter { program, reason }` on both backends (built only on Linux; one shape for callers) with messages that name the file and the fix ("`Exec::Never` and `Exec::Program` run binaries only; start the interpreter as the program"); `native` test pins the common subset — crates/procage/src/macos/mod.rs, crates/procage/src/linux/mod.rs, crates/procage/tests/native.rs

**Checkpoint**: policy types, ELF reader and allowance compile and are unit-tested.

## Phase 3: User Story 1 — Nothing else can be executed (P1) 🎯 MVP

**Goal**: under both settings no file other than the program can be executed; on Linux under `Never` nothing after the first exec.
**Independent test**: caged shell under each base and setting fails to execute system programs; `Exec::Granted` control runs them.

- [X] T010 [SR-001] [US1] macOS lowering: under `Never`/`Program` drop `process-exec*` from every `Decider::Base` rule (keep `file-read*`, `file-map-executable`); emit `(allow file-read* process-exec* file-map-executable (extension "procage.exec.program"))` with `PROGRAM_EXTENSION_CLASS` next to `PTY_EXTENSION_CLASS`; ledger `exec-never`/`exec-program` exact — crates/procage-policy/src/lower/macos.rs, crates/procage-policy/src/lower/mod.rs
- [X] T011 [SR-001] [SR-007] [US1] Linux lowering: under `Never`/`Program` remove `EXECUTE` from base rules; emit a `RuleTarget::Program` rule (`READ_FILE | EXECUTE`); under `Never` add `execve`/`execveat` `Supervise` rules (`DenyReason::Exec`); ledger `exec-never` exact, `exec-program` `Approximated` with note "the program's ELF interpreter can start any readable ELF file" — crates/procage-policy/src/lower/linux.rs
- [X] T012 [SR-001] [US1] Policy-crate tests: base without exec under both settings (macOS text, Linux rights), program rule present, `Supervise` rules only under `Never`, `exec-program` approximated on Linux only; `ExecConflict` for `Program` — crates/procage-policy/tests/gaps.rs, crates/procage-policy/tests/base.rs
- [X] T013 [SR-001] [SR-002] [US1] macOS spawn: under `Never`/`Program` compute the allowance in `prepare` for every entry point; issue a `PROGRAM_EXTENSION_CLASS` token for the program (after `canon::exact_allow`) consumed with the grant tokens — crates/procage/src/macos/mod.rs, crates/procage/src/macos/spawn.rs
- [X] T014 [SR-001] [SR-002] [US1] Linux ruleset: resolve `RuleTarget::Program` to the allowance's program and interpreter (O_PATH in the parent, file rights) — crates/procage/src/linux/spawn.rs, crates/procage/src/linux/mod.rs
- [X] T015 [SR-007] [SR-009] [US1] Seccomp builder: `Action::Supervise` → `SECCOMP_RET_USER_NOTIF` always; filters: the cage keeps a supervised filter when the plan has `Supervise` rules (other `Eperm` rules notify only with reporting); builder test — crates/procage/src/linux/seccomp.rs, crates/procage/src/linux/mod.rs
- [X] T016 [SR-007] [SR-009] [US1] Child sequence: with a listener and supervised exec, after `NEW_LISTENER` create `pipe2(O_CLOEXEC)`, send listener + read end (control buffer for two descriptors from the parent), close both; on listener failure with supervised exec return the step error (no plain-filter fallback); document the call sequence in the module — crates/procage/src/linux/sys.rs
- [X] T017 [SR-007] [SR-009] [US1] Supervisor before the spawn: rename `violations.rs` → `supervisor.rs`; start the thread in `launch` before `command.spawn()`; wait for the handover until received or the parent's spawn-done flag (then one non-blocking receive); answer `Supervise` notifications `CONTINUE` (`SECCOMP_USER_NOTIF_FLAG_CONTINUE`) while the sentinel is open (`poll` 0) else `EPERM`; others `EPERM`; record only with reporting (`DeniedBy::Exec`); `adopt` takes the running supervisor (also on the async path: `spawn_async*` sets the flag after tokio's `spawn`) — crates/procage/src/linux/supervisor.rs, crates/procage/src/linux/mod.rs, crates/procage/src/linux/sys.rs, crates/procage/src/linux/child.rs, crates/procage/src/async_child.rs, crates/procage/src/violation.rs
- [X] T018 [SR-008] [US1] Listener probe once per process (forked child installs a filter with `NEW_LISTENER`; `EBUSY` → none), cached with the probe results; `Cage::with_options` under `Never` without one: gap `exec-never` `Approximated` (note "an enclosing seccomp filter already has a listener") unless allowed; allowed → no `Supervise` rules, approximation in the cage facts — crates/procage/src/linux/probe.rs, crates/procage/src/linux/mod.rs
- [X] T019 [SR-008] [US1] Gap messages for `exec-never` and `exec-program` end with the accepting call (Rust, Python, Node.js spellings) — crates/procage-policy/src/lower/mod.rs
- [X] T020 [SR-001] [US1] macOS canaries `r38_*`: Base V1/V2/V3 × `Never`/`Program` + fork: sh cannot execute `/bin/echo`, `/usr/bin/env`, `/bin/sh`, nor can a forked descendant; `Exec::Granted` control runs them; the documented contract is pinned: under `Never` the program re-executes itself and nothing else runs — crates/procage/tests/escape_macos.rs
- [X] T021 [SR-001] [SR-002] [SR-007] [SR-009] [US1] Linux canaries `r38_*` on T1 and T2 (also with `PROCAGE_ESCAPE_VIOLATIONS=1` and `PROCAGE_ASYNC=1`): same probes; under `Never` the program executing itself, `ld.so /bin/echo`, and a descendant's exec fail `EPERM`; with reporting the refusal is a `DeniedBy::Exec` violation; the program's open descriptors are stdio only — crates/procage/tests/escape_linux.rs
- [X] T022 [SR-009] [US1] Multithreaded spawn under `Never` (8 threads × ~12 spawns, with and without reporting): every spawn returns, every program runs — crates/procage/tests/spawn_linux.rs
- [X] T023 [SR-008] [US1] Outer-listener test (`testing::install_outer_listener`): `Never` → gap `exec-never`; with `allow(Construct::ExecNever)` it runs and the receipt lists `exec-never` — crates/procage/tests/spawn_linux.rs, crates/procage/tests/receipts.rs
- [X] T024 [US1] Threat model row R-38 "Execution beyond the program" (macOS, Linux; evidence the `r38_*` canaries); `threat_model` test passes — crates/procage/THREAT_MODEL.md

**Checkpoint**: MVP — the defect is closed and kernel-checked on macOS, T1, T2.

## Phase 4: User Story 2 — The program itself starts (P1)

**Goal**: every entry point starts the program under both settings, with or without a base.
**Independent test**: `Base::None` + `Never` runs a program; a script is refused.

- [X] T025 [P] [US2] macOS spawn tests: `Base::None` + `Never` with read of the program's libraries runs `/bin/echo`-like program; bare name resolved via `PATH`; script → `SpawnError::Script` before forking; async variant — crates/procage/tests/spawn_macos.rs
- [X] T026 [P] [US2] Linux spawn tests (T1, T2): same, plus a static program (no interpreter) and an ELF with an unusable interpreter → `SpawnError::Interpreter` — crates/procage/tests/spawn_linux.rs
- [X] T027 [SR-008] [US2] `Cage::exec*` under `Never`: macOS runs and the program cannot execute another; Linux gap `exec-never` before anything is applied unless allowed (then Landlock only); `Program` on both — crates/procage/src/linux/mod.rs, crates/procage/src/macos/mod.rs, crates/procage/tests/exec.rs

**Checkpoint**: US1 + US2 make `Exec::Never` usable and correct.

## Phase 5: User Story 3 — A program that re-executes itself (P2)

**Goal**: `Exec::Program` lets the program start copies of itself and nothing else.
**Independent test**: the caged program re-executes itself; `/bin/echo` is refused.

- [X] T028 [P] [SR-002] [US3] macOS: under `Program` the test binary re-executes itself and fails to execute `/bin/echo`; a second spawn of the same cage with another program cannot execute the first's program — crates/procage/tests/spawn_macos.rs
- [X] T029 [P] [SR-002] [SR-008] [US3] Linux: `Program` without `allow` → gap `exec-program` whose message names the accepting call; with it the program re-executes itself, `/bin/echo` is refused, the receipt lists `exec-program`; a second spawn of the same cage with another program cannot execute the first's; a program in a writable tree that replaces its own file by rename cannot execute the path again (inode-bound rule) — crates/procage/tests/spawn_linux.rs

## Phase 6: User Story 4 — What procage reports is what the kernel does (P2)

**Goal**: explain, the lowering table and the bindings tell the truth about both settings.
**Independent test**: oracle agrees on every exec probe; table test green; bindings run `"program"` and accept by `allow`.

- [X] T030 [SR-004] [US4] Oracle: `runnable()` adds no `Exec` rule under `Never`/`Program`; add both settings with each base to the policies; every exec probe agrees — crates/procage/tests/oracle.rs
- [X] T031 [SR-005] [US4] Lowering table rows: `exec-never` (macOS exact, note on re-execution; Linux exact, note on the supervisor and the gap), new `exec-program` (macOS exact; Linux approximated, note on the interpreter); table test green — crates/procage-policy/src/lowering.md, crates/procage-policy/tests/lowering_table.rs
- [X] T032 [P] [SR-005] [US4] Python binding: `allow=[...]` (construct names, unknown → `ValueError`) mapped to `LowerOptions::allow`; gaps' `accept` lists `allow=["exec-program"]`/`["exec-never"]`; stub and README; test with a `"program"` policy — bindings/python/src/lib.rs, bindings/python/python/procage/_native.pyi, bindings/python/README.md, bindings/python/tests/test_procage.py
- [X] T033 [P] [SR-005] [US4] Node.js binding: `allow?: string[]` (unknown → `TypeError`); gaps' `accept`; `index.d.ts`, README, test — bindings/nodejs/src/lib.rs, bindings/nodejs/index.d.ts, bindings/nodejs/README.md, bindings/nodejs/test/procage.test.js

## Phase 7: Polish & cross-cutting

- [X] T034 [P] Docs: `site/content/docs/policies.md` (four exec settings, a "which one?" table), `exec.md` (`Exec::Never` with `Cage::exec`), `explain.md`, `python.md`, `nodejs.md`; README if it lists exec settings — site/content/docs/, README.md
- [X] T035 [P] CHANGELOG `[Unreleased]`: Security (base exec under `Exec::Never`, R-38; migration: `Exec::Program` or `Exec::Granted` with `Exec` rules), Added (`Exec::Program`, bindings `allow`), Changed (`Exec`, `Action`, `RuleTarget`, `DenyReason` gain variants) — CHANGELOG.md
- [X] T036 [P] Decision recorded in the project's decision log (meaning of both settings, one-exec supervisor with the sentinel, amendment of spec 034's "never `CONTINUE`", macOS contract); specs index row — specs/README.md
- [X] T037 Benchmark case `exec-never` vs `exec-granted` (cached cage); record in quickstart (SC-003 ≤ +0.5 ms median) — crates/procage/benches/spawn.rs, specs/051-exec-never/quickstart.md
- [X] T038 Run `just ci`, `just linux`, `just linux-t1`, the fuzz target `elf` (5 min); record results in quickstart; status Implemented; commit on `main` — specs/051-exec-never/quickstart.md, specs/051-exec-never/spec.md

## Dependencies

- Phase 2 blocks everything. T006 → T007, T008; T008 → T009.
- US1 (Phase 3): T010–T012 (policy) → T013/T014 (backends) → T015 → T016 → T017 → T018 → T019; canaries T020–T024 after their backend.
- US2 depends on US1's allowance and lowering (T010–T014, T017).
- US3 depends on T010, T011, T013, T014, T019.
- US4 depends on US1 (lowering) and T019 (gap spellings).
- Polish last.

## Parallel examples

- Phase 2: T003, T004, T005, T007 in parallel after T002.
- US2: T025 (macOS) ∥ T026 (Linux).
- US3: T028 ∥ T029.
- US4: T032 ∥ T033 after T030/T031.
- Polish: T034 ∥ T035 ∥ T036.

## Implementation strategy

MVP = Phase 2 + US1 (the defect closed, kernel-checked). Then US2 (usable
under `Base::None`), US3 (`Exec::Program`), US4 (reports and bindings),
Polish. One commit on `main` when T038 is green (per-feature commit).

## Phase 8: Convergence

- [X] T039 Record in plan.md (§10) and research.md (R4) that the listener is probed per cage under `Exec::Never`, not cached per process, and why (a process can install a filter later; one fork per cage) per plan: §10 (contradicts)
- [X] T040 Record in contracts/api.md and plan.md (§16) that an unknown `allow` name raises `PolicyError` in both bindings, as `relax` names do per contracts/api.md (contradicts)
- [X] T041 Add `Exec::program_only()` to contracts/api.md per contracts/api.md (unrequested)
