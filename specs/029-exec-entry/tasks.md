# Tasks: Exec entry

## Phase 1: Setup

- [X] T001 Add `[[test]] name = "exec" harness = false` to Cargo.toml and `--test exec` to the Linux recipes in justfile

## Phase 2: Foundational

- [X] T002 [SR-001] Replace `new_session: bool` with `Session { New, Group, Keep }` in src/macos/sys.rs and src/linux/sys.rs (Keep: no call); add `ppid()` and `thread_count()` to src/linux/sys.rs
- [X] T003 [SR-002] Program lookup in src/unix.rs mirroring execvp (slash: relative to the command's directory; else the child's PATH or `/usr/bin:/bin`; executable regular file); unit tests

## Phase 3: User Story 1 + 2 (P1)

- [X] T004 [US1] [SR-001] [SR-002] macOS: split `spawn_with_fds` into `prepare(…, Session)` + spawn; add `exec`/`exec_with_fds` (checks: nesting, probe, `tmpdir` grant → `GrantError::TmpdirWithExec`, env, program lookup; then install + `Command::exec`, decode) in src/macos/mod.rs; rustdoc with the lifetime per system
- [X] T005 [US1] [SR-001] [SR-002] Linux: the same in src/linux/mod.rs, plus `Unsupported::ExecThreads { threads }` for T1 with more than one thread, parent = `ppid()` for the death-signal check
- [X] T006 [US1] [US2] [SR-001] [SR-003] tests/exec.rs: helper roles (shell script, env, threads-t2) and cases: pid identity + inside/outside write + exit code; env_clear keeps a secret out; group kill ends command and background sleeper; Linux: `setsid` fails for a descendant; Linux: command dies with its parent; per tier on Linux

## Phase 4: User Story 3 (P2)

- [X] T007 [US3] [SR-002] Refusal cases in tests/exec.rs run in-process: `tmpdir` grant, missing program (path and PATH), Linux T1 with a second thread (and T2 with threads succeeds via a helper); each followed by an outside write that must succeed

## Phase 5: DX and docs

- [X] T008 [P] [SR-004] examples/exec_helper.rs (portable via `procage::native`, ≤ 15 procage lines); "Helpers" section in src/lib.rs (helper + outside side: `process_group(0)`, kill the group; lifetime per system)
- [X] T009 [P] [SR-004] THREAT_MODEL.md: lifetime with `Cage::exec` per system (R-23 text and release status); README status line

## Phase 6: Polish

- [X] T010 Docker T1/T2 runs; record in quickstart.md
- [X] T011 `just ci`; record the decision; commit on `main`

## Dependencies

T001 → T002, T003 → T004, T005 → T006, T007; T008, T009 after T004/T005; T010 after T006–T008; T011 last.
