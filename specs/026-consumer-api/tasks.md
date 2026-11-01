# Tasks: Consumer API before the freeze

## Phase 1: Setup

- [X] T001 Baseline: `cargo test -p procage --lib` and the env tests in tests/spawn_macos.rs pass

## Phase 2: Foundational

- [X] T002 [SR-003] Add the observer in src/unix.rs: `fn observe(text) -> Option<bool>` (trimmed `env: CommandEnv {` line followed by `clear: true,`/`clear: false,`; no env field → `Some(false)`), `fn cleared(&Command)`, a cached self-check over three probe commands; unit tests incl. arguments and values containing the marker text

## Phase 3: User Story 1 — env_clear honoured (P1)

- [X] T003 [US1] [SR-001] [SR-002] Make `crate::unix::environment` return `Result<Vec<String>, ()>`: cleared → empty caller environment; observer unusable + passthrough → `Err`; unit-test the decision with an injected observer state in src/unix.rs
- [X] T004 [US1] [SR-002] Add `Unsupported::EnvClear` with Display to src/macos/mod.rs and src/linux/mod.rs; map the `Err` at both call sites; in src/macos/mod.rs compute the environment before `run_and_bytecode`
- [X] T005 [US1] [SR-001] Tests: `env_clear_keeps_the_caller_environment_out` in tests/spawn_macos.rs and tests/spawn_linux.rs (secret in the uncaged runner's environment; passthrough and allowlist; child sees only the set variable)
- [X] T006 [P] [US1] Docs: src/hygiene.rs (env rules incl. `env_clear`), spawn docs in src/macos/mod.rs and src/linux/mod.rs

## Phase 4: User Story 2 — native module (P2)

- [X] T007 [US2] [SR-004] `pub use` the backend as `native` in src/lib.rs with docs; create tests/native.rs using only `procage::native` (cage, options with lower, spawn with a grant, tmpdir, dropped_env, kill_all, detach, error Display)

## Phase 5: User Story 3 — spawn masks (P3)

- [X] T008 [US3] [SR-005] `LowerOptions::accept_spawn_masks()` in crates/procage-policy/src/lower/mod.rs; test in crates/procage-policy/tests/gaps.rs (read `/` on T1: refused without, lowers with, degradations name the three; a glob rule stays refused); docs in src/linux/mod.rs ("reading everything except secrets")

## Phase 6: Polish

- [X] T009 Docker T1/T2 (`just linux`, `just linux-t1`, plus `--test native`); record in quickstart.md
- [X] T010 Gates `just ci`; record the decision (the helper entry point becomes 029-exec-entry, Unix sockets under trees go to 028); commit on `main`

## Dependencies

T001 → T002 → T003 → T004 → T005; T006 ∥ T005; T007, T008 independent of T002–T006; T009 after T005, T007, T008; T010 last.
