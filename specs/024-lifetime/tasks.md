# Tasks: Lifetime — nothing a run starts outlives it

**Input**: spec.md, plan.md, research.md, data-model.md, contracts/lifetime.md, quickstart.md

## Phase 1: Setup

- [X] T001 Confirm the baseline: `cargo test -p procage-policy`, `cargo test --features escape-suite --test escape_macos r23` (one ignored) on macOS; record in specs/024-lifetime/quickstart.md

## Phase 2: Foundational (policy and lowering)

- [X] T002 [SR-007] Add `Lifetime { Run (default), Tree }` (serde kebab-case `"run"`/`"tree"`) and `Process.lifetime` in crates/procage-policy/src/policy.rs; re-export where `Signals` is exported; serde round-trip test incl. a document without `lifetime` parsing as `Run`
- [X] T003 [P] [SR-007] Add `Syscall::Setsid` ("setsid") and `Syscall::Setpgid` ("setpgid") in crates/procage-policy/src/linux.rs and their x86_64/aarch64 numbers in src/linux/seccomp.rs `native_number`; extend the per-arch tests
- [X] T004 [SR-001] [SR-007] Linux lowering in crates/procage-policy/src/lower/linux.rs: with `fork` and `Lifetime::Run` push `deny(Setsid)`, `deny(Setpgid)` and ledger `LifetimeRun` Exact; with `Tree` ledger `LifetimeTree` Exact; new constructs `lifetime-run`, `lifetime-tree` in crates/procage-policy/src/lower/mod.rs; tests for both values and for `fork: false` (no lock, no entry)
- [X] T005 [SR-004] [SR-007] macOS lowering in crates/procage-policy/src/lower/macos.rs: with `fork`, append the marker block after every other block (`(deny mach-lookup (global-name-prefix (param "procage-run-prefix")))`, `(allow mach-lookup (global-name (param "procage-run-marker")))`), public consts `RUN_PREFIX_PARAM`, `RUN_MARKER_PARAM`, a plan flag `run_marker: bool`, ledger entries; tests: block is last, literal params, no `extension` filter, absent without fork
- [X] T006 [P] [SR-007] Document the setting in crates/procage-policy/src/lowering.md (rows for both systems) and in crates/procage-policy/src/presets.rs (presets carry `Lifetime::Run`, a tightening); test that every preset has `Lifetime::Run`

## Phase 3: User Story 1 + 2 — descendants die with the run (P1)

**Independent test**: R-23 canaries pass on macOS, T1, T2 (quickstart).

- [X] T007 [US1] [SR-004] [SR-005] Create src/macos/lifetime.rs: process prefix `org.procage.run.<pid hex>.<RandomState hex>.`, slot pool (`Mutex<BTreeSet<u32>>` in use + retired), `Run { slot }` with `marker()`, `probe()`, `free()`, `retire()`; params for a slot; unit tests (lowest free slot, retired never reused, names match `[0-9a-z.]`)
- [X] T008 [US1] [SR-002] [SR-006] Add to src/macos/sys.rs: `all_pids()` (`proc_listallpids`, growing buffer), `same_user_live(pid)` (`proc_pidinfo` SHORTBSDINFO: uid == getuid, status != SZOMB), `Libsandbox::allows_name(pid, op, name) -> Result<bool, i32>` (sandbox_check with filter type 2; −1 → Err); and in src/macos/lifetime.rs `scan(run)` and a generic `reap(scan, kill, rounds)` returning `Err(survivors)`; unit test of `reap` with an always-live scanner
- [X] T009 [US1] [SR-005] [SR-004] Wire spawning in src/macos/mod.rs: `Cage` keeps slot-0 bytecode (compiled at `with_options` with slot-0 params when `run_marker`); `spawn_with_fds` takes a slot, binds the params, gets bytecode from the cache (compile on miss, before fork), probes `allows_name` once (VI), frees the slot on any spawn error; `Child::new` gets the `Run`
- [X] T010 [US1] [SR-002] [SR-003] [SR-006] Kill path in src/macos/child.rs: after walk + `killpg`, `reap` by marker (64 rounds, 1 ms pause), then wait; survivors → `io::Error::other("processes of the run survived: [..]")` keeping the run; clean → free slot, `run = None`; `detach` retires; update the type docs (run ends at drop/kill_all; exited child does not end it)
- [X] T011 [US1] [SR-001] [SR-003] Linux: update src/linux/child.rs docs (under `Run` the group kill reaches every descendant, also after exit); add `testing::try_session()` in src/linux/mod.rs returning the errno of `setsid()` and `setpgid(0, 0)`
- [X] T012 [US1] [SR-001] [SR-002] [SR-008] Escape canaries in tests/escape_macos.rs and tests/escape_linux.rs: un-ignore `r23_a_double_forked_descendant_dies_with_the_run` (Linux: the intermediate's `setsid` fails, the sleeper stays in the group); add `r23_descendants_of_an_exited_child_die_with_the_run` (child starts a sleeper, exits, is waited for, then dropped)
- [X] T013 [US2] [SR-005] Canaries in tests/escape_macos.rs: `r23_concurrent_runs_are_separate` (two runs from one cage, drop one, the other's sleeper lives) and `r23_a_detached_run_keeps_its_marker` (detach A, run and drop B, A's sleeper lives; then kill it)
- [X] T014 [US1] [SR-004] Marker tests in tests/spawn_macos.rs: a run's child matches its marker; the caller, an `(allow default)` `sandbox-exec` process and a second run do not; spawning one forking policy twice compiles once (via `testing` hooks in src/macos/mod.rs)

## Phase 4: User Story 3 — opt-out (P2)

- [X] T015 [US3] [SR-001] Linux canaries in tests/escape_linux.rs: `r23_sessions_are_locked` (default: setsid and setpgid EPERM on T1, T2) and `r23_tree_lifetime_allows_sessions` (`Tree`: both succeed); macOS canary in tests/escape_macos.rs `r23_tree_lifetime_still_reaps` (US3/AC2: with `Tree` a double-forked descendant dies on drop)

## Phase 5: Claims and docs

- [X] T016 [SR-008] Mark R-23 `mitigated` in THREAT_MODEL.md with the canaries as evidence; drop it from "does not yet" and "Open variants", describe the Linux `Tree` residual and the macOS pid-reuse window; update tests/threat_model.rs (R-23 status); update README.md and src/lib.rs lifetime claims
- [X] T017 [P] Rustdoc for `Lifetime` (both systems, EPERM, opt-out, compatibility notes) and for `macos::Child`/`linux::Child`

## Phase 6: Polish

- [X] T018 Linux: run the R-23 canaries and `procage-policy` tests in Docker T1 and T2 (`just linux`, `just linux-t1`); record in quickstart.md
- [X] T019 Timing (SC-003): drop of a forking macOS run before/after; compile-once check (SC-004); record in quickstart.md
- [X] T020 Gates: `just ci`; record the decision (with the constitution amendment) and commit on `main`

## Dependencies

T001 → T002 → T003, T004, T005, T006 → T007 → T008 → T009 → T010 → T012, T013, T014; T011 → T012, T015; T016 after T012–T015; T017 ∥ T016; T018, T019 after T016; T020 last.

## Parallel examples

T003 ∥ T005 ∥ T006 (different files); T013 ∥ T014; T016 ∥ T017.

## Implementation strategy

MVP: T002–T005 + T007–T012 (the double-fork canary passes on macOS and Linux). Then concurrency and opt-out, then claims.
