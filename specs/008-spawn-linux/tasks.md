---

description: "Task list for 008-spawn-linux"
---

# Tasks: Spawning a caged child on Linux

## Phase 1: Setup

- [X] T001 Move the platform-neutral spawn helpers (`environment`, `private_tmpdir`, `limits`, `TmpdirGuard`) from `src/macos/spawn.rs` and `src/macos/mod.rs` into `src/unix.rs` (`pub(crate)`, cfg unix) and use them from the macOS backend; `just ci` stays green.
- [X] T002 Add `just linux` and `just linux-t1` (Docker lanes running `cargo test -p procage --lib --test spawn_linux --test unsafe_confined` as uid 65534, `PROCAGE_EXPECT_TIER` T2 / T1) and clippy for `aarch64-unknown-linux-gnu` and `x86_64-unknown-linux-musl` in `lint`, in `justfile`; add the lanes to `ci-all`.

## Phase 2: Foundational (policy crate)

- [X] T003 [SR-006] [SR-007] Add the frozen Linux lists and homes to `crates/procage-policy/src/presets.rs` per FR-013 (`SECRETS_HOME_LINUX`, `PERSISTENCE_HOME_LINUX`, `PERSISTENCE_SYSTEM_LINUX`, `LINUX_HOMES`) and `linux_class_paths(class) -> Option<ClassPaths>`; pin them in `crates/procage-policy/tests/presets.rs`.
- [X] T004 [SR-006] [SR-007] Add `Mount::Pin`, `ClassPaths` and `LinuxPlan.classes` to `crates/procage-policy/src/linux.rs`.
- [X] T005 [SR-004] [SR-006] [SR-007] [SR-009] [SR-012] Rework `crates/procage-policy/src/lower/linux.rs`: coverage-aware data classes (exact / T1 approximated / T2 unsupported, `classes` filled when in force), `Namespaces.pid` false, gaps for loopback and proxy networks, unix sockets below ABI 9, hide on T2, glob allow rules, and signals below ABI 6; update `crates/procage-policy/src/lowering.md` and the fixtures in `crates/procage-policy/tests/{lowering_table,gaps,precedence}.rs`.

## Phase 3: US1 + US2 - caged child, never weaker (P1)

- [X] T006 [US1] [SR-002] [SR-003] Write `src/linux/seccomp.rs`: syscall table per architecture, BPF builder (arch check, x32 kill, one block per rule, EPERM/ENOSYS), and unit tests with a classic-BPF interpreter covering every condition, a foreign architecture and an x32 number.
- [X] T007 [US1] [US2] [SR-001] [SR-002] [SR-005] [SR-008] [SR-009] [SR-010] Write `src/linux/sys.rs` (the only unsafe module on Linux): Landlock ruleset and rules, `ChildPlan::run` with the call sequence of plan.md, step codes, the probe child, `close_range` with fallback, kill helpers and `/proc` children; extend `tests/unsafe_confined.rs` to both `sys` modules.
- [X] T008 [US2] [SR-004] Write `src/linux/probe.rs`: `probe()` cached per process; tier T1 / T2 / none with ABI, errata and the user-namespace errno.
- [X] T009 [US1] [US2] [SR-001] [SR-004] [SR-005] Write `src/linux/mod.rs` and `src/linux/spawn.rs`: `Cage` (tier choice, lowering, seccomp build, `Unsupported` cases), `CageOptions`, `Grants`, `SpawnError`, `Step`, `Unsupported`, `GrantError`, the per-spawn ruleset with grant fds, the T1 mount list with locked flags, id maps, error decoding; `src/linux/child.rs`; `pub mod linux` in `src/lib.rs`.
- [X] T010 [US1] [SR-001] [SR-002] [SR-009] Write `tests/spawn_linux.rs` with the harness (`child_entry`, `PROCAGE_EXPECT_TIER` check) and tests `fs_read_write_outside` (US1-1), grant per spawn, `network_none` (US1-2, host loopback listener), `hard_deny_syscalls` (US1-3), `probe_reports_tier` (US1-4). On T2 every write rule covers `trust-handoff` (unsupported), so T2 runs of write scenarios waive that class by name and assert the waiver is listed.
- [X] T011 [US2] [SR-004] [SR-005] Add tests: `t2_protect_is_a_gap` and the allowed-degradation case, requesting T1 on T2 is `Unsupported`, a missing policy path fails before any child runs, a forced step failure is reported with the step and the target did not run (US2-1..4).

## Phase 4: US3 - data classes on Linux (P1)

- [X] T012 [US3] [SR-006] [SR-007] [SR-011] Write `src/linux/classes.rs`: homes (`/root`, `/home/*`, the caller's `$HOME`), the bounded walk of writable roots (no symlink following, `SpawnError::Walk` over the bound), the mount list for each class (mask secrets, read-only handoff and persistence, pin `.git`), and the T2 grant overlap check (`GrantError::CoversClass`).
- [X] T013 [US3] [SR-006] [SR-007] [SR-011] Add tests: `t1_secrets_masked`, `t1_trust_handoff` (hooks, `.vscode`, `.bashrc` refused; `.git` rename refused; objects and `src` writable), the waiver case, `t2_workspace_is_a_gap` and its waiver, `t2_grant_covering_secrets_refused`, `walk_bound_fails`, `walk_skips_symlinks`.

## Phase 5: US4 + US5 - hygiene and T1 isolation (P2)

- [X] T014 [US4] [SR-010] Add tests: base V1 runs `sh -c`, `cat`, `ls` and refuses the home; leaked and handed-over fds; drop kills a grandchild; passthrough env drops; `tmpdir`; session; rlimits; 100 spawns from a multithreaded parent (constitution IV).
- [X] T015 [US5] [SR-008] [SR-009] Add T1 tests: protect gives `EROFS`; hide is empty and unreadable; capability sets empty; `umount` and a rw remount refused.

## Phase 6: Polish

- [X] T016 [SR-012] Docs: `src/linux/mod.rs` module docs (observed behaviour, not yet done), `src/lib.rs` status, README, THREAT_MODEL release status (escape statuses unchanged), the `presets` module Linux note.
- [X] T017 Inject the quickstart defects and record the results; record the latency in each container.
- [X] T018 Run `just ci`, `just linux`, `just linux-t1`; record the decision, record outcomes, commit on `main`.

## Phase 7: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-10-30 (commit fbf108d).

- [X] T019 [SR-002] Complete SR-002 (The child MUST be refused ptrace, io_uring_setup, bpf, keyctl, perf_event_open, userfaultfd, unshare, mount and the other hard-deny syscalls with EPERM, on both tiers) — touchpoints: src/linux/seccomp.rs, src/linux/sys.rs, tests/spawn_linux.rs [converge: partial; On the T1 lane all eight probed syscalls (ptrace, io_uring_setup, bpf, keyctl, unshare, setns, perf_event_open, userfaultfd) get EPERM with informative controls, but mount and the other mount-API calls named by the statement are not shown to be filtered (an unprivileged control also gets EPERM).]
- [X] T020 [SR-003] Complete SR-003 (The seccomp filter MUST kill a syscall made through a foreign architecture or the x32 ABI) — touchpoints: src/linux/seccomp.rs, src/linux/sys.rs, tests/spawn_linux.rs [converge: partial; A foreign audit architecture is killed, but the x32 scenario only asserts kill on x86_64 builds; on the aarch64 host it never evaluates an x86_64 filter.]

## Phase 8: Convergence

- [X] T021 Run quickstart step 4 (`just linux T1` in the default container must fail with a tier mismatch, never skip) and record the result per quickstart.md and FR-018 (missing) — done 2026-10-30: `TIER MISMATCH` left T2 right T1, 25 passed 1 failed, recipe exit 101
- [X] T022 Add `CageOptions::homes`/`with_home` (homes outside `/home` and `/root`, needed for FR-013's `$HOME` and for tests) and `BACKEND_MAX_ABI` to `contracts/linux-api.md` per plan: contract (unrequested)
