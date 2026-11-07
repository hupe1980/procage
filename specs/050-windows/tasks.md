# Tasks: Windows backend

The tests are required: the spec's acceptance scenarios are canaries on a
real host (constitution III). Tasks marked **[lane]** need the Windows lane
to run. Everything else runs on any lane.

## Phase 1: Setup

- [ ] T001 Workspace: `windows-sys` and `flatbuffers` as `cfg(windows)` dependencies of `procage`; `tokio`, `futures-core` and `procage-proxy` enabled for `cfg(windows)` too (FR-013) (pinned in the workspace manifest, `cargo-deny` clean); `x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc` added to docs.rs targets and the crate description — Cargo.toml, crates/procage/Cargo.toml, deny.toml
- [ ] T002 [SR-013] CI: a `windows` job on `windows-11-arm`. Its first step prints the OS build and runs `kf-probe`; the job fails when the probe reports no process security environment; `cargo build` for `x86_64-pc-windows-msvc` as a build-only step — .github/workflows/ci.yml
- [ ] T003 Module skeleton: `#[cfg(windows)] pub mod windows`, `pub use windows as native`; `unsafe_code` allowed only in `windows::sys` (the `unsafe_confined` test extended) — crates/procage/src/lib.rs, crates/procage/src/windows/mod.rs, crates/procage/src/windows/sys.rs, crates/procage/tests/unsafe_confined.rs

## Phase 2: Foundational (blocks every story)

- [ ] T004 [SR-006] [SR-001] Probe: resolve the four exports from `processmodel.dll` with `LOAD_LIBRARY_SEARCH_SYSTEM32` after `IsApiSetImplemented`; read the version (major 1 only) and the support flags; detect an AppContainer caller token (`AlreadySandboxed`), Windows Server and Windows 10 (`UnsupportedOs`); keep the result in one `OnceLock` — crates/procage/src/windows/probe.rs, crates/procage/src/windows/sys.rs
- [ ] T005 [P] [SR-004] Vendor `ProcessSecurityEnvironment.fbs` as `psec.fbs` with its MIT notice, provenance and SHA-256; a test checks the hash — crates/procage/src/windows/psec.fbs, crates/procage/src/windows/psec.rs
- [ ] T006 [P] [SR-004] Encoder: `WindowsPlan` + per-spawn grants → PSEC bytes, every slot in schema order, version 1.1; a round-trip test decodes with the `flatbuffers` verifier and checks each list exactly (built for tests on every OS) — crates/procage/src/windows/psec.rs
- [ ] T007 [P] Policy: `Target::Windows { features: WindowsFeatures }`, `Plan::Windows(WindowsPlan)`, both enums `#[non_exhaustive]`; `Construct::ExecWhereReadable`; the fields of data-model.md ("major version 1 only"; `exec_on_read_only: ExecSemantics::{Refused, Allowed}`) — crates/procage-policy/src/lower/mod.rs, crates/procage-policy/src/lib.rs
- [ ] T008 [P] [SR-003] [SR-016] Paths: the `/X:/…` spelling ("drive letter upper-cased, separators `/`"); pure helpers in policy; `windows::abs_path` walks each component without following reparse points (research R7), refuses a reparse point inside a writable tree (`GrantError::Link`), resolves `subst` drives, and refuses UNC, `\\?\`, device and volume GUID paths, non-UTF-8 and case-sensitive directories; grants resolved again at every spawn — crates/procage-policy/src/path.rs, crates/procage/src/windows/paths.rs
- [ ] T009 [lane] Kernel facts KF-W1…KF-W19 as listed in research R4, each with its decision rule asserted; `kf-probe` prints them — crates/procage-kernel-facts/src/sys/windows.rs, crates/procage-kernel-facts/src/bin/kf-probe/windows.rs, crates/procage-kernel-facts/src/lib.rs
- [ ] T010 [SR-002] [lane] Record the KF-W outcomes of the lane's build as a fixture; `windows-base-1` measured (KF-W8) as data — crates/procage-policy/src/base.rs, crates/procage-policy/tests/fixtures/windows-features.json

## Phase 3: User Story 1 — Cage a command on native Windows (P1) 🎯 MVP

**Independent test**: the workspace preset writes in the workspace, reads a system DLL, and is refused `%USERPROFILE%\.ssh`, writes outside and an outbound connection.

- [ ] T011 [SR-001] [US1] Lowering `lower/windows.rs`, file and process rows of the plan's table: Read/Write/Protect/Hide, grants, Exec (exact or `exec-where-readable` from the fixture), `Exec::Never`, globs, `Base::None`, IPC, signals (`SameUser` a gap); every row a lowering-table fixture test; SC-005: every shipped preset and version lowers for Windows without gaps or with each gap named with the option that accepts it — crates/procage-policy/src/lower/windows.rs, crates/procage-policy/src/lowering.md, crates/procage-policy/tests/lowering_table.rs
- [ ] T012 [SR-001] [US1] `windows::Cage::new`/`with_options`/`fit`/`plan`/`features`, `CageOptions`, `Grants`, `Unsupported`, `SpawnError`, `Step` as in contracts/windows-api.md; `with_violations` and `Tty::NewPty` are gaps; `exec`/`exec_session` return `Unsupported::NoExec` — crates/procage/src/windows/mod.rs
- [ ] T013 [SR-012] [US1] One security environment per spawn: the plan and the encoded base cached per shape, grants appended to a copy; the environment closed when the `Child` drops — crates/procage/src/windows/mod.rs, crates/procage/src/windows/spawn.rs
- [ ] T014 [SR-015] [P] [US1] Command line: the inverse of `CommandLineToArgvW`, property-tested; `.bat`/`.cmd` in argv form refused — crates/procage/src/windows/cmdline.rs
- [ ] T015 [SR-001] [SR-005] [SR-012] [lane] [US1] (runs after T016) Tests: preset reads, writes and refusals; `Unsupported` on a forced-missing feature; gaps named with their option; `AlreadySandboxed` from inside a cage; two concurrent runs cannot reach each other's grants; no security descriptor changes after a run; SC-001: the workspace preset (with `exec-where-readable` accepted by name if the fixture requires it) runs `cargo build` of a small crate and `git status` in the workspace — crates/procage/tests/spawn_windows.rs, crates/procage/tests/native.rs

## Phase 4: User Story 2 — Same hygiene and lifetime (P1)

**Independent test**: undeclared handles, a secret variable, a breakaway grandchild and a dropped `Child` each behave as on the other OSes.

- [ ] T016 [SR-007] [SR-008] [SR-009] [US2] Spawn sequence 1–10 of the plan: job (kill-on-close, no breakaway, limits, UI limits), attribute list (security environment, handle list, job list per KF-W15, child-process policy per KF-W3, Win32k mitigation), `CreateProcessW` suspended with an explicit environment and console flags, verification (token is AppContainer, container SID, `IsProcessInJob`), resume or terminate — crates/procage/src/windows/spawn.rs, crates/procage/src/windows/sys.rs
- [ ] T017 [SR-008] [US2] `Child`: `id`, `wait`, `try_wait`, `kill_all` (terminate the job), stdio, receipt; dropping it closes the job, then the environment — crates/procage/src/windows/child.rs
- [ ] T018 [SR-014] [US2] Rlimits: `nproc` → active-process limit, `cpu_seconds` → job time; `nofile`, `fsize_bytes`, `core_bytes` → gaps (the IR has no memory limit) — crates/procage-policy/src/lower/windows.rs, crates/procage/src/windows/spawn.rs
- [ ] T019 [SR-007] [SR-008] [SR-009] [SR-014] [lane] [US2] Hygiene canaries: undeclared inheritable handles (64 concurrent spawns while other threads create inheritable handles), secret env absent, `Tty::None` gets no parent console, a breakaway grandchild dies with the run, the parent killed abruptly kills the run, a fault-injected verification failure never runs the target, a fifth process over `nproc` 4 fails — crates/procage/tests/spawn_windows.rs
- [ ] T020 [SR-005] [lane] [US2] Stress: 1,000 runs, some killed, one parent killed; the workspace's security descriptors byte-identical, no process left (SC-003) — crates/procage/tests/spawn_windows.rs

## Phase 5: User Story 3 — Escape classes answered (P2)

**Independent test**: the Windows escape suite is green and the threat model has a Windows column.

- [ ] T021 [SR-010] [P] [US3] Hard-deny data, frozen v1: `SECRETS_WINDOWS`, `PERSISTENCE_WINDOWS`, `ENGINE_PIPES_WINDOWS`, `SERVICE_PIPES_WINDOWS` (research R8) — crates/procage-policy/src/presets.rs
- [ ] T022 [SR-010] [SR-002] [US3] Lower each hard-deny class for Windows (deny paths on `FS_DENY` hosts, UI limits, base rules), or a typed gap per the KF-W9…W12 fixture; the `TerminalInjection` waiver required for `Tty::Inherit`; the per-class verdict table in `lowering.md` checked by a fixture test — crates/procage-policy/src/lower/windows.rs, crates/procage-policy/src/lowering.md
- [ ] T023 [SR-003] [SR-010] [SR-016] [lane] [US3] Escape suite: one canary per class (secrets, Docker and OpenSSH agent pipes, COM and scheduled tasks, HKCU `Run` and Startup, `OpenProcess`, `SendInput`, window messages, `WriteConsoleInput`), and the alias matrix (8.3, case, streams, `\\?\`, device paths, junction, symlinks, hard link) against Protect, Hide and deny; rename anchors; planted links: the child replaces a granted subdirectory with a junction and with a directory symlink to `%USERPROFILE%\\.ssh`, and the next spawn with that grant fails with `GrantError::Link` — crates/procage/tests/escape_windows.rs
- [ ] T024 [SR-010] [SR-013] [US3] Threat model: a Windows column for every R-class and hard-deny class (canary, gap or out of scope), checked by the threat-model test — crates/procage/THREAT_MODEL.md, crates/procage/src/threat_model.rs, crates/procage/tests/threat_model.rs

## Phase 6: User Story 4 — Network modes (P2)

**Independent test**: a direct connection, an unrelated loopback listener and the proxy, under each mode.

- [ ] T025 [SR-011] [US4] Network lowering per research R5: capabilities, egress, ingress and host loopback per mode; `Loopback` with ports other than `Any`, and any mode without its build feature, are gaps; the proxy endpoint from `with_proxy` — crates/procage-policy/src/lower/windows.rs, crates/procage/src/windows/mod.rs
- [ ] T026 [SR-011] [lane] [US4] Network canaries: `None` refuses public and loopback; `Ip`/`All` connect and listen; `Proxy` reaches only the proxy (unrelated loopback listener and a public address refused) or is a gap; the proxy test file runs on Windows — crates/procage/tests/escape_windows.rs, crates/procage/tests/proxy.rs

## Phase 7: User Story 5 — Evidence (P3)

**Independent test**: a Windows receipt names build, features and base; `explain` names the base for a system DLL.

- [ ] T027 [SR-002] [US5] Receipts: `target: windows` with `build`, `schema`, `features`, `base` (additive to format 1) — crates/procage/src/receipt.rs, crates/procage/src/windows/child.rs
- [ ] T028 [SR-002] [US5] `explain`/`diff` for the Windows target with case folding; "allowed by the Windows base" for base paths; `suggest` on Windows — crates/procage-policy/src/explain/, crates/procage/src/explain.rs, crates/procage/src/suggest.rs
- [ ] T029 [SR-002] [lane] [US5] Tests: receipt fields; `explain` agrees with the OS on the reliable operations (oracle subset); tokio spawn and wait on Windows — crates/procage/tests/receipts.rs, crates/procage/tests/oracle.rs, crates/procage/tests/tokio.rs

## Phase 8: Polish

- [ ] T030 [SR-013] Docs: README (Windows row, minimum build, the undocumented interface, the base, gaps, WSL2 still supported), rustdoc of `procage::windows`, a site page, CHANGELOG with the migration note for `Target`/`Plan` (`#[non_exhaustive]`, new variants) — README.md, crates/procage/src/windows/mod.rs, site/content/docs/windows.md, CHANGELOG.md
- [ ] T031 Benchmark: the Windows lane publishes spawn overhead over a plain `CreateProcessW` (SC-004, target < 5 ms median) — crates/procage/benches/spawn.rs
- [ ] T032 `just ci` on macOS and Linux, the Windows lane green; quickstart results filled in; specs index; status Implemented; commit on `main` — specs/050-windows/quickstart.md, specs/README.md, specs/050-windows/spec.md

## Dependencies

- Phase 1 → Phase 2 → US1 → US2. US2's spawn sequence (T016) is what US1's tests run on, so T015 runs after T016.
- US3 and US4 depend on US1 and US2 and are independent of each other.
- US5 depends on US1. T009 (facts) gates every **[lane]** claim; T010 feeds the lowering's fixture.

## Parallel opportunities

- Phase 2: T005, T006, T007, T008 in parallel (different crates and files).
- US1: T014 alongside T011–T013.
- US3 T021 and US4 T025 in parallel once US2 is done.

## Implementation strategy

MVP = Phases 1–4 (US1 and US2): a Windows cage with fail-closed lowering,
hygiene and lifetime, gaps for everything not yet proven. Then US3, which
is required before any Windows claim reaches the README, then US4 and
US5. Nothing is released before T024 and T030.
