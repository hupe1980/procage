---

description: "Task list for 004-spawn-macos"
---

# Tasks: Spawn a caged child on macOS

**Input**: Design documents from `specs/004-spawn-macos/`

**Tests**: Required. FR-014, FR-015 and SC-001 to SC-004 make caged-child tests deliverables.

## Format: `[ID] [P?] [Story] Description`

- US1 caged run, US2 paths, US3 grants and cache, US4 fail closed
- `[SR-###]` tags sit on the first line of each security task

---

## Phase 1: Setup

- [X] T001 [SR-003] Update the root `Cargo.toml`: version `0.0.2`; `[dependencies] procage-policy = { path = "crates/procage-policy", version = "0.0.1" }`; `[target.'cfg(target_os = "macos")'.dependencies] libc = "0.2"`; replace `[lints] workspace = true` with the workspace set but `unsafe_code = "deny"`. Update `crates/procage-policy/Cargo.toml` to version `0.0.1`, publishable, with a description of the companion crate. Run `cargo deny`.
- [X] T002 [P] Update `package-docs` in `justfile`: package `-p procage -p procage-policy`, unpack both into `mktemp -d`, build the procage docs with `--config 'patch.crates-io.procage-policy.path="<dir>/procage-policy-0.0.1"'`, and check that `threat_model/index.html` and `macos/index.html` exist.

---

## Phase 2: Foundational

- [X] T003 [SR-003] Create `src/macos/sys.rs` (`#![allow(unsafe_code)]`). It holds:
  - the `Libsandbox` table resolved once (`OnceLock`) with `dlopen` and `dlsym`, failing with `Unsupported::Symbol { symbol, os_build }`;
  - `os_build()` (sysctl `kern.osversion`);
  - `compile(text, params) -> Result<Vec<u8>, String>`;
  - `is_sandboxed()` (`sandbox_check(getpid(), NULL, 0) == 1`);
  - `issue_file(class, path) -> Option<CString>`;
  - `ChildOps` (copyable fn pointers `mac_syscall`, `check` and `consume`) with in-child methods `apply(&[u8]) -> Result<(), i32>`, `verify() -> Result<(), i32>` and `consume(&CStr) -> Result<(), i32>`;
  - the wrappers `setsid()`, `setrlimit(res, cur, max)`, `getsid`/`getrlimit` (for tests), `open_denied_probe()`.
  
  Every `unsafe` block has a `// SAFETY:` comment.
- [X] T004 [P] Create `src/macos/mod.rs`. It holds `Step`, `Unsupported`, `GrantError`, `SpawnError` (with `Display`, `Error` and `From<LowerError>`), `PathRewrite`, `CageOptions` (compile limit 2000, `LowerOptions`) and `Grants`, plus the compile cache (`Mutex<HashMap<(String, Vec<(String, String)>), Arc<[u8]>>>`). Export it from `src/lib.rs` with `#[cfg(target_os = "macos")] pub mod macos;` and add `pub use procage_policy as policy;`.

---

## Phase 3: US1 - a cage that holds (P1) 🎯 MVP

- [X] T005 [US1] [SR-001] [SR-004] [SR-009] [SR-010] Implement `src/macos/spawn.rs`:
  - environment: read `get_envs`, `env_clear`, add allowlist/passthrough entries, re-apply explicit values;
  - the rlimit list (CORE always; NPROC, CPU, FSIZE, NOFILE when set);
  - the `pre_exec` closure running steps 1–5 of the plan, syscalls only, returning encoded step codes;
  - `decode(io::Error) -> Option<(Step, i32)>`.
- [X] T006 [US1] [SR-001] Implement `src/macos/probe.rs`: `probe()` runs once per process. It compiles `(version 1)(deny default)`, spawns `/usr/bin/true` with a pre_exec that applies, verifies and requires `open("/private/etc/hosts")` to fail with EPERM, then returns the `PROBE_OK` marker. The result is `ApplyMethod::PathA`, or a cached `Unsupported::ApplyMethod`.
- [X] T007 [US1] [SR-001] [SR-002] [SR-007] [SR-008] Implement `Cage` in `src/macos/mod.rs`:
  - `new`/`with_options`: refuse `Tty::NewPty` with `Unsupported::Setting`; call `canon::resolve_policy`; `lower(MacOs)`; check the compile limit; compile through the cache (`compiled` flag);
  - `spawn`: symbol table → `is_sandboxed` (`AlreadySandboxed`) → `probe` → grant tokens → env → pre_exec → `Command::spawn`, with step decoding;
  - the accessors `plan`, `rewrites`, `compiled`.
- [X] T008 [US1] [SR-001] [SR-004] Write the base-policy helper and US1 tests in `tests/spawn_macos.rs` (`#![cfg(target_os = "macos")]`):
  - read inside versus outside a granted directory (`cat`, EPERM);
  - write plus protect (`touch`);
  - network none versus loopback (`nc -z -n -w 2` against a parent `TcpListener`);
  - a failed step (NOFILE = `u64::MAX`) gives `Apply { step: Rlimit, .. }` and the marker file is never created;
  - a target the policy does not let the child execute gives a permission error, and nothing runs;
  - `contention`: 4 dyld-churn threads, 100 spawns of a denied `cat`, every one EPERM, each within 10 s.

## Phase 4: US2 - paths mean what was written (P1)

- [X] T009 [P] [US2] [SR-005] Implement `src/macos/canon.rs`: `resolve(&AbsPath)` (longest existing prefix, remainder byte-exact, `/System/Volumes/Data` mapped to the visible form when dev and inode match); glob prefix resolution with escaping; `resolve_policy(&Policy) -> Result<(Policy, Vec<PathRewrite>), SpawnError>` covering fs targets, unix sockets and raw Seatbelt filters.
- [X] T010 [US2] [SR-005] Add tests to `tests/spawn_macos.rs`:
  - write through `/tmp/<dir>` succeeds and the rewrite to `/private/tmp/<dir>` is recorded;
  - a missing leaf keeps the remainder;
  - a glob under `/tmp` whose directory name contains `*` resolves with the `*` escaped and matches only literally (the child reads the file it should, and not a sibling);
  - `/System/Volumes/Data` + `$HOME` resolves to the visible `$HOME` (FR-004).

## Phase 5: US3 - compile once, grants per spawn (P2)

- [X] T011 [US3] [SR-006] Implement grant binding in `src/macos/spawn.rs`: undeclared name → `GrantError::Undeclared`; resolve, and a missing path → `Missing`; `issue_file("procage.<name>")`, and null → `Issue`; tokens moved into the closure.
- [X] T012 [US3] [SR-006] [SR-007] Add tests:
  - one cage, grant `scratch` bound to A then to B: each child writes only its own directory;
  - an unbound grant gives no access;
  - undeclared and missing bindings give typed errors;
  - the same policy prepared twice gives `compiled() == false` the second time, and a policy differing in one rule gives `compiled() == true`;
  - `Cage` is `Send + Sync`, and two threads spawn from one cage concurrently (FR-013).

## Phase 6: US4 - never nest, never weaker (P2)

- [X] T013 [US4] [SR-002] [SR-010] [SR-009] Add the self-re-exec `child_entry` and tests:
  - `nested`: a caged child's own spawn returns `AlreadySandboxed`;
  - `session`: with `Tty::None` the child leads its own session, and with `Inherit` it does not;
  - `rlimit`: NOFILE and CORE as set;
  - `env`: allowlist and passthrough with `SECRET_TOKEN`.
- [X] T014 [US4] [SR-001] [SR-003] [SR-008] Add tests:
  - `probe()` returns `PathA` on this release;
  - a missing symbol name gives `Unsupported::Symbol` naming it (through a `sys` test hook `resolve_for_test`);
  - a policy over a compile limit of 5 gives `LimitExceeded` and no compile;
  - `Tty::NewPty` gives `Unsupported::Setting`;
  - a Linux-layer policy gives `SpawnError::Lower(Gaps)`.
- [X] T015 [P] [SR-003] Write `tests/unsafe_confined.rs`: scan `src/` for the token `unsafe`. It is allowed only in `src/macos/sys.rs`, and there each occurrence must have `// SAFETY:` within the 3 lines above it.

---

## Phase 7: Polish

- [X] T016 [SR-011] Docs:
  - `src/lib.rs` crate docs: development status. 0.0.1 is published as a name reservation; 0.0.2 (unreleased) spawns caged children on macOS. List what is not done (fd hygiene, descendant lifetime, base profile, Linux), and give a usage example (`no_run`).
  - `src/macos/mod.rs` module docs: each enforcement sentence names its test.
  - The `THREAT_MODEL.md` Release status names `procage 0.0.2` (development, unreleased) honestly; escape-class statuses are unchanged.
  - Update the README status.
- [X] T017 [P] Add `cargo test --locked -p procage --test spawn_macos --target …` to the CI macOS lanes in `.github/workflows/ci.yml`.
- [X] T018 Record the latency measurement (SC-005) with a release-mode test, `latency`, that prints the medians.
- [X] T019 Inject the five defects of `quickstart.md`, confirm that each fails a named test, restore byte for byte, and record the results.
- [X] T020 Run `just ci`, record the quickstart outcomes, and record the decision: companion crate, version 0.0.2, step encoding, path B deferred to a later feature (021-helper), minimal hygiene in 004.

## Dependencies

T001 → T003 → T004 → T005/T006/T009 → T007 → T008, T010–T014. T015, T002 and T017 run in parallel. T016 to T020 come last.

---

## Phase 8: Convergence

- [X] T021 Document the symlink-metadata allowance that path resolution adds (metadata reads of every symlink a policy path passes through, and of `/etc`, `/tmp` and `/var`) in the `procage::macos` module docs, as an observable effect on the child, and in research R3, per FR-004 (unrequested)
