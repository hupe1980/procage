---

description: "Task list for 001-kernel-facts"
---

# Tasks: Kernel facts as regression tests

**Input**: Design documents from `specs/001-kernel-facts/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md, threat-model.yaml

**Tests**: The feature *is* a test suite. Each fact task writes the probe step(s)
and the runner fact together. No separate test-first tasks.

**Security tags**: `[SR-###]` links a task to a ThreatSpec security requirement.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependencies)
- **[Story]**: US1–US4 from spec.md

---

## Phase 1: Setup (workspace)

**Purpose**: turn the repository into the workspace from plan.md, without changing `procage`'s published surface

- [X] T001 Add `[workspace]` to the root `Cargo.toml`: members `crates/procage-policy` and `tests/kernel_facts`, `resolver = "3"`, `[workspace.package]` (edition 2024, rust-version 1.99, license, repository), and `[workspace.lints]` (rust `unsafe_code = "forbid"`, `missing_docs = "warn"`; clippy `all = deny`, `undocumented_unsafe_blocks = "deny"`). Keep the root `[package] procage` 0.0.1 with `lints.workspace = true` and its `include` list unchanged.
- [X] T002 [P] Create `crates/procage-policy/Cargo.toml` (`publish = false`, no dependencies, `lints.workspace = true`) and `crates/procage-policy/src/lib.rs` (`#![no_std]`, `extern crate alloc;`, crate docs stating it is a placeholder for the policy IR)
- [X] T003 [P] Create `tests/kernel_facts/Cargo.toml`: crate `procage-kernel-facts`, `publish = false`, dependency `libc = "0.2"`, `[[bin]] kf-probe` at `src/bin/kf-probe/main.rs`, `[[test]] kernel_facts` with `harness = false`, and its own `[lints]` (the workspace set, but `unsafe_code = "deny"`) [SR-009]
- [X] T004 Run `cargo generate-lockfile` (or `cargo build --workspace`) and confirm `Cargo.lock` covers the workspace; `cargo build --workspace` passes [SR-011]

---

## Phase 2: Foundational (blocking prerequisites)

**Purpose**: protocol, runner skeleton and FFI that every fact uses

**⚠️ CRITICAL**: no fact work can begin until this phase is complete

- [X] T005 Implement in `tests/kernel_facts/src/lib.rs`: [SR-014]
  - `Observation` (key=value lines per contracts/probe-protocol.md, values restricted to `[A-Za-z0-9_.:/+-]*`) and its `emit`/`parse`;
  - `Exit {Code, Signal, Timeout}`;
  - `Outcome {Pass, Fail, NotApplicable, SetupFailed}`.

  Lines that don't start with `kf ` are ignored.
- [X] T006 Implement `run_step(probe, args, timeout, stdin) -> (Exit, Observation)` in `tests/kernel_facts/src/lib.rs`: [SR-006] [SR-007] [SR-008]
  - `std::process::Command` with `env_clear()`, stdin `/dev/null` or a pipe, stdout/stderr piped;
  - poll `try_wait` and SIGKILL on timeout; default 30 s, compile-heavy 120 s.


- [X] T007 Implement `Scratch` in `tests/kernel_facts/src/lib.rs`: a fresh 0700 directory per fact, created exclusively with a unique name (`mkdir` with a random suffix, retried on EEXIST), canonicalised, asserted to match `^[A-Za-z0-9/._-]+$`, and removed on drop. It never resolves `$HOME`. [SR-005]
- [X] T008 [P] Implement a UTC `YYYY-MM-DD` civil date from `SystemTime` (days-to-civil, no dependencies) in `tests/kernel_facts/src/lib.rs` [SR-012]
- [X] T009 Create `tests/kernel_facts/src/sys/mod.rs` with `#![allow(unsafe_code)]` and cfg-gated `pub mod macos;` / `pub mod linux;`. This is the only module allowed unsafe, and every unsafe block carries `// SAFETY:`. [SR-009]
- [X] T010 Implement the macOS dynamic symbol table in `tests/kernel_facts/src/sys/macos.rs`. It loads with `dlopen("/usr/lib/libsandbox.1.dylib")` and `dlsym(RTLD_DEFAULT, …)` for: [SR-009]
  - compile: `sandbox_compile_string`, `sandbox_free_profile`, `sandbox_create_params`, `sandbox_set_param`, `sandbox_free_params`;
  - apply: `sandbox_apply`, `__mac_syscall`;
  - check: `sandbox_check` (variadic), and the data symbol `SANDBOX_CHECK_NO_REPORT`;
  - extensions: `sandbox_extension_issue_file`, `sandbox_extension_consume`, `sandbox_extension_release`.

  A missing symbol returns `Err(name)`. It provides safe wrappers `compile(sbpl, params) -> Result<Bytecode, CompileError{text: Option<String>}>` (error slot pre-set to NULL and inspected), `apply_path_a(&Bytecode) -> Result<(), errno>` (`{data, size, NULL, 0}`), `apply_lib`, `check_self() -> i32`, `check_path(op, path) -> i32`, `check_global_name(name) -> i32`, `issue_file_ext(class, path) -> Result<String>`, `consume_ext(token) -> i64`, and `osinfo()` via `sysctlbyname(kern.osproductversion, kern.osversion)`.
- [X] T011 [P] Implement the Linux syscall layer in `tests/kernel_facts/src/sys/linux.rs`: [SR-009]
  - Landlock: `#[repr(C)]` `LandlockRulesetAttr {handled_access_fs, handled_access_net, scoped}` and `LandlockPathBeneathAttr`; `abi_version()`, `errata()`, `create_ruleset`, `add_path_rule(fd, O_PATH fd, access)`, `restrict_self`;
  - seccomp: `no_new_privs()` and `install_allow_all_filter()` (`seccomp(SECCOMP_SET_MODE_FILTER)` with a one-instruction RET_ALLOW `sock_fprog`);
  - namespaces and mounts: `unshare(flags)`, `mount(src, target, fstype, flags, data)`, `umount`;
  - `lo_flags()` via `SIOCGIFFLAGS`.


- [X] T012 Create `tests/kernel_facts/src/bin/kf-probe/main.rs`: [SR-004] [SR-008] [SR-014]
  - dispatch `argv[1]` to cfg-gated `macos`/`linux` step modules;
  - exit codes 0/2/3 per contracts/probe-protocol.md;
  - a helper that asserts every inlined path matches the safe charset before formatting SBPL;
  - no shell and no argv built from the environment;
  - the `osinfo` and `selfcheck` steps.


- [X] T013 Create the runner (it also prints an `excluded:` section listing each fact left out on purpose with its reason, per spec FR-002) `tests/kernel_facts/tests/kernel_facts.rs`: [SR-012]
  - a `Fact` table (id, statement, platform, kind, tiers, slow, run) and `Ctx` per data-model.md;
  - an id-prefix filter from `std::env::args`;
  - sequential execution with per-fact timing;
  - report printing and writing to `target/kernel-facts/report-<os>-<arch>.txt` per contracts/report-format.md;
  - non-zero exit on any FAIL or SETUP-FAILED.


- [X] T014 Implement the outside-sandbox precheck in `tests/kernel_facts/tests/kernel_facts.rs`. It runs the `selfcheck` step before any fact and prints `sandboxed: yes|no` in the header. When it reports `yes`, every `Enforcement` fact becomes FAIL "already inside a Seatbelt sandbox: run `just test-outside` from a terminal that is not inside an agent sandbox" and none is skipped. [SR-001]
- [X] T015 Implement the control-run helper `expect_denied(control_args, caged_args, expected_errno)` in `tests/kernel_facts/tests/kernel_facts.rs`. A control that does not succeed → SETUP-FAILED. A caged run with a different errno → FAIL with expected and observed. [SR-002]

**Checkpoint**: `cargo test -p procage-kernel-facts --test kernel_facts` prints a header with OS build and date and runs an empty catalog

---

## Phase 3: User Story 1: re-verify every macOS kernel fact (Priority: P1) 🎯 MVP

**Goal**: KF-M01…M22 and M27, M28 run on the reference Mac with one command

**Independent Test**: `just facts KF-M` on macOS 26.6.2 outside a sandbox → all PASS, header shows `26.6.2 (25G83)`

- [X] T016 [US1] KF-M01 symbol resolution: step `symbols` prints `missing=` per unresolved name, and the fact passes when none is missing. Files: `tests/kernel_facts/src/bin/kf-probe/macos.rs`, `tests/kernel_facts/tests/kernel_facts.rs` [SR-009]
- [X] T017 [US1] Compile-only facts via step `compile <case>` in `tests/kernel_facts/src/bin/kf-probe/macos.rs` and the runner:
  - **KF-M02**: small profile → `builtin` NULL and `size>0`;
  - **KF-M03**: error text with line/col parsed; error slot not cleared on success;
  - **KF-M04**: unset param → `err_kind=unset_param`;
  - **KF-M13**: specific IP → `err_kind=ip_host`;
  - **KF-M14**: every hard-deny/network form from the catalog compiles under `(deny default (with message "pc-run-1"))`;
  - **KF-M15**: `(param …)` in subpath, literal, prefix, regex, unix-socket path-literal, global-name, string-append;
  - **KF-M16**: 1016 B literal OK, 1024 B rejected, 4000 B param OK.
- [X] T018 [US1] KF-M27 and KF-M28 via step `compile-rules <shape> <n>` in `tests/kernel_facts/src/bin/kf-probe/macos.rs`: [SR-006]
  - shapes `deny-default-allow` (the shape measured in earlier research), `allow-default-deny`, `require-any`;
  - M27: 10,000 `deny-default-allow` → `err_kind=data_too_long`, no signal;
  - M28: 10,000 `require-any` → NULL and `err=none`.

  The runner uses a 120 s timeout.
- [X] T019 [US1] KF-M17: 20,000 `deny-default-allow` rules → the observation `exit=signal:6` (SIGABRT), recorded while the runner continues; marked `slow`. File: `tests/kernel_facts/tests/kernel_facts.rs` [SR-006] [SR-007]
- [X] T020 [US1] KF-M05 and KF-M06: step `apply-selfcheck` (apply allow-default bytecode via path A, then `sandboxed` must be 1 and still 1 after a second identical apply) and step `apply-then-spawn` (apply, then spawn `kf-probe selfcheck`, which must print `sandboxed=1`). The control is the unapplied `selfcheck`, which must print 0. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-002]
- [X] T021 [US1] KF-M07 and KF-M08: step `read <control|literal-etc|literal-private>` on `/etc/hosts` (reports `bytes` only, never contents) and step `tmp-create <control|subpath-tmp|subpath-private> <dir>`, where `<dir>` is a unique, exclusively created dir under `/private/tmp`, removed afterwards. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-002] [SR-005] [SR-014]
- [X] T022 [US1] KF-M09 and KF-M10: step `nest <scratch>`. Apply profile A (deny read of `a`), then apply B (deny read of `b`) and expect rc -1, errno EPERM, and `b` still readable. Re-applying A gives rc 0. After apply, `compile` succeeds (M10). File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-002]
- [X] T023 [US1] KF-M11: step `setuid-exec <control|caged>` execs the fixed argv `/usr/bin/sudo -n -V` with stdin `/dev/null` and a 10 s timeout. Record the exec errno and exit status; the control must exec successfully. Expected: the caged `execve` fails with errno EPERM (1) and the control execs successfully. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-004] [SR-007]
- [X] T024 [US1] KF-M12: step `no-sandbox-exec` applies `(version 1)(allow default)(allow process-exec (with no-sandbox))` and execs its own `current_exe()` with the argument `selfcheck`, which must print `sandboxed=0`. The control without `with no-sandbox` prints 1. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-004]
- [X] T025 [US1] KF-M18: implement the fork window in `tests/kernel_facts/src/sys/macos.rs` as `fork_apply_exec(bytecode, devnull_fd, argv, envp) -> pid`. The child sequence is exactly `dup2`, `dup2`, `__mac_syscall`, `execve`, `_exit(127)`, and everything is prepared before `fork`. Add step `patha-contention <trials>` in `tests/kernel_facts/src/bin/kf-probe/macos.rs`: 4 threads loop `dlopen`/`dlsym`/`dlclose`, and the main thread runs 200 trials of `/bin/cat /private/etc/hosts` under a deny rule. Each trial has a `waitpid` deadline of 3 s with kill. Report `enforced=` and `hangs=`. The control is 5 trials without apply, which must exit 0. [SR-007] [SR-008]
- [X] T026 [US1] KF-M19: step `fd-parent <scratch>` creates `scratch/secret` (16 bytes), opens it without CLOEXEC, and spawns `fd-child <fd>` with the fd inherited. `fd-child` applies a profile that denies `file-read*` on that path, reads the fd (expect `bytes=16`), and does a fresh `open` (expect `errno=1`). It reports counts only. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-005] [SR-014]
- [X] T027 [US1] KF-M20: step `ext-parent <a> <b> apply-first` compiles one profile once (`deny file-write*` on the scratch subpath, `allow file-write*` with the `com.apple.app-sandbox.read-write` extension). It issues a token for `a` and writes it to `ext-child` over **stdin** (never argv or env), with the bytecode passed as a file in scratch. The child applies, consumes, writes to `a` (ok) and to `b` (EPERM). A second run with a token for `b` gives the reverse. The token is never printed. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs` [SR-017] [SR-005]
- [X] T028 [US1] KF-M21 and KF-M22: [SR-002]
  - step `read <control|deny-users> <the Shared folder under /Users>`: open the directory, expect `errno=1` under `(deny file-read* (subpath "/Users"))`;
  - step `check-oracle <scratch>`: apply allow-default with a deny on read of `scratch/x` and a deny on `mach-lookup (global-name "com.procage.kf.denied")`. Then `sandbox_check` with `NO_REPORT` must give `file-read-data x`=1, `y`=0, global-name denied=1, other=0.

  File: `tests/kernel_facts/src/bin/kf-probe/macos.rs`

**Checkpoint**: `just facts KF-M` passes every US1 fact on the reference Mac

---

## Phase 4: User Story 2: Linux facts and tier detection (Priority: P1)

**Goal**: probe → tier → KF-L01…L13 with N/A on lower tiers

**Independent Test**: `just kf-linux` → `tier: T2`; `just kf-linux-t1` → `tier: T1`; applicable facts PASS in both

- [X] T029 [US2] Step `measure <cap>` in `tests/kernel_facts/src/bin/kf-probe/linux.rs` for landlock (abi, errata), seccomp_filter, userns, uid_map (`setgroups deny` plus maps), tmpfs, ro_bind (locked ro bind, write → EROFS), fresh_proc (userns+pidns fork, `mount proc`), netns (only `lo`, not `IFF_UP`) and apparmor (sysctl read). Each runs in its own process, so a crash means absent. Never read `uname` for capabilities. [SR-016]
- [X] T030 [US2] Tier derivation in `tests/kernel_facts/tests/kernel_facts.rs`, per research R5: [SR-016]
  - T1 = userns ∧ uid_map ∧ tmpfs ∧ ro_bind ∧ landlock≥1 ∧ seccomp_filter;
  - T2 = landlock≥4 ∧ seccomp_filter;
  - T3 otherwise.

  Any measurement whose exit is not `Code(0)` with `ok=1` counts as absent. Print the tier line. Fail when `PROCAGE_KF_EXPECT_TIER` is set and differs.
- [X] T031 [US2] KF-L01, KF-L02 and KF-L12 from probe results in `tests/kernel_facts/tests/kernel_facts.rs`:
  - L01: abi≥1 with errata reported;
  - L02: `user_notif` in actions;
  - L12 (tier T2 inside a container only, else N/A; container detected by `/.dockerenv` or `/run/.containerenv`): userns errno EPERM while landlock is present.
- [X] T032 [P] [US2] KF-L06 and KF-L08 (tiers T1, T2): steps `landlock-write <scratch>` (allow write in `scratch/a`, write in `scratch/b` → EACCES; control without Landlock succeeds) and `landlock-devnull` (write `/dev/null` denied until a rule is added) in `tests/kernel_facts/src/bin/kf-probe/linux.rs` [SR-002]
- [X] T033 [P] [US2] KF-L03, KF-L04, KF-L05 and KF-L07 (T1 only): steps `userns`, `ro-bind`, `tmpfs` and `netns` in `tests/kernel_facts/src/bin/kf-probe/linux.rs`, each with a control (the same action outside the namespace) [SR-002]
- [X] T034 [US2] KF-L09, KF-L10 and KF-L11 (T1 only):
  - `nested-undo`: in a nested userns, remount rw → EPERM, umount tmpfs fails, non-recursive bind → EINVAL;
  - `nested-uidmap`: under Landlock, writing the nested uid_map → EACCES;
  - `mount-after-landlock`: a mount after `restrict_self` → EPERM.

  File: `tests/kernel_facts/src/bin/kf-probe/linux.rs`
- [X] T035 [US2] KF-L13: step `proc-mount`. In a container with masked /proc, `mount proc` fails and `fresh_proc=false` is reported; outside a container the fact is N/A. File: `tests/kernel_facts/src/bin/kf-probe/linux.rs`
- [X] T036 [US2] Recipes `kf-linux` (T2) and `kf-linux-t1` (adds `--security-opt seccomp=unconfined --security-opt apparmor=unconfined`) in `justfile`: [SR-013]
  - `docker run --rm --user 65534:65534`;
  - `-e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/tmp/target -e PROCAGE_KF_EXPECT_TIER=…`;
  - `-v "$PWD":/src:ro -w /src rust:1.99 cargo test --locked -p procage-kernel-facts --test kernel_facts`;
  - no `--privileged` and no host network.



**Checkpoint**: both container recipes pass with their expected tiers

---

## Phase 5: User Story 3: close the four open questions (Priority: P2)

**Goal**: dated, recorded answers with asserting facts KF-M23…M26

**Independent Test**: `just facts KF-M2` passes; `just bisect` reproduces the compile-abort bracket within 10%

- [X] T037 [US3] KF-M23 (path A layout): assert that `patha-contention` reports `enforced == trials` and `hangs == 0` on this lane. Record the finding constant with date and build in `tests/kernel_facts/tests/kernel_facts.rs`.
- [X] T038 [US3] Compile-abort bisection in `tests/kernel_facts/tests/kernel_facts.rs`, gated by `PROCAGE_KF_BISECT=1`, with a 10-minute budget per shape. It runs `compile-rules` in isolated children: `deny-default-allow` over 10,000–20,000 and `allow-default-deny` over 20,000–40,000 (a range bound that never aborts is recorded as such). It prints `bisect <shape>: ok<=N abort>=M (width P%)`. Then run `just bisect` and record the brackets as constants. [SR-006] [SR-007]
- [X] T039 [US3] KF-M24 (compile-abort bracket asserted): for each shape with an abort bracket, compile at the recorded `ok<=N` (no signal) and at `abort>=M` (SIGABRT). Marked `slow`. File: `tests/kernel_facts/tests/kernel_facts.rs` [SR-006]
- [X] T040 [US3] KF-M25 (extension ordering): `ext-parent <a> <b> consume-first`. The child consumes the token **before** applying, then writes to `a`; record allowed or denied. Disassemble `sandbox_extension_consume` and `sandbox_check` (`lldb --batch -o "disassemble -n …"` against a running `kf-probe`) and record the call targets in the finding constant with `proven=false`. Files: `tests/kernel_facts/src/bin/kf-probe/macos.rs`, `tests/kernel_facts/tests/kernel_facts.rs` [SR-017]
- [X] T041 [US3] KF-M26 (TIOCSTI): step `tiocsti <control|caged>`: [SR-003]
  - `posix_openpt`, `grantpt`, `unlockpt`;
  - spawn a child step that calls `setsid()`, opens the slave as its controlling tty, issues `ioctl(TIOCSTI, 'k')` and reads the slave non-blocking;
  - report `rc`, `errno` and `injected=0|1`; never touch the inherited terminal (stdin `/dev/null`) and never send a newline.

  Implement the pty and ioctl wrappers in `tests/kernel_facts/src/sys/macos.rs`. Record the finding. File: `tests/kernel_facts/src/bin/kf-probe/macos.rs`

**Checkpoint**: KF-M23…M26 pass and assert recorded answers

---

## Phase 6: User Story 4: gates and CI lanes (Priority: P2)

**Goal**: `just ci` mirrors CI; the workflow declares all lanes

**Independent Test**: `just ci` passes; each injected violation in quickstart scenario 9 and 10 fails its gate

- [X] T042 [P] [US4] Create `deny.toml`: [SR-011]
  - licences allow {MIT, Apache-2.0, Unicode-3.0};
  - `[sources] unknown-registry = "deny"`, `unknown-git = "deny"`;
  - `[bans] wildcards = "deny"`;
  - `[advisories] yanked = "deny"`.


- [X] T043 [US4] Create `justfile` with recipes `ci`, `fmt-check`, `lint`, `test`, `facts`, `test-outside`, `bisect`, `doc`, `deny`, `msrv` (`cargo +1.99.0 check --workspace --all-targets`), `no-std` (`cargo build -p procage-policy --target thumbv7em-none-eabihf`), `semver`, `planning-paths`, `kf-rosetta` and `ci-all`, per contracts/gates-and-lanes.md. Each prints `==> gate: <name>`. [SR-011] [SR-015] [SR-001]
- [X] T044 [US4] Create `.github/workflows/ci.yml` with the jobs gates, macos, macos-newest, macos-x86, linux, linux-userns, linux-next and linux-container, per contracts/gates-and-lanes.md: [SR-010]
  - `permissions: contents: read`;
  - `actions/checkout` and `taiki-e/install-action` pinned to full SHAs resolved with `git ls-remote`, each with a version comment;
  - `persist-credentials: false`; no `secrets.`;
  - `continue-on-error` on the allowed-missing lanes;
  - `PROCAGE_KF_EXPECT_TIER` per Linux lane.


- [X] T045 [US4] Add a "Development" section to `README.md`: `just ci`, and the fact suite's outside-sandbox rule (it fails, never skips, inside an agent sandbox). No planning paths. [SR-015]

**Checkpoint**: `just ci` green; violations from quickstart 9/10 caught

---

## Phase 7: Polish & cross-cutting

- [X] T046 Run quickstart scenarios 1–10 and record their outcomes in `specs/001-kernel-facts/quickstart.md` (local file): the sandboxed run (scenario 3) must show 0 enforcement PASS [SR-001]
- [X] T047 [P] Record the decisions: the R1 shape dependence, the 64 KiB cap, the silent `require-any` failure, and dated answers to the four open questions.
- [X] T048 [P] Verify that no file under `src/`, `crates/`, `tests/`, `.github/`, `README.md` or `Cargo.toml` mentions planning paths (`just planning-paths`), and that `cargo package -p procage --list` is unchanged apart from expected metadata [SR-015]
- [X] T049 Run `cargo clippy --workspace --all-targets -- -D warnings` and grep that `unsafe` appears only under `tests/kernel_facts/src/sys/`, with a `// SAFETY:` comment on each block [SR-009]

---

## Dependencies & Execution Order

- **Setup (T001–T004)** → **Foundational (T005–T015)** → the stories.
- **US1 (T016–T028)** and **US2 (T029–T036)** are independent of each other once
  Foundational is done (macOS vs Linux files; both touch the runner, so edit it
  sequentially).
- **US3** depends on US1's steps: T037 needs T025, T039 needs T038, T040 needs
  T027, T041 is standalone.
- **US4** depends only on Setup (gates). `just ci`'s `test` gate exercises
  US1–US3.
- **Polish** comes last.

## Parallel Opportunities

- T002 ∥ T003; T008 ∥ T011 (different files).
- US1 step functions in `kf-probe/macos.rs` and US2 steps in
  `kf-probe/linux.rs` can be written in parallel. Runner entries are appended
  sequentially.
- T042 ∥ T044 (deny.toml vs workflow). T047 ∥ T048.

## Implementation Strategy

1. **MVP** = Setup, then Foundational, then US1. The macOS facts are the
   riskiest assumptions (path A apply, the compile limits, extension grants), and they are verified locally on
   the reference Mac.
2. Then US2 (Linux in Docker, T2 and T1), then US3 (questions), then US4 (gates
   and CI file).
3. Each checkpoint runs `just facts` on its platform. Nothing is committed
   without the user's authorization.

## Phase 8: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-10-29 (commit 24f3263).

- [X] T050 [SR-002] Add a test for SR-002 (Every enforcement fact MUST include a control run of the same action without the restriction that succeeds, and MUST match the specific expected errno, exit code or data, never just "the child failed") — touchpoints: tests/kernel_facts/src/bin/kf-probe/linux.rs, tests/kernel_facts/src/bin/kf-probe/macos.rs, tests/kernel_facts/tests/kernel_facts.rs [converge: implemented-unverified; The unexpected-errno scenario was observed (KF-M25 and KF-L07 failed with expected and observed values), but no test exercises a failing control run turning into SETUP-FAILED.]
- [X] T051 [SR-003] Add a test for SR-003 (The TIOCSTI probe MUST operate only on a pseudo-terminal pair it creates, after detaching from any controlling terminal, and MUST NOT write a newline or command text) — touchpoints: tests/kernel_facts/src/bin/kf-probe/macos.rs, tests/kernel_facts/src/sys/macos.rs [converge: implemented-unverified; The control is in place and was run, but no test asserts that the inherited terminal is untouched (e.g. that the child has no controlling terminal before opening the pty).]
- [X] T052 [SR-005] Add a test for SR-005 (Facts MUST create and touch files only in their own freshly created 0700 temp directory (or under unique, exclusively created names where a fact needs /private/tmp itself), MUST NOT write under $HOME, and MUST remove what they create) — touchpoints: tests/kernel_facts/src/lib.rs [converge: implemented-unverified; Private, removed scratch dirs are unit-tested and no procage-kf-* remained after full runs, but no test exercises the pre-planted-symlink scenario.]
- [X] T053 [SR-007] Add a test for SR-007 (Timing-dependent facts MUST use fixed trial counts and per-child timeouts that kill the child and fail the fact; the compile-abort bisection MUST be opt-in and time-budgeted) — touchpoints: justfile, tests/kernel_facts/src/lib.rs, tests/kernel_facts/tests/kernel_facts.rs [converge: implemented-unverified; The default run never bisects (KF-M24 took 62 s against 776 s with bisection), but no test shows a hanging child being killed and reported as a timeout.]
- [X] T054 [SR-009] Add a test for SR-009 (All unsafe code MUST be confined to one test-only sys module per OS, with a SAFETY comment on every unsafe block; private symbols MUST be resolved by dynamic lookup and a missing symbol MUST fail its fact by name) — touchpoints: Cargo.toml, tests/kernel_facts/Cargo.toml, tests/kernel_facts/src/sys/linux.rs, tests/kernel_facts/src/sys/macos.rs, tests/kernel_facts/src/sys/mod.rs [converge: implemented-unverified; The lint scenario is verified (an injected unsafe failed the lint gate; 29 unsafe blocks match 29 SAFETY comments), but resolving a nonexistent symbol is not tested.]
- [X] T055 [SR-016] Add a test for SR-016 (The Linux probe MUST derive the tier only from measurements taken in throwaway children, MUST treat a failed, crashed or timed-out measurement as absent, and MUST NOT consult the kernel version string for capabilities) — touchpoints: tests/kernel_facts/src/bin/kf-probe/linux.rs, tests/kernel_facts/tests/kernel_facts.rs [converge: implemented-unverified; The default-seccomp container scenario passed (T2 with userns EPERM), but no test shows a crashed measurement counted as absent.]

## Phase 9: Convergence

- [X] T056 Update specs/001-kernel-facts/contracts/probe-protocol.md to the implemented step names and arguments (`read control-users|deny-users`, `measure seccomp`, `landlock-devnull <scratch> <rule|no-rule>`, `patha-contention <n> <apply|control>`, helper steps `proc-inner`, `tiocsti-child`) per plan: contracts (partial)
- [X] T057 Align `Fact.kind` in specs/001-kernel-facts/data-model.md with the implemented `Enforcement | Observation` per plan: data model (partial)
