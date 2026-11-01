# Implementation Plan: Kernel facts as regression tests

**Branch**: `001-kernel-facts` | **Date**: 2026-10-29 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-kernel-facts/spec.md`

## Summary

Turn the repository into a workspace (root facade crate `procage` 0.0.1,
`crates/procage-policy` as a `no_std` + `alloc` placeholder). Add an unpublished
member `tests/kernel_facts` that re-verifies every catalogued kernel fact on
the running kernel:

- a probe binary `kf-probe` performs exactly one step per invocation: compile,
  apply to itself, act, and print `key=value` observations;
- a `harness = false` runner owns the catalog, runs every fact with a control
  run, timeouts and crash isolation, measures the Linux tier, and prints a
  three-state report with OS build and date.

The runner fails every enforcement fact when it already runs inside a Seatbelt
sandbox. The four open questions (path A layout, compile-abort threshold, extension ordering, TIOCSTI) get probes, dated answers and
asserting facts. A `justfile` mirrors CI: fmt, clippy, tests and facts, doc,
cargo-deny, MSRV, no_std, semver, and a planning-path gate. A pinned,
read-only GitHub workflow declares the macOS and Linux lanes. Pre-plan
measurement (research R1) showed the 20k-rule abort depends on rule shape and
that a 64 KiB bytecode cap fails cleanly first. KF-M27 and KF-M28 were added
for that.

## Technical Context

**Language/Version**: Rust, edition 2024, MSRV 1.99 (1.99.0 toolchain; stable 1.99.1)

**Primary Dependencies**: `libc` 0.2 (kernel-facts crate only). No other runtime dependencies. The policy crate has none.

**Storage**: Files only: the report at `target/kernel-facts/report-<os>-<arch>.txt`; private temp dirs per fact (removed afterwards)

**Testing**: `cargo test` (unit) plus a custom `harness = false` integration test `kernel_facts`; `just ci`

**Target Platform**: macOS 26.6.2 arm64 (reference), x86_64 under Rosetta (local, via `--target x86_64-apple-darwin`), Linux ≥ 5.13 (Docker 7.0.14 locally; ubuntu-24.04/26.04 and debian:13 in CI)

**Project Type**: Library workspace plus an unpublished test crate

**Performance Goals**: full macOS fact run < 5 min (SC-002). Estimate ≈ 2.5 min, dominated by KF-M17 (~50 s) and the KF-M24 bracket edges

**Constraints**: no root or admin; no network except dependency fetch; no fact code between fork and exec except KF-M18's syscall-only sequence; nothing published cites planning paths

**Scale/Scope**: 28 macOS facts, 13 Linux facts, 4 question probes, about 9 just gates, 1 workflow

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan complies | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | A sandboxed runner fails every enforcement fact (SR-001). A missing symbol fails its fact by name. The tier comes only from measurements; a failed measurement means absent (SR-016). A mismatch with the lane's expected tier fails | KF runner precheck; `measure` children; `PROCAGE_KF_EXPECT_TIER` | none |
| II. Types over strings | No IR yet (spec 003). Test SBPL is built from constants plus `mkdtemp` paths. The runner asserts those paths match `^[A-Za-z0-9/._-]+$` before inlining them, so no escaper is needed. The policy crate is a `no_std` placeholder with unsafe forbidden | path-charset assert in `kf-probe`; no_std gate | the escaper arrives in spec 003 |
| III. Kernel is the oracle | Every fact runs a real child and observes errno, rc, bytes or the self-check. Each enforcement fact has a control run (SR-002). Reports carry date and build (SR-012) | runner output; report file | Linux distro lanes are verified only once CI runs (needs push authorization) |
| IV. Syscalls only between fork and exec; unsafe in sys only | Steps are exec'd fresh and cage themselves. The only fork window is KF-M18: `dup2`, `dup2`, `__mac_syscall`, `execve`, `_exit`, all prepared in the parent and run with a multithreaded parent (4 dyld-contention threads). Unsafe exists only in `procage-kernel-facts::sys::{macos,linux}`, and each block has a `SAFETY:` comment (clippy `undocumented_unsafe_blocks`) | KF-M18; clippy | the module path differs from `procage::{macos,linux}::sys`; see Complexity Tracking |
| V. Hygiene by default | Step children start with `env_clear()` and only the keys they need, stdin `/dev/null`. The TIOCSTI probe uses its own pty after `setsid` (SR-003). Scratch dirs are 0700 and removed (SR-005) | runner `Command` builder; TIOCSTI probe | — |
| VI. Private interfaces, honestly | Every libsandbox and `__mac_syscall` symbol is resolved with `dlsym` at step start; absence becomes a named FAIL (KF-M01). Linux capabilities are measured, never derived from `uname` | KF-M01; probe | — |
| VII. A library, not a harness | `procage` gains no API or global state. Edition 2024 and MSRV 1.99 are gated. The policy crate is `no_std` + `alloc` and unsafe-free (thumbv7em build gate). cargo-deny, semver-checks and docs with `-D warnings` are all in `just ci` | justfile; workflow | No consumer migration note is needed: no API change |

**Workflow rules**: one spec (001). The plan names its evidence and its gaps
above. Local planning stays local (SR-015 gate). The R1 re-measurement and the four
answers are recorded as dated decisions. No commits without authorization.

**Gate result (pre-research)**: PASS with one justified deviation (IV, module
path). **Post-design re-check**: PASS. The design adds no unsafe outside `sys`
and no fork window beyond KF-M18. The contracts keep observations to
numbers/errno (SR-014).

## Project Structure

### Documentation (this feature)

```text
specs/001-kernel-facts/
├── plan.md              # This file
├── research.md          # Phase 0 (R1 re-measured limits, R2–R10 decisions)
├── data-model.md        # Phase 1
├── quickstart.md        # Phase 1
├── contracts/
│   ├── probe-protocol.md   # kf-probe CLI, observation lines, exit codes
│   ├── report-format.md    # runner output and report file
│   └── gates-and-lanes.md  # just recipes, env vars, CI lane matrix
├── threat-model.yaml    # ThreatSpec (+ threat-model.md, security/)
└── tasks.md             # Phase 2 (/speckit-tasks)
```

### Source Code (repository root)

```text
Cargo.toml                    # [workspace] + root package `procage` 0.0.1 (facade, unchanged API)
Cargo.lock
src/lib.rs                    # unchanged placeholder docs
crates/
└── procage-policy/
    ├── Cargo.toml            # publish = false (decided in spec 019), no deps
    └── src/lib.rs            # #![no_std] extern crate alloc; placeholder
tests/
└── kernel_facts/             # crate procage-kernel-facts, publish = false
    ├── Cargo.toml            # libc; [[test]] kernel_facts harness = false; own [lints]
    ├── src/
    │   ├── lib.rs            # Observation parse/format, Outcome, report, run_with_timeout, scratch dirs, civil date
    │   ├── sys/
    │   │   ├── mod.rs        # #![allow(unsafe_code)]: the only unsafe in the workspace
    │   │   ├── macos.rs      # dlsym table, compile/apply/check/extension, __mac_syscall, fork window (M18), sysctl, pty/TIOCSTI
    │   │   └── linux.rs      # landlock structs + syscalls, seccomp filter, unshare/mount, SIOCGIFFLAGS
    │   └── bin/kf-probe/
    │       ├── main.rs       # step dispatch, path-charset assert
    │       ├── macos.rs      # macOS steps
    │       └── linux.rs      # Linux steps + `measure <cap>`
    └── tests/
        └── kernel_facts.rs   # runner: catalog KF-M01…M28, KF-L01…L13, precheck, tier, bisection (opt-in), report
justfile
deny.toml
.github/workflows/ci.yml
README.md                     # adds "Development" section: just ci, outside-sandbox note (no planning paths)
```

**Structure Decision**: the root stays the published `procage` facade, so the
0.0.1 placeholder, its README and its licence files are untouched. A
`[workspace]` is added with members `crates/procage-policy` and
`tests/kernel_facts`. The fact suite sits where the design names it. It is a
crate of its own because it needs unsafe FFI, a probe binary and a custom
harness, none of which may live in a published crate.

## Phase notes

- **Phase 0**: complete ([research.md](research.md)). No NEEDS CLARIFICATION
  remained. The re-measurement R1 changed the catalog (KF-M17 reworded; KF-M27
  and KF-M28 added).
- **Phase 1**: complete: [data-model.md](data-model.md),
  [contracts/](contracts/), [quickstart.md](quickstart.md).
- **Security**: the SR-001…SR-016 requirements map onto this design:

  | SR | Where it lands |
  |---|---|
  | 001 | runner precheck |
  | 002 | control step per fact |
  | 003 | TIOCSTI pty step |
  | 004 | fixed argv in `kf-probe` |
  | 005 | `lib.rs` scratch dirs |
  | 006 | every step is a child; abort is an observation |
  | 007 | `run_with_timeout`; `PROCAGE_KF_BISECT` |
  | 008 | runner uses `Command` only |
  | 009 | `sys/` |
  | 010 | `ci.yml` |
  | 011 | `deny.toml` |
  | 012 | report header |
  | 013 | `just kf-linux*` |
  | 014 | observation contract |
  | 015 | `just planning-paths` |
  | 016 | `measure` children |

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Unsafe in `procage-kernel-facts::sys`, not `procage::{macos,linux}::sys` (IV) | The facts must call libsandbox, `__mac_syscall`, Landlock and seccomp now, before spec 004 or 008 create the published `sys` modules. The crate is `publish = false` and test-only, and the same rules apply: one module per OS, `SAFETY:` comments, clippy-enforced | Putting the FFI into `procage::macos::sys` now would publish an unreviewed FFI surface in 0.0.1 and pre-empt spec 004's design. Specs 004 and 008 may move this code into the published `sys` modules and point the facts at them |
| A third workspace member (test crate) | A custom harness (three-state report) and a probe binary | libtest has no N/A state (FR-011), and a probe binary inside `procage` would ship with the crate |
