# Implementation Plan: The escape suite

**Branch**: `009-escape-suite` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

## Summary

Two new integration-test files hold the canaries:

- `tests/escape_macos.rs`;
- `tests/escape_linux.rs`.

Each canary is a test function named `rNN_…`. It spawns this test binary,
or a system program, as a caged child through the public API, tries the
escape, and asserts the specific refusal. It also runs a **positive
control** under the same setup. The control is either the same operation
on a granted target, or the same attempt with the class waived, which
proves the refusal comes from procage and not from the host. A variant
this release does not handle is a canary marked
`#[ignore = "open: R-NN …"]`.

The catalog gate (`tests/threat_model.rs`) gains:

- the status `partial`;
- an `### Open variants` subsection;
- five new rules: canary coverage, escape-suite evidence location, no
  ignored evidence, per-platform evidence for `mitigated`/`detected`,
  and no open canary on a `mitigated` class.

Each rule gets a defect-injection test.

The canaries' results decide each status in `THREAT_MODEL.md`. The
release status, README and crate docs follow. CI runs the suites in every
lane. The Linux lanes also gain the spawn tests (008 left them out) with
an expected tier.

The canaries need a few more doc-hidden `testing` helpers in each
backend's `sys` module (Mach lookup, fcntl, procargs, pty and ioctl calls,
more syscall probes). No library behaviour changes unless a canary
exposes a defect in an existing mitigation (FR-009).

## Technical Context

**Language/Version**: Rust 2024, MSRV 1.99

**Primary Dependencies**: `libc` (already a dependency on both OSes); no new crates

**Storage**: none (scratch directories under the temp dir, fake homes)

**Testing**:
- `cargo test --test escape_macos` on macOS 26.6.2;
- `just linux` (T2) and `just linux-t1` (T1) on Docker Desktop 7.0.14-linuxkit, aarch64, Landlock ABI 8;
- `cargo test --test threat_model` anywhere.

**Target Platform**: macOS 26+ arm64/x86_64; Linux ≥ 6.7 (Landlock ABI ≥ 4) on aarch64/x86_64

**Project Type**: library (tests + docs + CI)

**Performance Goals**: each platform suite < 60 s per tier (SC-004)

**Constraints**:
- canaries touch only scratch paths;
- no waits longer than a few seconds;
- no skip on `AlreadySandboxed`.

**Scale/Scope**: 20 classes, 32 class-platform pairs, roughly 45 canaries

## Constitution Check

| Principle | Compliance | Gap |
|---|---|---|
| I. Fail closed | Tier-dependent canaries accept a typed refusal before any child as handled; no canary accepts a silent weaker cage | — |
| II. Types | Canaries use the typed policy API only; no raw SBPL except the existing `sysctl-read` allowance the test child needs | — |
| III. Kernel is the oracle | This feature *is* the principle's check: every status change rests on a caged canary; positive controls rule out host-caused refusals | x86_64, Ubuntu and Debian kernels only after a push |
| IV. Unsafe in `sys` only | New helpers live in `src/macos/sys.rs` and `src/linux/sys.rs` with `SAFETY:` comments, exposed through the doc-hidden `testing` modules; no new code runs between fork and exec | — |
| V. Hygiene | Canaries for fds, env, tty, lifetime (and helper, open) are exactly the principle's named checks | Helper canary open until 021 |
| VI. Private interfaces | No new private interfaces (bootstrap lookup and sysctl are public libSystem calls) | — |
| VII. Library | No new dependency, no global state | — |

**Gate**: PASS.

## Project Structure

### Documentation (this feature)

```text
specs/009-escape-suite/
├── spec.md, plan.md, research.md, data-model.md, quickstart.md
├── contracts/catalog.md      # catalog grammar + gate rules + canary naming
├── threat-model.yaml/.md
└── tasks.md
```

### Source Code (repository root)

```text
tests/
├── escape_macos.rs           # NEW: macOS canaries (R-02…R-12, R-21…R-26)
├── escape_linux.rs           # NEW: Linux canaries (R-02, R-04, R-07…R-10, R-21…R-26, R-28…R-30)
├── threat_model.rs           # gate: partial, Open variants, canary rules
src/macos/{mod.rs,sys.rs}     # testing helpers: mach_lookup, fcntl, procargs, pty, ioctl, kill
src/linux/{mod.rs,sys.rs}     # testing helpers: more syscall probes, pty, ioctl
THREAT_MODEL.md               # statuses, evidence, Open variants, release status
README.md, src/lib.rs         # release status
.github/workflows/ci.yml      # escape suites + Linux spawn tests in every lane
justfile                      # `escape` recipe; linux recipes run escape_linux
```

**Structure Decision**: one canary file per system, so the gate can tell
platform coverage from the file alone, and each file is a separate test
binary with its own `child_entry`. As in `spawn_macos.rs` and
`spawn_linux.rs`, a little harness code is duplicated between the two
files rather than adding a shared module, because the two harnesses
differ (tiers, options).

## Phases

- **Phase 0 (research.md)**: one entry per class and platform:
  - the attempt;
  - the expected refusal;
  - the positive control;
  - the predicted status;
  - the open variants;
  - the lanes that are informative.
- **Phase 1 (data-model.md, contracts/catalog.md, quickstart.md)**:
  - the catalog grammar and gate rules;
  - the canary naming;
  - the commands that validate the suite.

## Complexity Tracking

No constitution violations.
