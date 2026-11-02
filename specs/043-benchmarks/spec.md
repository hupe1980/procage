# Feature Specification: Published spawn benchmarks

**Feature Branch**: `043-benchmarks` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented (2026-11-02)

**Input**: procage positions itself as the low-latency sandbox tier (sub-millisecond to milliseconds, against 100 ms and more for microVMs) and states targets: at most 0.3 ms median overhead over a plain fork and exec on macOS, at most 1 ms on Linux tier T1. 0.1.0 has no benchmark; two ignored latency probes print numbers that nothing records.

## Context

A claim of speed is a claim like any other: it needs a reproducible measurement
on named hardware and OS builds. The interesting comparisons are:

- a plain `fork`+`exec` of a trivial program (the floor);
- procage with a cached policy (the common case: one policy, many commands);
- procage with a policy compiled for the first time;
- `sandbox-exec -p` with the same profile (macOS) and `bwrap` with
  equivalent options (Linux), the tools others shell out to.

## Clarifications

### Session 2026-11-01

- Q: Are benchmarks a CI gate? → A: No. CI runs them briefly to keep them
  compiling and to publish indicative numbers; the claims are measured on the
  reference machine and stated with its model and OS build. Shared runners
  are too noisy to gate on.
- Q: What if a target is missed? → A: The docs state the measured number; the
  target is revised or the regression fixed, never left unstated.

- Q: A benchmarking framework? → A: No. A small bench program
  (`cargo bench`, no framework) reports median, p90 and p99 of many
  iterations per case; a statistics framework would add a large dependency
  tree to a security library for numbers a few hundred samples give.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A user can check the speed claim (Priority: P1)

**Independent Test**: One command runs the benchmark suite and prints median,
p90 and p99 for each case.

**Acceptance Scenarios**:

1. **Given** the reference Mac, **When** the suite runs, **Then** it reports
   each case, and the README's numbers match within noise.
2. **Given** a Linux T1 and a T2 host, **Then** the same.
3. **Given** a host without `bwrap`, **Then** that comparison is skipped with
   a message, the others run.

---

### User Story 2 - Regressions are visible (Priority: P2)

**Acceptance Scenarios**:

1. **Given** a change that doubles cached-spawn time, **When** the suite runs
   locally before and after, **Then** the difference is reported.

### Edge Cases

- Violation reporting on: measured as its own case (macOS starts a monitor
  once per process; Linux a supervisor per run).
- Inside another sandbox (an agent's): the suite refuses to run, like the
  kernel facts, rather than publish skewed numbers.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The repository MUST contain a benchmark suite covering the
  cases of the context, per backend and Linux tier, plus reporting on/off.
- **FR-002**: Results MUST state machine model, OS build or kernel release,
  tier, toolchain and date.
- **FR-003**: The README and site MUST state the measured medians with those
  details, replacing the targets once measured.
- **FR-004**: CI MUST build the suite and run it in a short mode, without
  failing on timing.

## Success Criteria *(mandatory)*

- **SC-001**: Published medians exist for macOS (reference Mac) and Linux T1
  and T2, each with the comparison tool.
- **SC-002**: The speed claim in the docs is a measured number with its
  conditions.

## Assumptions

- The reference machine is the maintainer's Apple M4 Pro; Linux numbers come
  from a named runner or host.

## Out of Scope

- Throughput of the commands themselves inside the cage.
