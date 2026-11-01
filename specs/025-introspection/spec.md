# Feature Specification: Other processes stay opaque

**Feature Branch**: `025-introspection` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: A caged child can read the command lines and environments of the user's other processes (R-25, partial). Command lines and environments routinely hold tokens. On macOS the `KERN_PROCARGS2` sysctl returns them for any same-user process; on Linux, a granted `/proc` exposes `cmdline` (and on tier T2 more).

## Context

At 0.1.0:

- **macOS**: `process-info*` is allowed only for the same sandbox, but the
  numeric `KERN_PROCARGS2` sysctl is not mediated by that rule. A measurement
  on macOS 26.6.2 (25G83, 2026-11-01) found:
  - a deny-default profile that says nothing about it lets the read through;
  - `(deny process-info* (target others))` does not stop it;
  - an **explicit** `(deny sysctl-read)` followed by **named** sysctl allows,
    together with an explicit `(deny process-info-pidinfo)` followed by an
    allow for the process itself, refuses it (EPERM), while the named sysctls
    and the process's own information keep working.
  The base profiles allow `sysctl-read` without a filter, so they cannot use
  this today.
- **Linux T1**: the child has its own user and mount namespaces but shares the
  PID namespace; `/proc` shows every process of the user.
- **Linux T2**: no namespaces; Landlock's ptrace scoping protects `environ`
  but `cmdline` is world-readable through `/proc`.

## Clarifications

### Session 2026-11-01

- Q: macOS fix by a new base version? → A: Yes, if the base program set
  passes with a named sysctl allowlist: a new frozen base version (V4) with
  the allowlist and the pidinfo rule; V1–V3 stay as they are, and the docs
  say which base closes R-25 on macOS.
- Q: Linux T1 — PID namespace? → A: Yes: the child gets a new PID namespace
  and a fresh `/proc`, so other processes are invisible; the run's own
  descendants stay visible to each other. The lifetime rules (the whole run
  is killed) must keep holding.
- Q: Linux T2? → A: Hiding `/proc/<pid>` of others is not expressible; the
  docs state the residual (command lines readable), and a policy that grants
  `/proc` on T2 is an approximation by name.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - On macOS a caged child cannot read other command lines (Priority: P1)

**Why this priority**: tokens in command lines and environments of the user's
editor, agent or shell are the easiest secrets to steal on macOS today.

**Independent Test**: The R-25 canary (today ignored as open on macOS) reads
`KERN_PROCARGS2` of a same-user process from a child on the new base; it is
refused; a positive control reads its own.

**Acceptance Scenarios**:

1. **Given** the new base, **When** the child reads another process's
   arguments, **Then** it gets EPERM.
2. **Given** the new base, **When** the base program set runs (shells,
   compilers, package managers, the developer tools of the older bases),
   **Then** every program works as before.
3. **Given** a child listing its own descendants (`ps` of the run), **Then**
   that still works, or the limit is documented.

---

### User Story 2 - On Linux T1 other processes are invisible (Priority: P1)

**Independent Test**: The T1 canary lists `/proc` and reads another
process's `cmdline`; it sees only the run's own processes.

**Acceptance Scenarios**:

1. **Given** T1, **When** the child lists processes, **Then** it sees only
   its run.
2. **Given** `Lifetime::Run`, **When** the run ends, **Then** every process is
   still killed (escape suite unchanged).

---

### User Story 3 - T2 says what it cannot hide (Priority: P2)

**Acceptance Scenarios**:

1. **Given** T2, **Then** the docs and the threat model state that other
   processes' command lines stay readable, and the cage records the
   approximation when `/proc` is granted.

### Edge Cases

- Programs that read `kern.*`/`hw.*` sysctls not in the allowlist: found by the
  program-set measurement; added by name, never by wildcard.
- The run's own violation reporting on macOS (it reads the log, in the
  parent): unaffected.
- PID namespace and `Cage::exec` (the helper keeps its pid): the namespace
  applies only to spawned runs; documented.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: A new frozen macOS base version MUST allow sysctls by name only
  and deny process information of other processes such that
  `KERN_PROCARGS2` of any process outside the run is refused.
- **FR-002**: The new base MUST pass the base program set on macOS 26 and 27.
- **FR-003**: On Linux T1, spawned runs MUST get a new PID namespace and a
  fresh `/proc`; the run-lifetime guarantees MUST hold unchanged.
- **FR-004**: On Linux T2, granting `/proc` MUST be an approximation by name,
  and the threat model MUST state the residual.
- **FR-005**: The R-25 canaries MUST be non-ignored on macOS (new base) and
  T1, and the threat model MUST give R-25's per-platform status.

### Key Entities

- **Sysctl allowlist**: the named sysctls of the new base, each with the
  program that needed it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On the V4 base, reading the arguments, environment or process information of any process outside the run (KERN_PROCARGS2, KERN_PROCARGS, pidinfo) MUST fail with EPERM, while the child's reads of its own MUST succeed.
  - Mitigates: `threat.procargs-variant` via `mitigation.deny-then-name`
  - Given a same-user process holding a token in its arguments and a child on the V4 base, when the child reads that process's KERN_PROCARGS2, KERN_PROCARGS and pidinfo, then each read fails with EPERM
  - Given the same child, when it reads its own KERN_PROCARGS2 and pidinfo, then both succeed
- **SR-002** (P1): The V4 sysctl allowlist MUST name each sysctl literally, with the program that needed it, and MUST NOT contain a prefix or regular-expression form; V1 to V3 MUST compile byte-identical to before.
  - Mitigates: `threat.allowlist-widening` via `mitigation.literal-allowlist`
  - Given the V4 base, when its sysctl rules are lowered, then every allow is a literal name with a recorded program, and a prefix or regex form fails the test
  - Given the V1, V2 and V3 fixtures, when they are compiled, then they equal the frozen fixtures
- **SR-003** (P1): V4 MUST NOT be frozen until the R-25 canaries and the base program set pass on the macOS 26 and 27 lanes, and the canaries MUST fail, never skip, when the read succeeds or the child is already sandboxed.
  - Mitigates: `threat.unmeasured-release` via `mitigation.measure-before-freeze`
  - Given the macOS 26 and 27 lanes, when the R-25 canaries and the base program set run on V4, then the canaries are refused and every program works as on V3
  - Given a lane where the read succeeds, when the canary runs, then it fails the lane
- **SR-004** (P1): On Linux T1 every spawned run MUST run inside a new PID namespace with a /proc mounted from inside it, and no proc mount showing processes outside the run MUST be reachable.
  - Mitigates: `threat.stale-proc-view` via `mitigation.fresh-proc`
  - Given T1 and a same-user process outside the run, when the child lists /proc and reads that process's cmdline by its outside pid, then it sees only the run's processes and the read fails
  - Given the same child, when it lists the proc mounts in /proc/self/mountinfo, then every proc mount shows only the run's processes
- **SR-005** (P1): With the PID namespace, Lifetime::Run MUST still end every process of the run, orphans MUST be reaped, and the R-23 escape suite MUST pass unchanged on T1.
  - Mitigates: `threat.pidns-lifetime` via `mitigation.lifetime-suite`
  - Given T1 and a double-forked descendant, when the run ends, then the descendant is gone
  - Given a child that orphans many short-lived processes, when the run proceeds, then no zombie of the run remains
  - Given the R-23 canaries, when they run on T1 with the namespace, then every canary holds
- **SR-006** (P1): On Linux T2 a policy whose rules reach /proc, literally or through an ancestor, MUST be refused as a capability gap unless the caller accepts the approximation by name, and the acceptance MUST be recorded in the receipt; other processes' environ MUST stay unreadable.
  - Mitigates: `threat.t2-silent-proc` via `mitigation.proc-gap`
  - Given T2 and a policy that grants read on /, when the cage spawns without the approximation, then it is refused with a capability gap naming /proc
  - Given the approximation accepted by name, when the child reads another process's cmdline and environ, then cmdline is readable, environ is refused, and the receipt records the approximation
- **SR-007** (P2): THREAT_MODEL and the docs MUST give R-25's status per platform, base and tier, MUST state that V1 to V3 and T2 leave command lines readable, and MUST state that Cage::exec gets no PID namespace.
  - Mitigates: `threat.status-overclaim` via `mitigation.per-platform-status`
  - Given THREAT_MODEL, the crate docs and the site, when they describe R-25, then they name the closing base on macOS, T1's canary, the T2 residual and the Cage::exec limit
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: No caged child on the new macOS base or on T1 can read another
  same-user process's arguments or environment (canaries on every lane).
- **SC-002**: The base program set passes on the new base on every macOS lane.

## Assumptions

- The measured rule holds on macOS 27 (checked on the macOS 27 lane before
  the base is frozen).

## Out of Scope

- Other users' processes (already refused by the kernel).
- Making the caller's own process restricted (code-signing flags).
