# Feature Specification: Process groups under `Lifetime::Run` on Linux

**Feature Branch**: `046-process-groups` (planning directory; commits land on `main`)

**Created**: 2026-11-02

**Status**: Implemented (2026-11-02)

**Input**: A harness that runs every command of a coding agent in a cage reports, against 0.3.0, that cargo-nextest cannot run a test on Linux: it starts each test in a process group of its own, and `Lifetime::Run` refuses `setpgid` with `EPERM`. Job-control shells and other runners that group their children fail the same way. macOS is unaffected.

## Context

`Lifetime::Run` keeps every descendant in the run. On Linux it refuses
`setsid` and `setpgid`, so every process stays in the child's process
group, which ending the run kills. A process group, though, cannot leave
its session: `setpgid` moves a process only within its own session. With
the default `Tty::None` the child calls `setsid` before the cage closes,
so it leads a session whose id is its pid; with `setsid` refused, no
descendant can leave that session. Ending the run by session reaches
every process, whatever group it made.

## Clarifications

### Session 2026-11-02

- Q: Which mechanism finds the run? → A: The child's session, on both
  tiers. A PID namespace (T1 only, needs an init) or a cgroup (needs a
  writable delegated hierarchy) is not needed for what a session gives.
- Q: When does `setpgid` stay refused? → A: With `Tty::Inherit` (the child
  is in the caller's session, so its group is the boundary) and for
  `Cage::exec` (the command keeps the caller's session and group).
- Q: How is the session found? → A: `/proc/<pid>/stat`'s session field,
  scanned when the run ends, repeated until no live member is new (members
  forked during the kill). While a member lives, the session's id cannot
  belong to another process; after the leader is reaped and every member
  is gone, the window is the one `killpg` already has.

## User Scenarios & Testing

### User Story 1 - Test runners group their children (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a forking policy with the defaults on T1 or T2, **When** a
   process of the run calls `setpgid(0, 0)`, **Then** it succeeds, and
   `setsid` still fails with `EPERM`.
2. **Given** a descendant in a process group of its own whose parent exited
   (outside the child's group and tree), **When** the run ends, **Then** it
   dies.

### User Story 2 - The caller's session stays the boundary (Priority: P1)

**Acceptance Scenarios**:

1. **Given** `Tty::Inherit`, **When** the policy is lowered, **Then**
   `setpgid` is denied.
2. **Given** `Cage::exec`, **When** a descendant of the command calls
   `setpgid(0, 0)`, **Then** it fails, and so does `setsid`.

## Requirements

- **FR-001**: Under `Lifetime::Run` the Linux lowering MUST deny `setsid`,
  and `setpgid` only with `Tty::Inherit`.
- **FR-002**: `Cage::exec` MUST refuse `setpgid` under `Lifetime::Run`.
- **FR-003**: Ending a run MUST kill every live process in the child's
  session, besides its group and the descendants found from it.
- **FR-004**: The lowering table, the `Lifetime` docs, the lifetime guide,
  the violations page, the threat model (R-23) and the changelog MUST
  describe it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Under Lifetime::Run no process of the run MUST be able to start a session; starting a process group MUST work with the defaults.
  - Mitigates: `threat.fork-during-kill`, `threat.group-outlives-run`, `threat.session-escape` via `mitigation.session-boundary`
  - Given a forking default policy on T1 and T2, when a process of the run calls setsid and setpgid(0, 0), then setsid fails with EPERM and setpgid succeeds
  - Given the lowering with fork and Lifetime::Run, when it is lowered with Tty::None and Tty::Inherit, then setsid is denied in both, setpgid only with Tty::Inherit
- **SR-002** (P1): Ending a run MUST kill every live process of the child session, including those in other process groups and outside the child tree.
  - Mitigates: `threat.fork-during-kill`, `threat.group-outlives-run`, `threat.session-escape` via `mitigation.session-boundary`
  - Given a descendant in a process group of its own whose parent exited, when the run ends, then it dies within two seconds on T1 and T2
- **SR-003** (P1): With the caller session (Tty::Inherit, Cage::exec) setpgid MUST stay refused under Lifetime::Run.
  - Mitigates: `threat.caller-session` via `mitigation.group-boundary-kept`
  - Given Cage::exec of a shell, when a descendant calls setsid and setpgid(0, 0), then both fail
<!-- threatspec:end -->

## Success Criteria

- **SC-001**: A program that starts a process group (as cargo-nextest does)
  runs in a default forking cage on Linux, and its processes die with the
  run.
