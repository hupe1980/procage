# Feature Specification: A helper's command in a session of its own

**Feature Branch**: `047-exec-session` (planning directory; commits land on `main`)

**Created**: 2026-11-02

**Status**: Implemented (2026-11-02)

**Input**: A harness reports, against 0.3.1, that `cargo nextest run` fails on Linux in commands it runs through a helper that execs into the cage (an agent's terminal, MCP servers): `Cage::exec` keeps the caller's session, so its filter refuses `setpgid`. `Cage::spawn` allows it since 0.3.1.

## Context

`Cage::exec` makes the helper the command; the helper's owner ends the
run by killing the helper's process group, so `setpgid` must stay
refused there. A command that leads a session of its own can allow it,
as a spawned child does: with `setsid` refused, no descendant leaves the
session, and the owner ends the run by the session.

## Clarifications

### Session 2026-11-02

- Q: The shape? → A: `Cage::exec_session` and `exec_session_with_fds` on
  both backends, and `end_session(pid)` (the kill a run's end does) in
  `procage::linux` and `procage::macos`. `Cage::exec` is unchanged.
- Q: Who starts the session? → A: The child sequence, with `setsid`
  unless the helper leads its session already. A helper that leads a
  process group but no session cannot start one: refused before the
  process changes with the new `SpawnError::GroupLeader` (the enum is
  `non_exhaustive`); `Tty::Inherit` with `Unsupported::Setting`.
- Q: macOS? → A: The same API; Seatbelt cannot refuse `setsid`, so a
  descendant can leave the session, as with `Cage::exec`.

## User Scenarios & Testing

### User Story 1 - Test runners through a helper (Priority: P1)

**Acceptance Scenarios**:

1. **Given** a helper started as a plain child that calls `exec_session`,
   **When** a descendant calls `setpgid(0, 0)`, **Then** it succeeds; on
   Linux `setsid` still fails.
2. **Given** a descendant in a process group of its own, **When** the owner
   calls `end_session` with the helper's pid, **Then** it dies.
3. **Given** a helper started with `process_group(0)`, **When** it calls
   `exec_session`, **Then** it fails with `SpawnError::GroupLeader` and the
   process is unchanged.

## Requirements

- **FR-001**: `exec_session` MUST make the command lead its own session and
  use the spawn filter (`setpgid` allowed, `setsid` refused on Linux).
- **FR-002**: `end_session(pid)` MUST kill every live process of session
  `pid` and process group `pid`, and ignore pids 0 and 1.
- **FR-003**: A group leader without a session, and `Tty::Inherit`, MUST be
  refused before the process changes.
- **FR-004**: The exec guide, the exec rustdoc, the lowering table and the
  changelog MUST describe it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): A command run with exec_session MUST lead its own session; on Linux its descendants MUST be able to start process groups and MUST NOT start sessions.
  - Mitigates: `threat.grouped-descendant-outlives-exec`, `threat.session-escape-exec` via `mitigation.exec-session-boundary`
  - Given a plain-child helper calling exec_session, when a descendant calls setpgid(0, 0) and setsid, then setpgid succeeds; on Linux setsid fails
- **SR-002** (P1): end_session of the helper pid MUST kill every live process of its session, including one in a process group of its own.
  - Mitigates: `threat.grouped-descendant-outlives-exec`, `threat.session-escape-exec` via `mitigation.exec-session-boundary`
  - Given a descendant in its own process group, when the owner calls end_session with the helper pid, then it dies within two seconds on macOS, T1 and T2
- **SR-003** (P1): exec_session in a process group leader that leads no session MUST fail before the process changes; end_session MUST ignore pids 0 and 1.
  - Mitigates: `threat.half-applied-exec`, `threat.wrong-session-killed` via `mitigation.checked-first`
  - Given a helper started with process_group(0), when it calls exec_session, then it fails with SpawnError::GroupLeader and the command never runs
<!-- threatspec:end -->
