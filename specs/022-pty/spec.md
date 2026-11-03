# Feature Specification: A fresh pseudo-terminal for interactive runs

**Feature Branch**: `022-pty` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

**Input**: Interactive tools (shells, REPLs, editors, test runners with colour and progress) need a terminal. procage 0.1.0 offers no terminal (`Tty::None`, the default) or the caller's own (`Tty::Inherit`), which lets the child inject keystrokes into the caller's terminal (measured on macOS 26) and is denied as terminal injection. `Tty::NewPty` exists in the policy but is refused.

## Context

A fresh pseudo-terminal pair, created by the parent, gives the child a
controlling terminal of its own: the caller reads and writes the controller
side, the child gets the other end as stdio and controlling terminal. The
child can still push input into *its own* terminal — harmless, since only the
caller reads that controller side and nothing runs it as a shell command.

## Clarifications

### Session 2026-11-01

- Q: Who owns the controller side? → A: The caller, returned with the child
  handle; procage does not render or interpret output.
- Q: Window size and signals? → A: The caller sets the size; procage forwards
  nothing on its own.

### Session 2026-11-03

Decided by the project's scope rule (best-in-class, no overengineering).

- Q: In what form does the caller get the controller side? → A: A `Pty` taken
  from the child handle (sync and async): it reads and writes, names the
  terminal device, and sets the window size. No other terminal API.
- Q: What window size does a new terminal start with? → A: 80 columns by 24
  rows, set before the child starts, so no program reads an empty size; the
  caller resizes at any time.
- Q: What happens to stdin, stdout and stderr the caller configured on the
  command? → A: The terminal replaces all three; other declared descriptors
  are handed over as before.
- Q: Can `Cage::exec` or `Cage::exec_session` use a new terminal? → A: No,
  both refuse `Tty::NewPty` with a typed error: no caller remains to hold
  the controller side.
- Q: Does the child's access to its terminal depend on a base profile? → A:
  No. `Tty::NewPty` grants the child its own terminal device and `/dev/tty`
  (read, write, terminal ioctls) under every policy; pushing input
  (`TIOCSTI`) stays denied by the terminal-injection class, waivable only by
  name, and every other terminal stays out of reach.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run an interactive program caged (Priority: P1)

**Independent Test**: Spawn a shell with `Tty::NewPty` on both backends,
write a command to the controller side, read its output, check `isatty` in
the child, and close.

**Acceptance Scenarios**:

1. **Given** `Tty::NewPty`, **When** the child starts, **Then** stdin, stdout
   and stderr are the terminal and it is the controlling terminal.
2. **Given** the child pushing input into its terminal, **Then** it reaches
   only the controller side the caller holds; the caller's own terminal is
   untouched (the terminal-injection canary passes).
3. **Given** the run ending, **Then** the terminal is closed and every process
   killed.

### Edge Cases

- Programs that open `/dev/tty`: they get their own terminal.
- A child opening another terminal device (the caller's, or another run's):
  denied.
- `Cage::exec` or `Cage::exec_session` with `Tty::NewPty`: refused.
- The caller's stdio settings on the command: replaced by the terminal.
- Job control inside the terminal (a shell's background jobs): stays inside
  the run's lifetime rules.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `Tty::NewPty` MUST create a pseudo-terminal pair in the parent
  and make the other end the child's stdio and controlling terminal.
- **FR-002**: The policy MUST grant the child access to exactly its own
  terminal device and the terminal operations programs need, and MUST keep
  terminal injection into any other terminal denied.
- **FR-003**: The controller side MUST be returned to the caller as a `Pty`
  taken from the child handle (sync and async) that reads, writes, names the
  device and sets the window size; a new terminal starts at 80 by 24.
- **FR-004**: The child sequence MUST stay system calls only.
- **FR-005**: `Cage::exec` and `Cage::exec_session` MUST refuse
  `Tty::NewPty` with a typed error.
- **FR-006**: The terminal grant MUST NOT depend on the base profile, and
  MUST NOT reach any terminal but the child's own.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): With Tty::NewPty the child MUST reach only its own terminal device and /dev/tty, under every base version including none; opening any other terminal device MUST fail.
  - Mitigates: `threat.other-terminal` via `mitigation.exact-device`
  - Given a caged child with Tty::NewPty and a second terminal the test opened, when the child opens the second terminal's device for reading and writing, then both opens fail
  - Given a policy without a base profile and Tty::NewPty, when the child reads and writes its terminal and sets its attributes, then all succeed
- **SR-002** (P2): With Tty::NewPty, TIOCSTI on the child's own terminal MUST fail unless the terminal-injection class is waived by name.
  - Mitigates: `threat.sti-own` via `mitigation.sti-denied`
  - Given a caged child with Tty::NewPty, when it pushes a byte into its own terminal, then the call fails with EPERM
  - Given the same policy with the terminal-injection class waived, when it pushes a byte, then the byte reaches only the controller side
- **SR-003** (P1): The controller side and the parent's copy of the terminal end MUST NOT be open in any caged child; the parent MUST hold no copy of the terminal end after the spawn.
  - Mitigates: `threat.descriptor-leak` via `mitigation.cloexec-handover`
  - Given two runs with Tty::NewPty spawned concurrently from different threads, when each child lists its open descriptors, then none is either run's controller or the other run's terminal
  - Given a run whose child exited, when the caller reads the controller side, then the read ends (EOF or EIO) instead of blocking
- **SR-004** (P2): The child MUST acquire its controlling terminal with system calls only (setsid, ioctl TIOCSCTTY), and spawns with Tty::NewPty from a multithreaded parent MUST succeed.
  - Mitigates: `threat.child-unsafe` via `mitigation.syscall-session`
  - Given a parent with several threads allocating and locking, when it spawns many children with Tty::NewPty, then every child starts with its terminal as controlling terminal
- **SR-005** (P1): When a run with Tty::NewPty ends, every process of the run, including background jobs a shell started in the terminal, MUST be dead.
  - Mitigates: `threat.outlive` via `mitigation.run-end`
  - Given a shell in a new terminal that started a background job, when the run ends, then the shell and the job are dead
- **SR-006** (P1): Cage::exec and Cage::exec_session MUST refuse Tty::NewPty with a typed error before anything is changed.
  - Mitigates: `threat.exec-fallback` via `mitigation.exec-refuses`
  - Given a cage with Tty::NewPty, when exec or exec_session is called, then it returns the unsupported-setting error and the process is unchanged
- **SR-007** (P3): The Pty documentation MUST state that the controller side carries the cage's untrusted bytes, including escape sequences, and that procage does not filter them.
  - Mitigates: `threat.escape-sequences` via `mitigation.untrusted-output`
  - Given the rustdoc of Pty, when a reader looks for how to treat output, then it says the bytes are untrusted and unfiltered
- **SR-008** (P2): An interactive shell, a REPL and a full-screen program MUST run caged through Tty::NewPty in tests on every macOS and Linux lane, and the docs MUST claim no more than those tests show.
  - Mitigates: `threat.claim-overstates` via `mitigation.lane-tests`
  - Given each CI lane, when the terminal tests run, then the shell answers a command, the REPL evaluates an expression and the full-screen program draws and quits
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: An interactive shell, a REPL and a full-screen program run caged
  through the terminal on every lane.
- **SC-002**: The terminal-injection canaries pass with `Tty::NewPty`.

## Assumptions

- Terminal device paths are known only at spawn; they are granted per spawn
  like other per-spawn paths.

## Out of Scope

- Terminal emulation or recording.
