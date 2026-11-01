# Feature Specification: A fresh pseudo-terminal for interactive runs

**Feature Branch**: `022-pty` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

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
- Job control inside the terminal (a shell's background jobs): stays inside
  the run's lifetime rules.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `Tty::NewPty` MUST create a pseudo-terminal pair in the parent
  and make the other end the child's stdio and controlling terminal.
- **FR-002**: The policy MUST grant the child access to exactly its own
  terminal device and the terminal operations programs need, and MUST keep
  terminal injection into any other terminal denied.
- **FR-003**: The controller side MUST be returned to the caller.
- **FR-004**: The child sequence MUST stay system calls only.

## Success Criteria *(mandatory)*

- **SC-001**: An interactive shell, a REPL and a full-screen program run caged
  through the terminal on every lane.
- **SC-002**: The terminal-injection canaries pass with `Tty::NewPty`.

## Assumptions

- Terminal device paths are known only at spawn; they are granted per spawn
  like other per-spawn paths.

## Out of Scope

- Terminal emulation or recording.
