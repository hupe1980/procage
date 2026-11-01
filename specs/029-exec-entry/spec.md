# Feature Specification: Exec entry — a helper becomes the caged command

**Feature Branch**: `029-exec-entry` (planning directory; commits land on `main`)

**Created**: 2026-10-31

**Status**: Draft

**Input**: User description: "029-exec-entry: Self-confine-then-exec entry for helper processes (a blocker for a consumer harness): apply the cage to the calling (single-threaded) process and `exec` the target, so a helper *becomes* the command and the caller's process-group and kill semantics hold; both systems, with the lifetime trade-offs of feature 024 stated. Research it; we want a great developer experience."

## Context

Programs that embed procage often do not spawn the caged command
themselves. An agent harness hands an argument vector to other code: an
MCP client library, a terminal emulator, `tokio::process::Command` with
`kill_on_drop`. That code owns the process: it reads its pipes, waits for
it, and kills it (by pid, or by killing its process group).

Today procage can only spawn a cage as a child of the calling process,
with a handle that owns its lifetime. A harness therefore needs a helper
program between the two: the outside code starts the helper, and the helper
spawns the cage. A consumer harness built exactly that and hit the
limit of the design: when the outside code kills the helper with SIGKILL,
the cage, a separate process in its own session, keeps running.

The consumer's previous sandbox avoided this because its helper *became* the
command: it confined itself and then executed the target, so the pid, the
pipes, the exit status and the process group the outside code holds are
the command's. procage needs the same entry point.

Research for this spec (procage at `6d05458`, std 1.99 source):

- std's `CommandExt::exec` runs a command's `pre_exec` hooks in the
  calling process, after setting up stdio, the working directory and the
  process group, and then calls `execvp`, without forking.
- procage's child sequence on both systems is self-contained: on macOS
  (session, limits, descriptors, apply, verify, grant tokens) and on Linux
  (session, parent-death signal, namespaces with self-written id maps,
  mounts, capabilities, limits, descriptors, no-new-privs, Landlock,
  seccomp, verify), no step needs a parent process. The same sequence can
  run in the calling process before `exec`.
- On Linux tier T1, `unshare(CLONE_NEWUSER)` fails with `EINVAL` in a
  multithreaded process. Landlock and seccomp apply to the calling thread,
  which is the one that executes, so tier T2 works from a multithreaded
  caller.

## Clarifications

### Session 2026-10-31

- Q: What is the shape of the entry point? → A: `Cage::exec(&self, &mut
  Command, &Grants) -> SpawnError` and `Cage::exec_with_fds`, on both
  systems with the same signature (so `procage::native` covers it). Like
  std's `CommandExt::exec`, it returns only on failure; on success the
  calling process is the caged command.
- Q: What happens to the session and process group? → A: They are kept. The
  command stays in the caller's process group, so a kill of that group, or
  of the pid, reaches it. The policy's `Tty` still decides which terminal
  devices the cage may open; `exec` does not start a session.
- Q: What about descendants of the command (lifetime, feature 024)? → A: The
  outside code owns the lifetime; there is no handle. On Linux, under the
  default `Lifetime::Run`, descendants cannot leave the process group, so a
  kill of the group reaches all of them, and the command dies with its
  parent (parent-death signal). On macOS, descendants that start their own
  session are not found by a group kill; that limit is documented, and
  callers that need it use `Cage::spawn`.
- Q: What can fail after the process has changed? → A: Every check that can
  be made beforehand is made beforehand, so a refusal leaves the process
  untouched: the nesting check, the probe, grant bindings, the environment
  decision, a program that cannot be found, the `tmpdir` grant (refused:
  nothing would remove the directory), and on Linux T1 a multithreaded
  caller (refused with the thread count and what to do). A failure after the
  first change (a step, or `execvp` itself) leaves the process partly
  confined; the docs tell the caller to exit, and the error says which step
  failed.
- Q: How does a developer learn the pattern? → A: A runnable example, a
  "Helpers" section in the crate docs that shows both the helper and the
  outside side, and error messages that name the fix.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A helper becomes the caged command (Priority: P1)

A harness starts `my-helper -- server --stdio` through code it does not
control. The helper builds a cage and calls `Cage::exec`. The server runs
caged, with the helper's pid, stdio and process group; its exit status is
what the outside code sees.

**Why this priority**: This is the blocker for the consumer harness
replacing its own sandbox with procage.

**Independent Test**: A helper process calls `exec` for a shell command
that prints its pid, writes inside and outside a granted directory, and
exits with a code. The outside code sees the helper's pid printed, the
write inside succeed and the one outside fail, and the exit code.

**Acceptance Scenarios**:

1. **Given** a helper that execs a command in a cage, **When** the command
   prints its pid, **Then** it is the pid the outside code started.
2. **Given** the caged command, **When** it writes inside the granted
   directory and outside it, **Then** the first succeeds and the second
   fails.
3. **Given** the caged command exits with code 7, **When** the outside code
   waits for the helper, **Then** it gets 7.
4. **Given** the helper's environment holds a secret and the command calls
   `env_clear`, **When** the command prints its environment, **Then** the
   secret is absent.

---

### User Story 2 - Killing the helper kills the command and its descendants (Priority: P1)

The outside code started the helper in its own process group and kills it
with SIGKILL, or kills the group.

**Why this priority**: The lifetime gap the consumer harness found.

**Independent Test**: The caged command starts a background sleeper; the
outside code SIGKILLs the helper's process group; command and sleeper are
gone.

**Acceptance Scenarios**:

1. **Given** a caged command started through a helper, **When** the outside
   code SIGKILLs the helper's pid, **Then** the command is gone (it is the
   same process).
2. **Given** the command started a background process, **When** the outside
   code kills the helper's process group, **Then** the background process is
   gone, on macOS and Linux.
3. **Given** Linux and the default lifetime, **When** a descendant tries to
   start its own session, **Then** it fails, and the group kill reaches it.

---

### User Story 3 - Mistakes are refused before anything changes (Priority: P2)

A developer misuses `exec`: a policy with the `tmpdir` grant, a program
that does not exist, or (on Linux T1) a call after the program started
threads. `exec` returns an error that says what to do, and the helper
process is unchanged.

**Why this priority**: The process cannot be restored after a partial
confinement; good errors before the first change are most of the DX.

**Independent Test**: Each misuse returns its error; afterwards the helper
can still write outside the policy (it is unconfined) and keeps running.

**Acceptance Scenarios**:

1. **Given** a policy with the `tmpdir` grant, **When** `exec` is called,
   **Then** it returns an error naming the grant and `Cage::spawn`, and the
   process is unconfined.
2. **Given** a program name that cannot be found, **When** `exec` is called,
   **Then** it returns a not-found error before confining.
3. **Given** Linux T1 and a caller with two threads, **When** `exec` is
   called, **Then** it returns an error naming the thread count and the two
   fixes (call it before starting threads, or use tier T2); with tier T2 the
   same multithreaded caller execs successfully.

### Edge Cases

- The command sets its own process group (`Command::process_group`): std
  applies it before procage's steps; procage does not change it.
- The command's stdio is piped: std creates the pipes in the calling
  process; the outside code usually leaves stdio inherited.
- `exec` succeeds in confining, but `execvp` fails (the policy does not
  allow executing the program): the error is returned and the process is
  confined; the docs say to exit.
- The policy allows no forking: the command cannot start descendants.
- macOS: the run-marker block of a forking policy still needs its
  parameters bound; the marker is never searched (no handle).
- Calling `exec` from inside another sandbox (macOS): refused as for spawn.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Both backends MUST offer `Cage::exec(&self, command, grants)
  -> SpawnError` and `Cage::exec_with_fds(&self, command, grants, fds) ->
  SpawnError` with the same signatures; on success they do not return and
  the calling process runs the command in the cage.
- **FR-002**: `exec` MUST apply the same confinement as `spawn` for the same
  policy and grants (file system, network, process, IPC, environment,
  limits, descriptors, hard-deny tier, lifetime lock on Linux), with the
  same environment rules (including `env_clear`, spec 026).
- **FR-003**: `exec` MUST NOT start a session or a process group; the command
  keeps the caller's pid, process group and session.
- **FR-004**: `exec` MUST make every check it can before changing the
  process, and return without changing it when one fails: nesting, probe,
  grant bindings, environment decision, program lookup, the `tmpdir`
  grant (refused), and on Linux T1 a multithreaded caller (refused).
- **FR-005**: Each refusal in FR-004 MUST be a typed error whose message
  names the cause and the fix.
- **FR-006**: On Linux, the command MUST receive the parent-death signal
  relative to the helper's parent.
- **FR-007**: The docs MUST state the lifetime of an exec'd command on each
  system: the outside code owns it; Linux keeps descendants in the process
  group under `Lifetime::Run`; macOS does not find descendants that start
  their own session.
- **FR-008**: A runnable example MUST show a complete helper, and the crate
  docs MUST show the outside side (start in its own process group, kill the
  group).
- **FR-009**: Child-side code MUST stay unchanged in nature (the existing
  step sequence, syscalls only); the session step gains a "keep" mode.
- **FR-010**: Tests MUST run the helper as a single-threaded process (as
  real helpers are) on macOS and Linux T1 and T2.

### Key Entities

- **Exec entry**: `Cage::exec` / `Cage::exec_with_fds`.
- **Session mode**: new session, own group, or keep (exec only).

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): A command run with exec MUST be confined like a spawned one for the same policy - writes outside the grant and the environment rules are enforced - on macOS and Linux T1 and T2.
  - Mitigates: `threat.exec-weaker-than-spawn` via `mitigation.shared-sequence`
  - Given a helper that execs a shell in a cage with a write grant, when the shell writes inside and outside the grant, then the inside write succeeds and the outside one fails
  - Given a secret in the helper's environment and env_clear on the command, when the command prints its environment, then the secret is absent
- **SR-002** (P1): Each refusal that can be known before the first change (tmpdir grant, missing program, multithreaded caller on Linux T1, environment decision) MUST return an error and leave the helper unconfined.
  - Mitigates: `threat.partial-confinement` via `mitigation.checks-first`
  - Given each misuse, when exec is called, then it returns its typed error and an outside write by the helper still succeeds
- **SR-003** (P1): The exec'd command MUST keep the helper's pid and process group, and a kill of that group MUST end the command and a background descendant on macOS and Linux; on Linux a descendant MUST NOT be able to start its own session.
  - Mitigates: `threat.helper-outlived` via `mitigation.same-process`
  - Given a helper started in its own process group whose command starts a background sleeper, when the outside code kills the group, then the command and the sleeper are gone
  - Given the exec'd command, when it prints its pid, then the pid is the helper's
- **SR-004** (P2): The docs MUST state the lifetime of an exec'd command on each system, including that macOS does not reach a descendant in its own session.
  - Mitigates: `threat.lifetime-overclaimed` via `mitigation.honest-lifetime-docs`
  - Given the crate docs and the threat model, when read for exec, then both state the per-system lifetime and the macOS limit
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: All acceptance scenarios pass on macOS and Linux T1 and T2.
- **SC-002**: A helper written from the example is at most 15 lines of
  procage-specific code.
- **SC-003**: Every refusal in FR-004 leaves the helper unconfined (100% of
  the refusal tests check an outside write afterwards).
- **SC-004**: `just ci` passes, including the example.

## Assumptions

- std's `CommandExt::exec` keeps running `pre_exec` hooks in the calling
  process (documented behaviour of `exec`).
- The consumer harness adopts the entry in its own code later; this feature
  does not change the consumer.
