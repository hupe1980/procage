# Feature Specification: Process hygiene for caged children

**Feature Branch**: `005-hygiene`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "005-hygiene: fds, env allowlist, `setsid`/tty, process group / kill-on-drop, rlimits — shared by both backends; canaries R-21…R-26."

## Context

Feature 004 cages a child on macOS, and already applies part of the
policy's hygiene settings: the environment, resource limits, and a new
session without a controlling terminal. The remaining hygiene gaps are
escapes that bypass a correct sandbox profile:

- **Inherited file descriptors (R-21).** A descriptor opened by the caller
  before the spawn reads a file the profile denies. This project's kernel
  facts observed it (KF-M19).
- **Outliving the run (R-23).** Descendants of the child keep running after
  the caller is done with it.
- **Secrets in the environment (R-24).** Tokens and agent sockets pass
  through when the policy passes the environment through.
- **A shared temporary directory (R-10).** Every process of the user shares
  `$TMPDIR`, so runs can read each other's files.

This feature closes these gaps for macOS. It keeps the logic that does not
depend on the OS (environment filtering, lifetime bookkeeping) in a form the
Linux backend (008) reuses. Each claim is shown by a caged child on the real
kernel.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The child gets only the descriptors it was given (Priority: P1)

A harness has open files, sockets and pipes, such as its log, its
database, or a credential file it just read. It spawns a caged child. The
child receives standard input, output and error, plus only the descriptors
the harness names for that spawn. Every other descriptor is closed when the
child's program starts, whether or not the harness marked it
close-on-exec.

**Why this priority**: An inherited descriptor bypasses every path rule. It
is the cheapest escape there is, and it was observed on this kernel.

**Independent Test**: The harness opens a file the policy denies, without
close-on-exec, and spawns a child. The child cannot use that descriptor. When
the harness names the descriptor for the spawn, the child can.

**Acceptance Scenarios**:

1. **Given** the caller holds a descriptor to a denied file without
   close-on-exec, **When** a caged child tries to read that descriptor
   number, **Then** the descriptor does not exist in the child.
2. **Given** the caller names that descriptor for the spawn, **When** the child
   reads it, **Then** it can, because the caller explicitly chose to hand it
   over.
3. **Given** a caller with thousands of open descriptors, **When** it spawns,
   **Then** every one of them except those named is closed in the child.

---

### User Story 2 - Nothing outlives the run (Priority: P1)

The harness drops its handle to a caged child, or asks it to stop. The
child and every descendant still running is killed, including descendants
that started their own session. A harness that wants the child to keep
running detaches the handle explicitly.

**Why this priority**: A child that leaves a process behind keeps acting
after the caller believes the run is over (R-23).

**Independent Test**: A caged child starts a grandchild in its process group
and another in a new session. Dropping the handle kills both.

**Acceptance Scenarios**:

1. **Given** a caged child with a sleeping grandchild, **When** the handle is
   dropped, **Then** both are gone.
2. **Given** a grandchild that called `setsid`, **When** the handle is
   dropped while the child is alive, **Then** the grandchild is gone too.
3. **Given** a detached handle, **When** it is dropped, **Then** the child keeps
   running.

---

### User Story 3 - Secrets stay out of the environment; each run has its own temp dir (Priority: P2)

A harness passes its environment through, minus a few names. Known secret
and injection variables are dropped anyway, unless the harness sets them
explicitly on the command. The spawn reports which names it dropped. A
policy that declares the grant `tmpdir` gets a fresh private temporary
directory for each spawn. `TMPDIR` points to it, the child can write
there, and the directory is removed when the run ends.

**Why this priority**: These are the R-24 and R-10 escapes. Each is common in
agent harnesses that pass the environment through.

**Independent Test**: A caller with `GITHUB_TOKEN`, `SSH_AUTH_SOCK` and
`DYLD_INSERT_LIBRARIES` set spawns with passthrough; the child sees none of
them, and the spawn lists them as dropped. Two spawns with a `tmpdir` grant
get different directories; each can write its own.

**Acceptance Scenarios**:

1. **Given** passthrough and a caller with `GITHUB_TOKEN` set, **When** the
   child prints its environment, **Then** `GITHUB_TOKEN` is absent, and the
   spawn reports it as dropped.
2. **Given** the same, with `GITHUB_TOKEN` set explicitly on the command,
   **When** the child prints its environment, **Then** it is present.
3. **Given** a policy with a `tmpdir` grant, **When** two children run, **Then**
   each has its own `TMPDIR`, can write there, and the directory is gone
   after its handle is dropped.

---

### Edge Cases

- **Std's error pipe**: the standard library reports exec failures over a
  close-on-exec pipe. Closing descriptors must not break that channel.
  Marking them close-on-exec, rather than closing them, keeps it working.
- **Naming a standard descriptor**: a caller naming descriptor 0, 1 or 2 is
  a no-op; the standard descriptors are always given.
- **An invalid descriptor**: naming a descriptor that is not open fails the
  spawn with a typed error.
- **Leader already reaped**: if the caller already waited for the child,
  dropping the handle still kills the remaining group members. A process ID
  cannot be reused while a group of that ID exists.
- **Tty::Inherit**: the child is placed in its own process group too, so
  lifetime control works. Its reads from the shared terminal then stop with
  SIGTTIN, like a background job; the docs say so.
- **Escape by double fork**: a descendant that double-forks and calls
  `setsid` is reparented away from the child. macOS gives no way to find it
  afterwards, so it escapes lifetime control. This is a documented gap of
  macOS; the Linux PID namespace (008) closes it.
- **TMPDIR cleanup**: the temporary directory is removed even if the child
  filled it, and even if the child is still running when the handle is
  dropped (it is killed first).

## Requirements *(mandatory)*

### Functional Requirements

**Descriptors**

- **FR-001**: Before the target program starts, every descriptor numbered 3
  or higher MUST be closed in the child, except the descriptors the caller
  names for that spawn.
  - The standard library's own error-reporting channel MUST keep working.
  - The sweep MUST use only system calls on data prepared in the parent.
- **FR-002**: The caller MUST be able to name descriptors to hand over for
  one spawn. A named descriptor that is not open MUST fail the spawn with a
  typed error.
- **FR-003**: The sweep MUST finish in bounded time when the caller has a
  very large descriptor limit (measured: a soft limit of 1,048,576 on the
  development Mac).

**Lifetime**

- **FR-004**: The child MUST run in its own process group (its own session
  with `Tty::None`).
- **FR-005**: Spawning MUST return a handle. Dropping the handle, or asking
  it to kill, MUST send SIGKILL to the child's process group and to every
  descendant that can be found from the child, including descendants in
  other sessions, and then reap the child. A detached handle MUST NOT kill.
- **FR-006**: The docs MUST state the double-fork escape on macOS.

**Environment**

- **FR-007**: With passthrough, procage MUST drop these names unless the
  caller set them explicitly on the command:
  - `DYLD_*`;
  - `LD_PRELOAD` and `LD_LIBRARY_PATH`;
  - `SSH_AUTH_SOCK`;
  - names ending in `_TOKEN`, `_SECRET`, `_PASSWORD` or `_API_KEY`;
  - names starting with `AWS_`.
  The handle MUST list the dropped names. An allowlist MUST be honoured as
  written, because the caller named each variable.
- **FR-008**: Environment filtering MUST be a pure function of the caller's
  environment, the policy and the explicit command variables, so the Linux
  backend can reuse it.

**Temporary directory**

- **FR-009**: When the policy declares a grant named `tmpdir`, each spawn
  MUST:
  - create a fresh directory, accessible only to the user, under the
    caller's temporary directory;
  - bind the grant to it;
  - set `TMPDIR` for the child, unless the caller set `TMPDIR` explicitly.
  Dropping the handle MUST remove the directory, after killing the child if
  it is still running.

**Evidence and docs**

- **FR-010**: Each claim MUST be shown by a caged-child test on the real
  kernel, which fails when the test process itself is sandboxed.
- **FR-011**: The docs and the threat model's release status MUST drop the
  gaps this feature closes, and keep the ones it does not close:
  - double fork on macOS;
  - pseudo-terminals;
  - Linux.
  The escape-class statuses stay as they are until the escape suite (009).

### Key Entities

- **Child handle**: the running child, its process group, its descendants,
  its private temp directory and the environment names it dropped. It kills
  on drop unless detached.
- **Descriptor list**: the descriptors handed to one spawn.
- **Environment decision**: the variables the child gets, and the names that
  were dropped.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every descriptor >= 3 not named for the spawn MUST be unusable in the child after exec, including descriptors the caller left without close-on-exec, using only system calls on parent-prepared data.
  - Mitigates: `threat.inherited-fd`, `threat.sweep-unbounded` via `mitigation.cloexec-sweep`
  - Given the caller holds a descriptor to a denied file without close-on-exec, when the caged child checks that descriptor number, then it does not exist (EBADF)
  - Given the caller holds 1,000 extra descriptors, when the child counts its descriptors >= 3, then none remain
- **SR-002** (P2): A descriptor named for a spawn MUST be usable in the child; a named descriptor that is not open MUST fail the spawn with a typed error; the sweep MUST stay fast under a very large descriptor limit.
  - Mitigates: `threat.inherited-fd`, `threat.sweep-unbounded` via `mitigation.cloexec-sweep`
  - Given a named descriptor, when the child reads it, then it succeeds
  - Given a named descriptor number that is not open, when spawn runs, then it fails with a typed error and no child runs
- **SR-003** (P1): A failed in-child step MUST still reach the parent as a typed error after the descriptor sweep.
  - Mitigates: `threat.sweep-breaks-reporting` via `mitigation.mark-not-close`
  - Given a child whose rlimit step fails after the sweep ran, when spawn returns, then it is Apply with step Rlimit, not success
- **SR-004** (P1): Dropping or killing the handle MUST kill the child's process group and every descendant reachable from the child, including descendants in a new session, and reap the child; a detached handle MUST NOT kill.
  - Mitigates: `threat.outliving-descendants`, `threat.overclaimed-hygiene` via `mitigation.group-and-tree-kill`
  - Given a caged child with a grandchild in its group and one that called setsid, when the handle is dropped, then both are gone within 1 s
  - Given a detached handle, when it is dropped, then the child keeps running
- **SR-005** (P1): Under passthrough the child MUST NOT receive DYLD_*, LD_PRELOAD, LD_LIBRARY_PATH, SSH_AUTH_SOCK, *_TOKEN, *_SECRET, *_PASSWORD, *_API_KEY or AWS_* variables unless set explicitly on the command, and the handle MUST list each dropped name.
  - Mitigates: `threat.env-secret-passthrough` via `mitigation.env-denylist`
  - Given a caller with GITHUB_TOKEN, SSH_AUTH_SOCK and DYLD_INSERT_LIBRARIES set, when a passthrough child prints its environment, then none is present and all three are reported dropped
  - Given GITHUB_TOKEN set explicitly on the command, when the child prints its environment, then it is present
- **SR-006** (P2): A policy grant named tmpdir MUST be bound per spawn to a fresh directory accessible only to the user, TMPDIR MUST point to it, and dropping the handle MUST remove it.
  - Mitigates: `threat.shared-tmpdir` via `mitigation.private-tmpdir`
  - Given a policy with a tmpdir grant, when two children run, then their TMPDIRs differ, each child writes its own, and each directory is gone after its handle is dropped
- **SR-007** (P2): Docs and the threat-model release status MUST state the macOS double-fork escape from lifetime control, keep pseudo-terminals and Linux as open gaps, and leave escape-class statuses unchanged.
  - Mitigates: `threat.outliving-descendants`, `threat.overclaimed-hygiene` via `mitigation.group-and-tree-kill`
  - Given the macos module docs, README and threat model, when they are reviewed, then the double-fork gap is stated and no closed gap is still listed as open
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 0 descriptors at 3 or above, other than the named ones, are
  usable in the child, including one deliberately opened without
  close-on-exec.
- **SC-002**: After dropping the handle, 0 of the descendants the tests start
  (one in the same group, one in a new session) are still running, within
  1 second.
- **SC-003**: 100% of the dropped-name patterns are absent from the child's
  environment under passthrough, and each is reported.
- **SC-004**: Spawn latency with a caller holding 1,000 extra descriptors and
  a 1,048,576 soft limit stays under 5 ms of median overhead over an uncaged
  spawn (recorded).
- **SC-005**: `just ci` stays green.

## Assumptions

- **macOS only for now.** The OS-independent parts (environment filter,
  handle bookkeeping) live in a shared module. The Linux backend (008) adds
  `close_range`, `PR_SET_PDEATHSIG` and the PID namespace.
- **Descriptor listing.** The child lists its open descriptors with
  `proc_pidinfo(PROC_PIDLISTFDS)` (a wrapper over the `proc_info` system
  call), into a buffer sized and allocated in the parent. If the buffer
  turns out too small, it falls back to an `fcntl` sweep up to
  `getdtablesize()`.
- **Mark, don't close.** Descriptors are marked close-on-exec rather than
  closed, so std's error pipe keeps working; `execve` closes them.
- **Pseudo-terminals are a later row** (022-pty). A pty needs a per-spawn
  device grant and terminal ioctls through the cage, which deserves its own
  design. `Tty::NewPty` stays refused.
- **No change to escape-class statuses.** The catalog has one status per
  class across both OSes. The evidence from this feature is macOS-only, and
  the escape suite (009) owns the status changes.

## Out of Scope

- Pseudo-terminals (022-pty), the `/dev` allowlist and the base profile
  (006).
- Linux hygiene (008).
- Receipts that record the dropped names (011).
