# Feature Specification: Unix sockets under trees, and hiding on Linux T2

**Feature Branch**: `028-linux-gaps` (planning directory; commits land on `main`)

**Created**: 2026-10-31

**Status**: Draft

**Input**: User description: "028-linux-gaps: Linux: `Hide` on T2 by enumerating readable siblings as a consumer harness's builtin engine does; keep `AF_UNIX` while denying IP below Landlock ABI 9; a portable network setting for Unix sockets under trees (macOS by subpath filters on the network operations, moved from 026). Research it; we want a great developer experience."

## Context

Two gaps a consumer harness found in real use remain on Linux:

- **Unix sockets (blocker)**: test servers and databases talk over Unix sockets in
  the workspace. procage can express only a list of socket files to
  connect to (`Network::UnixSockets`), which is a network setting of its
  own (so it cannot be combined with loopback), cannot bind, and on Linux
  below Landlock ABI 9 is refused: with no network, Linux denies `socket()`
  for every family, Unix sockets included.
- **Hiding on T2 (major)**: on tier T2 (no user namespaces, the default on Ubuntu
  23.10 and later), a hidden path inside a readable tree is refused, so
  "read everything except credentials" cannot run there.

Research for this spec (Docker Desktop Linux 7.0, Landlock ABI 8; procage
at `95a407d`):

- The Linux backend uses Landlock up to ABI 8; ABI 9's Unix-socket right
  is not used.
- Below ABI 9, nothing in Landlock or seccomp restricts which pathname
  socket a process connects to. A new network namespace isolates abstract
  sockets but **not** pathname sockets (measured: a socket bound outside was
  still reachable from a fresh user + network namespace).
- `/proc/net/unix` lists every listening socket of the network namespace by
  path. Binding `/dev/null` over a socket file in a private mount namespace
  makes `connect` fail with `ECONNREFUSED` (measured).
- Landlock cannot deny inside a tree it allows, but a tree can be granted
  piecewise: every entry along the way except the hidden one. Entries added
  later along the way are then *not* granted (a safe over-restriction); the
  directories along the way cannot be listed; and `stat` of the hidden path
  still works, because Landlock does not control metadata. Inside a
  *writable* tree this does not work: creating entries in a directory can
  only be granted together with creating them in every directory below it,
  including the hidden one.

## Clarifications

### Session 2026-10-31

- Q: What is the portable setting for Unix sockets? → A: A new field
  `Policy.ipc.unix_sockets: Vec<AbsPath>`: the child may create Unix
  sockets and bind, listen on and connect to pathname sockets at or under
  these paths, whatever the network setting. It replaces
  `Network::UnixSockets` (removed before the freeze: one concept, not two).
  Binding also needs write access to the directory, as for any file.
- Q: How is it enforced on Linux below ABI 9? → A: Tier T1: `socket()` is
  allowed for `AF_UNIX` only (when the network is otherwise off), abstract
  sockets stay inside the cage's network namespace, and every listening
  socket outside the paths that exists at spawn (from `/proc/net/unix`) is
  masked. Sockets bound later outside the paths, or bound in another network
  namespace, stay reachable: an approximation the caller accepts by name.
  Tier T2: refused (no masks without a mount namespace).
- Q: What does T2 gain for hiding? → A: A hidden path inside a tree that no
  write rule reaches is enforced by granting the tree piecewise, as listed
  at spawn: an approximation (directories on the way cannot be listed,
  later entries on the way are denied, metadata stays visible). The secrets
  class on T2 gets the same treatment when only read rules reach it. A
  hidden or protected path inside a writable tree stays refused on T2.
- Q: How does a caller accept these approximations? → A: The 026 option
  `accept_spawn_masks()` becomes `accept_spawn_snapshot()`: it accepts every
  approximation that depends on the file system as procage sees it at spawn
  (the data-driven classes, hiding on T2, Unix-socket masks), and nothing
  else. Each accepted one stays listed in the plan's degradations.
- Q: What about the consumer harness? → A: Its Unix-socket workaround (a raw Seatbelt
  layer) becomes `ipc.unix_sockets`, and its Linux T1 runs gain the
  workspace socket. On T2 it still falls back, because its workspace is
  writable and contains read-only `.git` and hidden secrets (documented).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Test servers on Unix sockets in the workspace (Priority: P1)

A caged test suite starts a server that listens on a Unix socket in the
workspace and connects to it. A socket outside the workspace (a daemon's)
stays unreachable. This works with no network, and together with loopback.

**Why this priority**: The consumer harness's last blocker.

**Independent Test**: With `ipc.unix_sockets = [workspace]` and no network,
a caged child binds and connects to a socket in the workspace; connecting
to a socket outside fails; opening a TCP connection fails. On macOS and
Linux T1; Linux T2 refuses the policy with a gap that names the setting.

**Acceptance Scenarios**:

1. **Given** `ipc.unix_sockets = [workspace]` and a writable workspace,
   **When** the child binds a socket there, listens and connects to it,
   **Then** both succeed.
2. **Given** a daemon socket outside the workspace, **When** the child
   connects to it, **Then** it fails.
3. **Given** no network, **When** the child opens a TCP connection,
   **Then** it fails.
4. **Given** an abstract socket of the host (Linux), **When** the child
   connects to it, **Then** it fails.
5. **Given** Linux T2, **When** the policy is prepared, **Then** it is refused
   naming `ipc-unix-sockets`; on T1 without accepting the snapshot it is
   refused naming the same construct, and accepted with it.

---

### User Story 2 - Read everything except secrets on Linux T2 (Priority: P2)

A read-only agent on stock Ubuntu (tier T2) reads the whole file system
except credentials. A hidden directory's contents stay unreadable; the rest
reads as before.

**Why this priority**: T2 is the default on current Ubuntu.

**Independent Test**: On T2, a policy reading a tree with a hidden
subdirectory, accepted with `accept_spawn_snapshot()`, reads a sibling file
and is refused the hidden file; the same policy with a write rule on the
tree is refused at preparation.

**Acceptance Scenarios**:

1. **Given** T2, read on a tree and hide on a subdirectory, **When** the
   child reads a file next to the hidden directory and one inside it,
   **Then** the first succeeds and the second fails.
2. **Given** the same policy, **When** an entry is created on the way to the
   hidden path after the spawn, **Then** the child cannot read it.
3. **Given** T2 and a write rule on the tree, **When** the policy is
   prepared, **Then** it is refused naming `fs-hide`.
4. **Given** T2, read on `/` and the secrets class, **When** the child reads
   a key in a home's `.ssh`, **Then** it fails; reading `/etc/hostname`
   succeeds.
5. **Given** a write grant bound to a directory containing a hidden path on
   T2, **When** spawning, **Then** the spawn fails with an error naming the
   grant and the hidden path.

---

### User Story 3 - One option, clear errors (Priority: P3)

A developer who hits a snapshot approximation gets an error that names the
construct and the option; one option accepts all of them.

**Why this priority**: DX for every Linux caller.

**Independent Test**: The refusal message names the construct and
`accept_spawn_snapshot`; with the option the plan's degradations list each
accepted construct with a note.

**Acceptance Scenarios**:

1. **Given** a snapshot approximation, **When** lowering refuses it,
   **Then** the error names the construct and points to
   `LowerOptions::accept_spawn_snapshot`.
2. **Given** `accept_spawn_snapshot()`, **When** a policy also contains a
   glob rule on Linux, **Then** that rule is still refused.

### Edge Cases

- A listening socket outside the paths lives inside a hidden directory: the
  directory's mask already covers it; no second mount.
- A socket path in `/proc/net/unix` is relative, deleted or unreachable
  (permissions): skipped; the child cannot reach it by that path either.
- Many listening sockets (systemd hosts): one mask each; the spawn stays
  within the walk limit's spirit (the list is bounded by the kernel's
  listing, read once per spawn).
- A sibling on the way to a hidden path is a symbolic link: it is not
  granted (the link could lead into the hidden path); reaching its target
  needs a rule of its own.
- The hidden path does not exist at spawn: nothing to hide on the way; the
  tree is granted piecewise down to the deepest existing ancestor.
- `ipc.unix_sockets` together with `Network::All`: everything is reachable
  anyway; no masks.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy MUST have `ipc.unix_sockets`, a list of paths;
  `Network::UnixSockets` MUST be removed. Older documents without the field
  MUST parse.
- **FR-002**: On macOS, `ipc.unix_sockets` MUST allow creating sockets and
  binding, accepting and connecting at or under the paths, and nothing
  else beyond the network setting; a hidden path below one of them MUST
  stay unreachable.
- **FR-003**: On Linux with the network otherwise off, `ipc.unix_sockets`
  MUST allow `socket()` for `AF_UNIX` only. On T1 below ABI 9 every
  listening pathname socket outside the paths that exists at spawn MUST be
  masked, and abstract sockets MUST stay inside the cage's network
  namespace; the outcome MUST be an approximation. On T2 below ABI 9 it MUST
  be refused. At ABI 9 the lowering MUST use Landlock's Unix-socket right.
- **FR-004**: On T2, a hidden path that no write rule reaches MUST be
  enforced by granting the trees around it piecewise at spawn, skipping
  symbolic links; it MUST be an approximation. A hidden or protected path
  that a write rule reaches MUST stay refused on T2.
- **FR-005**: On T2, the secrets class reached only by read rules MUST be
  handled like FR-004 for its paths that exist at spawn; reached by a write
  rule, it MUST stay refused.
- **FR-006**: A write grant bound at spawn to a path that contains a hidden
  path on T2 MUST fail the spawn with a typed error naming both.
- **FR-007**: `LowerOptions::accept_spawn_masks` MUST be renamed
  `accept_spawn_snapshot` and accept exactly the data-driven classes,
  `fs-hide` and `ipc-unix-sockets`.
- **FR-008**: Lowering errors for a snapshot approximation MUST name the
  construct and the option.
- **FR-009**: The lowering table, the crate docs, the threat model (R-09) and
  the answer to the consumer MUST describe the new behaviour, including what
  stays refused on T2.
- **FR-010**: The escape suite MUST keep R-09 mitigated: daemons stay
  unreachable when `ipc.unix_sockets` does not cover them.

### Key Entities

- **Unix-socket paths** (`ipc.unix_sockets`).
- **Spawn snapshot**: what procage reads from the file system at spawn to
  enforce an approximation (class paths, siblings, listening sockets).

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): With ipc.unix_sockets covering the workspace and no network, a caged child MUST bind and connect to a socket in the workspace and MUST NOT connect to a listening socket outside it, nor open a TCP connection, on macOS and Linux T1.
  - Mitigates: `threat.abstract-socket-reached`, `threat.daemon-socket-reached` via `mitigation.socket-masks`, `mitigation.macos-path-filters`
  - Given a daemon socket outside and ipc.unix_sockets on the workspace, when the child binds and connects inside, connects to the daemon and opens TCP, then inside works, the daemon and TCP fail
- **SR-002** (P1): On Linux the child MUST NOT reach a host abstract socket under ipc.unix_sockets, and T2 below ABI 9 MUST refuse the setting.
  - Mitigates: `threat.abstract-socket-reached`, `threat.daemon-socket-reached` via `mitigation.socket-masks`
  - Given a host abstract socket and T1 with ipc.unix_sockets, when the child connects to it, then it fails
  - Given T2, when the policy is prepared, then it is refused naming ipc-unix-sockets
- **SR-003** (P1): On T2 a hidden path's contents MUST stay unreadable with piecewise grants - also through a symbolic link sibling - and a write rule or write grant around a hidden path MUST be refused.
  - Mitigates: `threat.sibling-leak` via `mitigation.safe-siblings`
  - Given T2, read on a tree, hide on a subdirectory and a symlink sibling pointing into it, when the child reads the hidden file directly and through the link, then both fail and a sibling file reads
  - Given a write rule on the tree, or a write grant bound around the hidden path, when preparing or spawning, then it is refused naming the construct or the grant and the hidden path
- **SR-004** (P2): accept_spawn_snapshot MUST accept exactly the data-driven classes, fs-hide and ipc-unix-sockets; without it these approximations MUST be refused with an error naming the construct and the option.
  - Mitigates: `threat.silent-approximation` via `mitigation.named-acceptance`
  - Given each snapshot approximation, when lowered without and with the option, then refused naming the option, then accepted and listed in degradations
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The Unix-socket scenarios pass on macOS and Linux T1; T2
  refuses with the named construct.
- **SC-002**: The T2 hiding scenarios pass in the T2 container.
- **SC-003**: R-09's canaries pass unchanged on all three.
- **SC-004**: `just ci` passes.

## Assumptions

- Landlock ABI 9 is not available on the test kernel; the ABI-9 lowering is
  checked by lowering tests only, and the backend keeps using ABI 8.
- The consumer harness adopts `ipc.unix_sockets` later, in its own code.
