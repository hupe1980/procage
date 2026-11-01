# Feature Specification: No service handoff over Unix sockets

**Feature Branch**: `041-service-sockets` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: With the network on (`Network::All`), a caged child on Linux can connect to any pathname Unix socket. Through the user's D-Bus bus it can ask systemd to start a transient unit (`systemd-run --user`), which runs outside the sandbox; through a container engine's socket it can start a container that mounts the home directory. On macOS the same holds for container engines. A 2026 advisory in another agent sandbox (CVE-2026-47128) was exactly this; macOS already denies the equivalent Mach services.

## Context

procage's hard-deny tier keeps a child from handing work to an unsandboxed
process, under every grant: on macOS the `service-handoff` class denies Launch
Services, Apple events, the pasteboard and XPC lookups. Linux has no such
class today. With the network closed procage refuses `socket()` for every
family but `AF_UNIX`, and `ipc.unix_sockets` limits Unix sockets to named
paths; but with the network open there is no restriction, and the escape
suite's own control asserts that a daemon socket is reachable then.

Services that run code on request, as the user, outside any sandbox:

| Service | Linux | macOS |
|---|---|---|
| User service manager | `$XDG_RUNTIME_DIR/bus` (D-Bus → `systemd-run --user`, `StartTransientUnit`), `$XDG_RUNTIME_DIR/systemd/private`; abstract D-Bus addresses on older systems | launchd (already denied over Mach) |
| System bus | `/run/dbus/system_bus_socket` (polkit may allow actions for an active local session) | — |
| Container engines | `/run/docker.sock`, `/var/run/docker.sock`, `$XDG_RUNTIME_DIR/docker.sock`, `$XDG_RUNTIME_DIR/podman/podman.sock`, rootless containerd | `~/.docker/run/docker.sock`, `/var/run/docker.sock`, Colima, OrbStack, Podman machine sockets |

## Clarifications

### Session 2026-11-01

- Q: One class or two? → A: Two. The user and system buses and the service
  manager extend the existing **service-handoff** class to Linux (its meaning
  on macOS is unchanged). Container engines get a new class,
  **container-engines**, on both systems, because build tools legitimately use
  them (test containers) and must be able to waive exactly that.
- Q: Does a new hard deny change frozen presets? → A: Yes. "Frozen" means a
  preset is never *loosened* silently. A new hard-deny class tightens every
  policy, presets included; it ships in a minor version with a Security entry
  in the changelog, and the preset fixtures are regenerated in the same
  change with the diff reviewed. Base profiles are not touched.
- Q: What about tier T2, which cannot deny one socket inside an allowed tree?
  → A: Fail closed: if such a socket exists at spawn and the class is not
  waived, the cage reports a capability gap naming the class and the socket;
  `fit` can relax it by name. Inside a typical container none exist, so
  nothing changes there.
- Q: Abstract socket addresses? → A: Where the kernel can scope abstract
  sockets (Landlock ABI 6) they are scoped when a service-handoff abstract
  address is found; otherwise it is a gap naming the address.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The child cannot start units outside the sandbox (Priority: P1)

An agent runs commands with the network on. Injected instructions make it call
`systemd-run --user` (or talk D-Bus directly). The call fails; the run's
violations name the denied socket.

**Why this priority**: it is a full escape with a one-line command, on the
most common policy shape for agents (network on).

**Independent Test**: An escape canary starts a private D-Bus session bus and
a fake service manager socket, then tries to connect from a caged child with
`Network::All` on T1 and T2; it is refused on T1 and reported as a gap on T2,
next to a positive control with the class waived.

**Acceptance Scenarios**:

1. **Given** T1 and `Network::All`, **When** the child connects to the user
   bus or the service manager socket, **Then** the connect fails.
2. **Given** T2 and an existing user bus socket, **When** the cage is made,
   **Then** it fails with a gap naming service handoff and the socket path,
   unless the class is waived.
3. **Given** the class waived by name, **When** the child connects, **Then**
   it succeeds, and the waiver is recorded.

---

### User Story 2 - Container engines are opt-in (Priority: P1)

A build tool that needs Docker waives `container-engines` and keeps every other
hard deny; an agent that does not, cannot reach any engine.

**Independent Test**: Canaries on both systems with fake engine sockets at
the known paths; refused by default, allowed with the waiver.

**Acceptance Scenarios**:

1. **Given** macOS and `Network::All`, **When** the child connects to a
   container engine socket at a known path, **Then** it is denied.
2. **Given** `container-engines` waived, **When** it connects, **Then** it
   succeeds and nothing else changes in the profile.

---

### User Story 3 - The docs say what changed (Priority: P2)

A harness author upgrading reads in the changelog that policies became
stricter, why, and how to waive each class.

**Acceptance Scenarios**:

1. **Given** the changelog and the threat model, **Then** both name the new
   class, the extended class and the escape class with its canaries.

### Edge Cases

- A socket path under a granted writable tree (a project's own dev server
  socket): unaffected unless it matches a service pattern.
- `DBUS_SESSION_BUS_ADDRESS` in the environment: already dropped by hygiene
  if listed; the socket rule holds regardless of the variable.
- Sockets created after spawn on T1: covered where the class's directory can
  be covered (the runtime directory entries), otherwise documented as the
  existing spawn-snapshot approximation.
- A socket reached through a symbolic link: the rule applies to the resolved
  socket (macOS) and to the cover (T1).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The service-handoff class MUST, on Linux, deny connecting to
  the user bus, the system bus and the user service-manager sockets, under
  every network setting.
- **FR-002**: A new hard-deny class, container-engines, MUST deny connecting
  to the known container-engine sockets on Linux and macOS under every
  network setting.
- **FR-003**: On T1 the backend MUST cover these sockets so a connect fails;
  on T2 it MUST report a capability gap naming the class and each socket
  found at spawn, unless the class is waived.
- **FR-004**: Abstract-address buses MUST be scoped where the kernel can
  scope abstract sockets, and otherwise reported as a gap.
- **FR-005**: Each class MUST be waivable by name only, and every waiver
  MUST be recorded like the existing ones.
- **FR-006**: Denials MUST appear in violation records with the class as the
  reason when reporting is on.
- **FR-007**: The threat model MUST gain the escape class (service handoff
  over Unix sockets) with canaries on both systems; the changelog MUST carry
  a Security entry; the preset fixtures MUST be regenerated and reviewed.
- **FR-008**: `fit` MUST be able to relax each class by name on hosts that
  cannot enforce it, with what would lift the gap.

### Key Entities

- **Hard-deny class**: service-handoff (extended), container-engines (new).
- **Service socket pattern**: a frozen list of paths and directory patterns
  per system, with the home and runtime directories expanded at spawn.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On Linux T1, the service-handoff class MUST make a connect from the caged child to the user bus, the system bus and the user service-manager sockets fail under every network setting, unless the class is waived.
  - Mitigates: `threat.system-bus-handoff`, `threat.user-bus-handoff` via `mitigation.linux-bus-deny`
  - Given T1, Network::All and a private bus at $XDG_RUNTIME_DIR/bus and a fake socket at $XDG_RUNTIME_DIR/systemd/private, when the child connects to each, and to a fake system bus socket at its path, then every connect fails and the fake services record no connection
  - Given the same setup with Network::None, when the child connects, then every connect fails
- **SR-002** (P1): The container-engines class MUST make a connect to every listed engine socket fail on Linux (T1) and macOS under every network setting, unless the class is waived.
  - Mitigates: `threat.engine-handoff` via `mitigation.engine-deny`
  - Given macOS, Network::All and fake engine sockets at each listed home-directory path, when the child connects to each, then every connect is denied and no fake engine records a connection
  - Given Linux T1 in a container lane with fake sockets at each listed system and runtime path, when the child connects to each, then every connect fails
- **SR-003** (P1): On T2, if a socket of an unwaived class exists at spawn, making the cage MUST fail with a capability gap naming the class and every such socket path; fit MUST relax the class by name and say what lifts the gap.
  - Mitigates: `threat.t2-silent-reach` via `mitigation.t2-gap`
  - Given T2 and a socket at $XDG_RUNTIME_DIR/bus, when the cage is made, then it fails with a gap naming service-handoff and that path
  - Given the same host and fit, when fit runs, then it relaxes service-handoff by name and states what would lift the gap
  - Given T2 and no listed socket, when the cage is made, then it succeeds unchanged
- **SR-004** (P1): An abstract address of a service-handoff bus found at spawn MUST be scoped where the kernel supports abstract-socket scoping (Landlock ABI 6), and otherwise MUST fail the cage with a gap naming the address.
  - Mitigates: `threat.abstract-bus` via `mitigation.abstract-scope`
  - Given a fake bus on an abstract address and Landlock ABI 6, when the child connects, then the connect fails
  - Given the same bus and a kernel below ABI 6, when the cage is made, then it fails with a gap naming the address
- **SR-005** (P1): A deny MUST hold for the socket object, not its spelling: a connect through a symbolic link, /var/run instead of /run, or a hard link made inside the cage to a listed socket MUST fail like the direct path.
  - Mitigates: `threat.alias-path` via `mitigation.resolved-object`
  - Given a writable workspace with a symbolic link to a listed fake socket, when the child connects through it, then the connect fails on T1 and macOS
  - Given a listed fake socket, when the child makes a hard link to it in the workspace and connects, then the link or the connect fails
- **SR-006** (P1): The runtime and home directories MUST be expanded both from the environment and from the account (/run/user/<uid>, the account's home), and the listed sockets denied under each spelling.
  - Mitigates: `threat.runtime-dir-expansion` via `mitigation.uid-expansion`
  - Given a harness with XDG_RUNTIME_DIR unset and a fake bus at /run/user/<uid>/bus, when the child connects, then the connect fails
  - Given HOME pointing to another directory, when the child connects to the engine socket under the account's home, then the connect is denied
- **SR-007** (P1): The service socket list MUST be versioned data with a source per entry, and the docs MUST list each path and directory pattern it covers and say that sockets outside it are not covered.
  - Mitigates: `threat.list-gap` via `mitigation.versioned-list`
  - Given the list and the docs, when a table test compares them, then every entry appears in both with its version
- **SR-008** (P1): On T1 a socket created after spawn at a listed runtime-directory path MUST be unreachable; any listed path that cannot be covered that way MUST be documented as the spawn-snapshot approximation.
  - Mitigates: `threat.post-spawn-socket` via `mitigation.cover-directories`
  - Given T1, no bus socket at spawn, when a fake bus is bound at $XDG_RUNTIME_DIR/bus after spawn and the child connects, then the connect fails, or the path is listed as a snapshot approximation in the docs
- **SR-009** (P1): Each class MUST be waivable only by its typed name; a waiver MUST remove exactly that class's denies and MUST be recorded in the receipt.
  - Mitigates: `threat.waiver-broadens` via `mitigation.class-scoped-waiver`
  - Given a policy compiled with and without the container-engines waiver, when the outputs are compared, then they differ only in the engine denies, service-handoff still holds, and the receipt lists the waiver
  - Given container-engines waived, when the child connects to a fake engine, then it succeeds and a connect to the fake bus still fails
- **SR-010** (P2): Patterns MUST match only listed names under the expanded directories; a socket under a granted writable tree that matches no pattern MUST stay reachable.
  - Mitigates: `threat.over-deny` via `mitigation.exact-patterns`
  - Given a project's own server socket in the writable workspace, when the child connects, then it succeeds on T1, T2 and macOS
- **SR-011** (P2): With reporting on, a refused connect to a listed socket MUST be recorded with the class name as its reason.
  - Mitigates: `threat.wrong-reason` via `mitigation.class-reason`
  - Given macOS, reporting on and a fake engine socket, when the child connects, then the record holds a violation with reason container-engines
- **SR-012** (P1): The escape suite MUST hold a canary per class with the network on, on T1, T2 and macOS, each paired with a positive control (class waived, connect succeeds) and failing, never skipping, when the setup is missing.
  - Mitigates: `threat.engine-handoff`, `threat.user-bus-handoff`, `threat.vacuous-canary` via `mitigation.paired-canaries`
  - Given each lane, when the canary runs, then the connect is refused (T2: the gap), and the waived control connects
  - Given a lane where the private bus cannot start, when the canary runs, then it fails
- **SR-013** (P2): The change MUST ship with a Security entry in the changelog and the escape class in the threat model, and the regenerated preset fixtures MUST differ only by the new denies.
  - Mitigates: `threat.silent-tightening` via `mitigation.reviewed-fixtures`
  - Given the fixture diff, when it is reviewed, then every changed line is a service-handoff or container-engines deny
  - Given the changelog and the threat model, when they are read, then both name container-engines, the extended service-handoff and the canaries
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: With the network on, no caged child on any lane can start a
  process outside the sandbox through a bus, the service manager or a
  container engine, unless the class is waived (canaries green).
- **SC-002**: Every existing escape and spawn test passes; the only fixture
  changes are the new denies.
- **SC-003**: A build that needs Docker works after a single waiver.

## Assumptions

- The canaries can run a private bus and fake sockets without system
  services (CI runners and containers have no user session).
- Socket paths are stable enough to list; the list is versioned like the
  other data classes.

## Out of Scope

- TCP endpoints of local services (a Docker TCP port): covered by the
  loopback rules.
- Polkit policy analysis: the system bus is denied as a whole.
