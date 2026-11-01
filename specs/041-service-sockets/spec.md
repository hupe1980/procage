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

### Session 2026-11-01 (after threat modelling)

- Q: Tier T1 covers the sockets that exist at spawn; a socket bound later at
  a file path is not covered. Exact or approximation? → A: An approximation,
  like the other spawn-snapshot classes: on T1 the classes are accepted with
  the spawn-snapshot option or by name, and where the class owns a whole
  directory (`$XDG_RUNTIME_DIR/systemd`, `$XDG_RUNTIME_DIR/podman`,
  `/run/podman`, `/run/containerd`, `/run/dbus`) the directory is covered,
  so later sockets there are covered too.
- Q: Abstract scoping refuses every abstract socket outside the cage (X11's
  too). Accepted? → A: Yes, and only when a service bus on an abstract
  address exists at spawn; documented.
- Q: Sockets named by `DOCKER_HOST` / `CONTAINER_HOST` at other paths? → A:
  Out of scope: the class covers the listed locations; a caller with an engine
  elsewhere hides that path in its policy. Documented with the list.
- Q: Linux reports only refused system calls; a covered socket is refused by
  a mount, not by seccomp. → A: FR-006 applies where the system reports the
  denial (macOS); on Linux the refusal is not reported, as for every mount and
  Landlock denial, and the docs say so.
- Q: Hard links to a listed socket made inside the cage? → A: Measured on
  macOS 26.6.2: under the deny rule, `link()` to the socket is refused.
  Linux: hard links across directories need Landlock's refer right, which
  procage never grants, and on T1 the cover hides the original name.
- Q: Which homes and runtime directories? → A: Every `/run/user/*` the caller
  can read, its `XDG_RUNTIME_DIR`, the account's home and the homes procage
  already knows (Linux); every user home (macOS).

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
- **FR-003**: On T1 the backend MUST cover these sockets so a connect fails,
  and the classes' directories as a whole; because a socket bound later
  outside those directories is not covered, a T1 cage that finds such
  sockets MUST report the spawn-snapshot approximation, accepted with the
  spawn-snapshot option or by name. On T2 it MUST report a capability gap
  naming the class and each socket found at spawn, unless the class is
  waived.
- **FR-004**: Abstract-address buses MUST be scoped where the kernel can
  scope abstract sockets, and otherwise reported as a gap.
- **FR-005**: Each class MUST be waivable by name only, and every waiver
  MUST be recorded like the existing ones.
- **FR-006**: Where the system reports the denial (macOS), denials MUST
  appear in violation records with the class as the reason when reporting is
  on; on Linux the docs MUST say that a covered socket's refusal is not
  reported.
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
  - Given macOS and a listed fake socket under procage's deny-default profile, when the child calls link() to it from the workspace, then link() is refused
  - Given Linux T1 and a listed fake socket, when the child makes a hard link to it in the workspace and connects, then the link fails (no refer right) or the connect fails (the cover hides the original name)
- **SR-006** (P1): Discovery MUST take the runtime directories from every /run/user/* the caller can read, the caller's XDG_RUNTIME_DIR and each with_runtime_dir addition (which adds, never replaces), canonicalised; the homes MUST be the account's home and the homes procage already knows on Linux and every user home on macOS; the listed sockets MUST be denied under each.
  - Mitigates: `threat.runtime-dir-expansion` via `mitigation.uid-expansion`
  - Given a harness with XDG_RUNTIME_DIR unset and a fake bus at /run/user/<uid>/bus, when the child connects, then the connect fails (T1) or the cage reports the gap (T2)
  - Given HOME pointing to another directory, when the child connects to the engine socket under the account's home, then the connect is denied
  - Given a scratch runtime directory added with with_runtime_dir and a fake bus in it, when the cage is made, then the bus is found, and the sockets under /run/user/* are still found
- **SR-007** (P1): The service socket list MUST be versioned data whose sources (the D-Bus, systemd and engines' documented default locations) are stated for the list, and the docs MUST list each path and directory pattern it covers, say that sockets outside it are not covered, and say that an engine at a path named only by DOCKER_HOST or CONTAINER_HOST is out of scope and is hidden by the caller's policy.
  - Mitigates: `threat.list-gap` via `mitigation.versioned-list`
  - Given the list and the docs, when a table test compares them, then every entry appears in both with its version
  - Given the docs, when they are read, then they state the DOCKER_HOST and CONTAINER_HOST scope limit next to the list
- **SR-008** (P1): On T1 the class directories ($XDG_RUNTIME_DIR/systemd, $XDG_RUNTIME_DIR/podman, /run/podman, /run/containerd, /run/dbus) MUST be covered whole when found, so a socket bound there after spawn is unreachable; a found socket outside them MUST make its class a spawn-snapshot approximation, accepted only by the spawn-snapshot option or by name and recorded as a degradation, and documented.
  - Mitigates: `threat.post-spawn-socket` via `mitigation.cover-directories`
  - Given T1, an empty $XDG_RUNTIME_DIR/systemd at spawn, when a fake socket is bound at $XDG_RUNTIME_DIR/systemd/private after spawn and the child connects, then the connect fails
  - Given T1, a fake bus at $XDG_RUNTIME_DIR/bus and neither the spawn-snapshot option nor the class named, when the cage is made, then it fails with an approximation gap naming service-handoff and the path
  - Given the same host with the spawn-snapshot option, when the cage is made, then it succeeds and the receipt records the degradation
- **SR-009** (P1): Each class MUST be waivable only by its typed name; a waiver MUST remove exactly that class's denies and MUST be recorded in the receipt.
  - Mitigates: `threat.waiver-broadens` via `mitigation.class-scoped-waiver`
  - Given a policy compiled with and without the container-engines waiver, when the outputs are compared, then they differ only in the engine denies, service-handoff still holds, and the receipt lists the waiver
  - Given container-engines waived, when the child connects to a fake engine, then it succeeds and a connect to the fake bus still fails
- **SR-010** (P2): Patterns MUST match only listed names under the expanded directories; a socket under a granted writable tree that matches no pattern MUST stay reachable.
  - Mitigates: `threat.over-deny` via `mitigation.exact-patterns`
  - Given a project's own server socket in the writable workspace, when the child connects, then it succeeds on T1, T2 and macOS
  - Given T1 below Landlock ABI 6 (where no plan scopes abstract sockets), no abstract service bus at spawn and an unrelated abstract socket, when the child connects to it, then it succeeds: the class adds no abstract scope of its own (from ABI 6 every plan already scopes abstract sockets, independent of this class)
- **SR-011** (P2): On macOS, with reporting on, a refused connect to a listed socket MUST be recorded with the class name as its reason; on Linux, where the refusal comes from a mount cover or the scope and is not reported, the docs MUST say so.
  - Mitigates: `threat.wrong-reason` via `mitigation.class-reason`
  - Given macOS, reporting on and a fake engine socket, when the child connects, then the record holds a violation with reason container-engines
  - Given the Linux docs page, when it is read, then it states that service-socket refusals are not reported on Linux
- **SR-012** (P1): The escape suite MUST hold a canary per class with the network on, on T1, T2 and macOS, each paired with a positive control (class waived, connect succeeds) and failing, never skipping, when the setup is missing.
  - Mitigates: `threat.engine-handoff`, `threat.user-bus-handoff`, `threat.vacuous-canary` via `mitigation.paired-canaries`
  - Given each lane, when the canary runs, then the connect is refused (T2: the gap), and the waived control connects
  - Given a lane where the private bus cannot start, when the canary runs, then it fails
- **SR-013** (P2): The change MUST ship with a Security entry in the changelog and the escape class in the threat model, and the regenerated preset fixtures MUST differ only by the new denies.
  - Mitigates: `threat.silent-tightening` via `mitigation.reviewed-fixtures`
  - Given the fixture diff, when it is reviewed, then every changed line is a service-handoff or container-engines deny and no existing line moves
  - Given the changelog and the threat model, when they are read, then both name container-engines, the extended service-handoff and the canaries
- **SR-014** (P1): Discovery MUST run again for each spawn, in the parent before the child is created: on T2 a socket or abstract bus of an unwaived class found then MUST refuse the spawn with the same gaps; on T1 every found socket MUST be covered in that spawn, and a cover MAY be skipped only when its name no longer exists; a socket bound after the child starts outside a class directory MUST be documented as the spawn-snapshot limit on T1 and T2.
  - Mitigates: `threat.discovery-race` via `mitigation.per-spawn-recheck`
  - Given T2, a cage made with no listed socket, then a fake bus bound at the runtime path, when spawn is called, then it fails with a gap naming service-handoff and the path
  - Given T1, a cage made with no listed socket, then a fake engine socket bound at a listed runtime path, when spawn is called and the child connects, then the connect fails
  - Given T2, a cage made before an abstract bus exists, then a fake abstract bus and no scope, when spawn is called, then it fails with a gap naming the address
- **SR-015** (P1): Discovery MUST treat an existing listed name as found whatever it is (socket, directory, symbolic link or other file), covering the name and its resolved object; it MUST parse /proc/net/unix without trusting the name field's layout; and a failure to read /proc/net/unix while the child shares the network namespace, or to inspect an existing listed path, MUST be a gap, not an empty result.
  - Mitigates: `threat.discovery-shaped` via `mitigation.discovery-fail-closed`
  - Given a writable runtime directory where the listed bus name is a symbolic link to a fake bus elsewhere, when the cage is made on T1 and the child connects by either name, then both connects fail
  - Given a fake abstract socket whose name holds a newline and a listed prefix, when discovery runs, then it neither panics nor drops a real fake bus listed after it
  - Given T2 with Network::All and /proc/net/unix unreadable, when the cage is made, then it fails with a gap naming service-handoff
- **SR-016** (P1): The Linux lowering MUST carry both classes in LinuxPlan::service_sockets for every policy that leaves the child any pathname or abstract Unix connect (Network::All, a non-empty ipc.unix_sockets, and any network mode added later that allows one), unless the class is waived; a lowering table test MUST cover every Network variant and ipc setting.
  - Mitigates: `threat.reach-predicate` via `mitigation.reach-table`
  - Given each Network variant crossed with an empty and a non-empty ipc.unix_sockets, when the policy is lowered, then service_sockets is non-empty exactly where a Unix connect is possible and the classes are not waived
  - Given a new Network variant without a table row, when the lowering tests run, then they fail
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
