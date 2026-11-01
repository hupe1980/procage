# Feature Specification: Lifetime — nothing a run starts outlives it

**Feature Branch**: `024-lifetime` (planning directory; commits land on `main`)

**Created**: 2026-10-31

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "024-lifetime: Keep double-forked descendants inside the run: Linux session/group lock or PID namespace; macOS research (R-23)."

## Context

procage promises that a caged child and its descendants do not outlive the
run (constitution V). Today the child's handle kills, when it is dropped or
`kill_all` is called:

- the child's process group, and
- every descendant it can still find by walking parent links from the child.

A descendant escapes both when it starts its own session (`setsid`) or
process group (`setpgid`) and its parent then exits: the kernel reparents it
to `launchd` or `init`, outside the child's tree and outside its group. The
same happens to every descendant once the child itself has exited, because
the walk starts from the child. This is the open variant of escape class
R-23, ignored as a canary on both systems, and a consumer harness hit it in
real use. A daemon an agent starts (`ssh-agent`, a dev server with
`--daemon`, a `nohup setsid` one-liner) keeps running unconfined in time,
though still in the cage, after the caller believes the run is over.

Research before this spec (macOS 26.6.2) found a way to identify a run's
processes on macOS without their parentage: the cage profile carries a
per-run marker that only processes of that run allow, and the parent asks
the kernel, per process, whether its sandbox allows the marker. A
double-forked, `setsid` process reparented to `launchd` was found, and
nothing else matched; a scan of 716 processes took 1.9 ms.

On Linux, a process can leave its group only through `setsid` and
`setpgid`. If those two calls fail inside the cage, every descendant stays
in the child's process group for its whole life, and the group cannot be
handed to another process while a member lives, so one group kill reaches
all of them, also after the child has exited.

## Clarifications

### Session 2026-10-31

- Q: Should keeping descendants in the run be the default for every policy,
  including the frozen presets, or an opt-in? → A: The default. It is what
  constitution V promises, and it only tightens. A policy can opt out with
  a lifetime setting for programs that need their own sessions or process
  groups (job-control shells, which a later pseudo-terminal row needs).
  Opting out is recorded in the policy, like any other setting.
- Q: On Linux, which mechanism: the session/group lock or a PID namespace?
  → A: The lock (`setsid` and `setpgid` fail with `EPERM` inside the cage).
  It works on both tiers, needs no extra process, and keeps the child the
  direct child of the caller. A PID namespace needs an init process inside
  the cage and user namespaces, so it would not cover T2; it stays a
  separate concern (R-25).
- Q: On macOS, where Seatbelt cannot filter `setsid`, what does "in the run"
  mean? → A: Every process whose sandbox carries the run's marker. Programs
  may start sessions freely; the handle finds them by marker and kills
  them. This also covers descendants of a child that has already exited.
- Q: When does the run end? → A: As today, when the handle is dropped or
  `kill_all` is called. `detach` still gives up lifetime control. A child
  that exits on its own does not end the run: its descendants live until
  the handle is dropped (documented).
- Q: What if the handle cannot kill everything (a process of the run keeps
  forking faster than it is killed, or runs as another user)? → A:
  `kill_all` keeps trying for a bounded number of rounds and then returns an
  error naming the survivors; it never reports success while a process of
  the run is known to live.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A daemon started in the cage dies with the run (Priority: P1)

A caller (an agent harness) runs a command that daemonizes something: it
forks, the intermediate starts a new session and forks again, and the
intermediate exits. When the caller drops the child's handle, the daemon
is gone, on macOS and on Linux tiers T1 and T2.

**Why this priority**: This is the open R-23 variant and the promise of
constitution V.

**Independent Test**: The escape-suite canary
`r23_a_double_forked_descendant_dies_with_the_run` runs (no longer ignored)
and passes on macOS and on Linux T1 and T2.

**Acceptance Scenarios**:

1. **Given** a policy that allows forking and the default lifetime, **When**
   the child double-forks a descendant that starts its own session (macOS)
   or tries to (Linux), and the caller drops the handle, **Then** the
   descendant is dead within two seconds.
2. **Given** the default lifetime on Linux, **When** a caged process calls
   `setsid` or `setpgid`, **Then** the call fails with `EPERM` and the
   process stays in the child's process group.
3. **Given** the default lifetime on macOS, **When** a caged process calls
   `setsid`, **Then** it succeeds, and the process is still killed when the
   run ends.

---

### User Story 2 - Descendants die even after the child exited (Priority: P1)

A command starts a background process and exits normally. The caller
waits for the child, reads its output, and drops the handle. The background
process is gone.

**Why this priority**: This is how every "run a command to completion"
consumer works (a consumer harness's runner among them). Today only the
group is killed after the child exits.

**Independent Test**: A canary where the child starts a descendant in a
new session (macOS) or in its group (Linux), exits, is waited for, and then
the handle is dropped: the descendant is dead.

**Acceptance Scenarios**:

1. **Given** a child that started a descendant and exited, **When** the
   caller has waited for the child and drops the handle, **Then** the
   descendant is dead within two seconds.
2. **Given** two children of the same caller running at the same time,
   possibly from the same cage, **When** the caller drops one handle,
   **Then** only that run's processes are killed; the other run's processes
   keep running.

---

### User Story 3 - A program that needs its own sessions can opt out (Priority: P2)

A caller that runs a job-control shell or a program that must create
process groups sets the policy's lifetime to the tree setting. On Linux,
`setsid` and `setpgid` then work as before, and the handle kills the group
and the descendants it can find from the child (the old behaviour, with
the R-23 gap stated in the documentation). On macOS nothing changes:
descendants are still found by marker.

**Why this priority**: Without the opt-out, the default would break programs
that legitimately manage process groups, with no recourse.

**Independent Test**: With the tree setting on Linux, a caged `setsid` call
succeeds; with the default it fails.

**Acceptance Scenarios**:

1. **Given** the tree setting on Linux, **When** a caged process calls
   `setsid`, **Then** it succeeds.
2. **Given** the tree setting on macOS, **When** a double-forked descendant
   in its own session exists and the handle is dropped, **Then** it is
   killed.

### Edge Cases

- The policy forbids forking: no descendants can exist; the handle does no
  extra work (no scan, no marker).
- The child was already reaped by the caller through `std::process::Child`
  (via `Deref`): the run's other processes are still killed on drop.
- `detach` was called: the run's processes keep running, and their marker
  is never reused for another run of the same caller.
- A process of the run forks continuously: the handle keeps killing until
  none is found or the round limit is reached, then reports the survivors.
- A process of the run is a zombie: it is not counted as a survivor.
- A marker check races with the exit of a process and the reuse of its
  pid: the window is documented; macOS has no process handle that would
  close it.
- Many runs at the same time: each gets its own marker; markers are reused
  only after their run has ended and all its processes are dead.
- The caller's process already runs sandboxed: procage refuses to spawn
  (unchanged), so the marker check never runs from inside a sandbox.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy MUST have a lifetime setting with two values: the
  default, under which every process the child starts belongs to the run
  until it ends, and a tree setting, under which programs may start their
  own sessions and process groups and the run ends the child's tree as
  before. Policies serialized before this feature MUST still parse and get
  the default.
- **FR-002**: On Linux, under the default lifetime, `setsid` and `setpgid`
  MUST fail with `EPERM` in every process of the cage, on tiers T1 and T2.
  procage's own setup in the child (which starts the session or group)
  MUST still run before the lock applies.
- **FR-003**: On Linux, ending the run MUST kill the child's process group;
  under the default lifetime this MUST reach every descendant, including
  after the child has exited and been reaped.
- **FR-004**: On macOS, every spawn whose policy allows forking MUST carry a
  marker unique among the caller's live runs, and ending the run MUST kill
  every process whose sandbox carries that marker, wherever it was
  reparented, and including after the child has exited.
- **FR-005**: On macOS, the marker MUST NOT grant the caged process any
  access to anything that exists, and processes outside the run (the
  caller, unsandboxed processes, other cages, other runs of the same cage)
  MUST NOT match it.
- **FR-006**: Ending the run MUST repeat the search and kill until no live
  process of the run is found or a fixed round limit is reached; in the
  latter case `kill_all` MUST return an error naming the surviving process
  ids, and the marker MUST NOT be reused.
- **FR-007**: A marker MUST be reused only after its run ended and no process
  carrying it lives; `detach` MUST retire the marker for the life of the
  caller's process.
- **FR-008**: The compile cache MUST keep serving repeated spawns of the same
  policy: sequential runs of the same policy MUST NOT compile again because
  of the marker.
- **FR-009**: The lowering MUST report the lifetime setting in its ledger on
  both systems; the Linux lock MUST appear in the seccomp program built for
  the policy, and the lowering table MUST document both systems.
- **FR-010**: The escape-suite canary for the double-fork variant MUST run
  (not be ignored) and pass on macOS and on Linux T1 and T2; a new canary
  MUST cover descendants of a child that exited before the run ended; the
  catalog status of R-23 MUST become `mitigated` with these tests as
  evidence, and the published threat model, README and crate docs MUST
  stop listing the variant as open.
- **FR-011**: The frozen presets MUST keep their version and get the default
  lifetime; the tightening MUST be stated in the documentation of the
  setting, the preset module and the threat model's release status
  (procage has no changelog yet).
- **FR-012**: Code that runs in the child between fork and exec MUST stay
  system calls only; the macOS marker MUST be part of the compiled profile,
  not a step in the child.

### Key Entities

- **Lifetime setting**: part of the policy's process section; the default
  (run) or the tree setting.
- **Run marker**: on macOS, a name unique among the caller's live runs,
  carried by every process of one run through its sandbox profile; it is
  free again once the run has ended and none of its processes lives.
- **Survivor report**: the process ids `kill_all` could not kill.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Under the default lifetime on Linux, setsid and setpgid MUST fail with EPERM in every caged process on tiers T1 and T2, and dropping the handle MUST kill a double-forked descendant.
  - Mitigates: `threat.daemon-outlives-run`, `threat.orphan-after-exit` via `mitigation.linux-group-lock`
  - Given the default lifetime on T1 and on T2, when a caged process calls setsid and setpgid, then both fail with EPERM
  - Given a double-forked descendant on T1 and on T2, when the handle is dropped, then the descendant is dead within two seconds
- **SR-002** (P1): On macOS, ending a forking run MUST kill every process whose sandbox carries the run's marker, including a double-forked descendant in its own session reparented to launchd.
  - Mitigates: `threat.daemon-outlives-run`, `threat.orphan-after-exit` via `mitigation.macos-marker-scan`
  - Given a double-forked descendant in its own session on macOS, when the handle is dropped, then the descendant is dead within two seconds
- **SR-003** (P1): Descendants of a child that exited and was reaped before the run ended MUST be killed when the handle is dropped, on macOS and on Linux T1 and T2.
  - Mitigates: `threat.daemon-outlives-run`, `threat.orphan-after-exit` via `mitigation.linux-group-lock`, `mitigation.macos-marker-scan`
  - Given a child that started a background descendant and exited, when the caller waits for it and drops the handle, then the descendant is dead within two seconds
- **SR-004** (P1): The macOS marker MUST be part of the compiled profile, MUST grant no access to an existing resource, and MUST NOT match the caller, unsandboxed processes, or a sandbox that allows all lookups.
  - Mitigates: `threat.cross-run-kill`, `threat.marker-evasion` via `mitigation.immutable-marker`
  - Given a running cage and an allow-all sandbox and the caller, when each is checked for the run's marker, then only the cage's processes match
  - Given the lowered profile, when its marker rules are inspected, then they use a literal name and no extension filter
- **SR-005** (P1): Two live runs of one caller MUST NOT share a marker; dropping one run's handle MUST leave the other run's processes alive; a marker MUST be reused only after a kill that found no survivor, and never after detach.
  - Mitigates: `threat.cross-run-kill` via `mitigation.slot-discipline`
  - Given two concurrent runs from the same cage with descendants in their own sessions, when one handle is dropped, then the other run's descendants are still alive
  - Given a detached child, when another child is spawned, then it gets a different marker
- **SR-006** (P2): kill_all MUST NOT return Ok while a process of the run is known to live; after the round limit it MUST return an error naming the survivors.
  - Mitigates: `threat.kill-false-success` via `mitigation.bounded-rounds`
  - Given a search that keeps finding a live process of the run, when the round limit is reached, then kill_all returns an error with its pid
- **SR-007** (P2): The lifetime setting MUST appear in the lowering ledger on both systems and in the lowering table; the Linux lock MUST be pinned per architecture; the frozen presets MUST carry the default lifetime.
  - Mitigates: `threat.silent-lifetime-weakening` via `mitigation.ledger-and-pins`
  - Given a policy with each lifetime value, when it is lowered for Linux and macOS, then the ledger reports the setting and the Linux seccomp rules contain the lock only for the default
  - Given every frozen preset, when it is built, then its lifetime is the default
- **SR-008** (P1): R-23 MUST be marked mitigated only with the double-fork and exited-child canaries as evidence, passing on macOS and Linux T1 and T2, and the catalog gate MUST pass.
  - Mitigates: `threat.daemon-outlives-run`, `threat.overclaimed-lifetime` via `mitigation.canary-evidence`
  - Given the catalog, when the gate runs, then R-23 is mitigated with existing canary tests as evidence
  - Given the escape suite on macOS, T1 and T2, when it runs, then the R-23 canaries pass and none is ignored
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The double-fork canary and the exited-child canary pass on
  macOS and on Linux T1 and T2 (previously ignored as open).
- **SC-002**: R-23 is `mitigated` in the catalog, with the catalog gate
  passing.
- **SC-003**: Dropping the handle of a forking run on macOS takes at most
  10 ms more than today, measured on the development machine.
- **SC-004**: Spawning the same forking policy twice in a row compiles once.
- **SC-005**: Two concurrent runs from the same cage: dropping one leaves the
  other's descendants alive (100% of attempts in the test).
- **SC-006**: `just ci` passes with all gates.

## Assumptions

- Development host macOS 26.6.2 (arm64); Linux evidence from the Docker
  T1/T2 images used by earlier rows (kernel 7.0, aarch64). CI lanes run once
  pushed.
- macOS's sandbox check accepts another process's id from an unsandboxed
  caller and a mach-lookup name filter (measured before this spec). This is
  a private interface; it is resolved and probed like the other libsandbox
  symbols.
- Persistence (launch agents, systemd user units) stays covered by the
  existing hard-deny classes; this feature handles live processes only.
- Consumers are not changed by this feature; the consumer harness that
  reported the escape is answered by it.
