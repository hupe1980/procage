# Feature Specification: Windows backend

**Feature Branch**: `050-windows` (planning directory; commits land on `main`)

**Created**: 2026-11-07

**Status**: Draft

**Input**: A native Windows 11 backend built on the operating system's
process security environment (BaseContainer), plus a job object for
lifetime and limits. Agent tools that run on Windows without WSL2 (editor
extensions, desktop agents, MCP hosts) get the same typed, fail-closed cage
procage gives on macOS and Linux.

## Context

Windows was not planned until now. The reason was that a native backend
would have to change the file ACLs of the user's own trees for every grant,
and that network filtering needed an administrator. WSL2 runs the Linux
backend, and that remains true.

Since Windows 11 24H2/25H2 build 26100.9278/26200.9278 (KB5120998,
2026-08), the OS ships a **process security environment**. It is a
per-container policy that the system applies when it creates the process:

- read-write, read-only, denied and enumerate-only paths;
- per-container egress filters by address, protocol and port;
- a host-loopback switch and a loopback proxy endpoint;
- UI restrictions.

None of it changes the ACLs of user files or needs an elevation prompt.
Microsoft documents it as the base of Microsoft Execution Containers (GA
2026-10-07). Codex, GitHub Copilot and others use that layer through its
SDK.

So the reason for "not planned" no longer holds: the OS mechanism is a
policy object applied at process creation, the same shape as Seatbelt or
Landlock. Like libsandbox it is not documented on Microsoft Learn. Its
interface is a FlatBuffers schema published under MIT in Microsoft's
open-source MXC repository, and it is exported from a system DLL. procage
treats it exactly as it treats libsandbox (constitution VI): resolve at
runtime, probe before use, report absence as `Unsupported`.

What procage adds over calling the SDK:

- the existing portable policy, lowered with typed gaps;
- the hard-deny tier;
- hygiene by default (handles, environment, console);
- receipts and `explain`;
- an escape suite run against the real OS.

## Clarifications

### Session 2026-11-07

Decided by the project's scope rule (best-in-class, no overengineering).

- Q: Which mechanism: restricted tokens with ACL changes (Codex
  "unelevated"), dedicated local users and firewall rules (Codex
  "elevated"), or the OS process security environment? → A: Only the
  process security environment. Restricted tokens leave reads open and
  rewrite ACLs on the user's trees, which leaves residue after a crash.
  Dedicated users need an administrator. Both are what the OS feature
  replaces. No fallback: a host without it is `Unsupported`, never weaker
  (constitution I).
- Q: Build on Microsoft's SDK or on the OS interface directly? → A: The OS
  interface directly. The SDK is an engine with its own JSON policy,
  backends and lifecycle. procage would then wrap another harness, and its
  lowering would no longer be the only translation of a policy. The schema
  is small, versioned and stable by its own evolution rules, so procage
  owns its encoder and pins the schema version it was tested with.
- Q: Which hosts? → A: Windows 11 at or above the first build with the
  process security environment; the backend builds for x64 and arm64, and
  a release claims an architecture only where a lane runs it (see the
  next session). Each optional OS feature
  (denied paths, enumerate-only paths, ingress policy) is probed, and a
  construct that needs a missing feature is a gap. Windows 10 and Windows
  Server are `Unsupported` until a CI lane proves them.
- Q: How do the OS's implicit read grants fit "deny by default"? → A: The
  OS grants every container read access to locations that system ACLs
  open to `ALL_APPLICATION_PACKAGES` (most of `C:\Windows` and
  `C:\Program Files`; not the user profile). procage cannot remove that
  grant. It is the Windows base: measured, recorded on the `Plan`, and
  named by `explain`. A policy with `Base::None` is a gap on Windows.
- Q: Network modes? → A: `None` maps to no network capability, with
  egress, ingress and host loopback denied. `Ip` and `All` map to the
  network capabilities with ingress and host loopback allowed (the IR's
  "connect to and listen on any address"), where the build has the
  ingress feature. `Loopback` maps to the host-loopback switch where the
  build supports it.
  `Proxy` maps to the loopback proxy endpoint, and only when the probe and
  a canary show that the child reaches the proxy and nothing else on
  loopback. Otherwise each is a gap.
- Q: Bindings? → A: Out of scope. Python wheels and Node addons for
  Windows follow in their own record once this backend is released.

### Session 2026-11-07 (clarify)

Decided by the same rule; each answer is applied in the sections it names.

- Q: Windows may let a container run any file it can read. How does
  `Exec::Granted` lower? → A: Exactly, if a canary shows that read-only
  grants without an `Exec` rule refuse execution. Otherwise it is an
  approximation, `exec-where-readable`, that the caller accepts by name
  and the `Plan` records. `Exec::Never` maps to the OS's child-process
  restriction where a canary proves it, otherwise it is a gap (FR-003,
  SC-001).
- Q: Which architectures does a release claim? → A: Only those a CI lane
  runs. The lane is GitHub's hosted `windows-11-arm` image (Windows 11,
  arm64). GitHub's x64 Windows images are Windows Server, so x64 is
  built there but not claimed. There is no self-hosted lane. Reports from
  users on other hosts arrive as GitHub issues; they inform the record
  but are not claims (FR-010, Assumptions).
- Q: Which parts of the API exist on Windows? → A: `Cage::new`,
  `with_options`, `fit`, `spawn`, `spawn_with_handles` (the Windows form of
  `spawn_with_fds`),
  the `Child` methods, receipts, `explain`, `diff`, `suggest` and the
  tokio feature. `Cage::exec` (replace the current process) and
  `exec_session` have no Windows equivalent and return `Unsupported`.
  `Tty::NewPty` and violations are gaps in this record (FR-013).
- Q: What console does the child get? → A: With `Tty::None`, a new
  console without a window, never the parent's: console programs still
  start, and nothing they write reaches the user's terminal input.
  `Tty::Inherit` shares the parent's console. A child sharing the console
  can write into its input buffer, the Windows form of TIOCSTI, so
  `Inherit` needs the `TerminalInjection` waiver by name, as on macOS
  (FR-006, Edge Cases).
- Q: What does `Lifetime::Tree` mean on Windows? → A: The same as
  `Lifetime::Run`. Every process of the run is in its job, and Windows
  has no session-escape equivalent to tell the two apart, so the
  documented Linux residual does not exist here (FR-007).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Cage a command on native Windows (Priority: P1)

A developer tool on Windows runs a model's command in a workspace with the
same preset it uses on macOS and Linux. The command reads and writes the
workspace and reads the toolchain. It cannot read the user's profile,
credentials or other projects, and has no network.

**Why this priority**: This is the backend. Without it, nothing else in
this record has a host.

**Independent Test**: On a Windows 11 lane, cage `cmd /c` and a Rust-built
probe with the workspace preset. Check that writes inside the workspace
succeed. Check that reads of `%USERPROFILE%\.ssh`, writes outside the
workspace and an outbound connection are each refused.

**Acceptance Scenarios**:

1. **Given** the workspace preset and a workspace directory, **When** a
   caged command writes a file there and reads a system DLL, **Then** both
   succeed.
2. **Given** the same cage, **When** the command reads a file in the
   user's profile outside the workspace, writes outside the workspace, or
   opens an outbound TCP connection, **Then** each is refused by the OS.
3. **Given** a host without the process security environment, **When** a
   cage is built, **Then** construction returns `Unsupported`, naming what
   is missing, and no process starts.
4. **Given** a policy with a construct Windows cannot enforce (for example
   a glob, `Base::None`, or a construct whose OS feature the host lacks),
   **When** it is lowered for Windows, **Then** a `CapabilityGap` names
   it, and it is accepted only by name.
5. **Given** a caller that already runs in an AppContainer or a process
   security environment, **When** it builds a cage, **Then** it gets
   `AlreadySandboxed`.

---

### User Story 2 - Same hygiene and lifetime as the other backends (Priority: P1)

A harness relies on procage's defaults: no inherited handles, an
environment from the allowlist, no console, and every process of a run
killed when the run ends.

**Why this priority**: Constitution V cannot be waived. A Windows child
that inherits handles or outlives its run would break the library's
contract on that OS.

**Independent Test**: The hygiene canaries ported to Windows: an
inheritable handle in the parent, a secret in the environment, a
grandchild started with breakaway, and a parent that drops the `Child`.

**Acceptance Scenarios**:

1. **Given** an inheritable handle in the parent that was not declared,
   **When** the child enumerates its handles, **Then** only stdio and the
   declared handles are present.
2. **Given** a secret-looking variable in the parent's environment,
   **When** the child prints its environment, **Then** the variable is
   absent.
3. **Given** a run whose descendants spawn further processes, including
   with a breakaway request, **When** the run is killed or its `Child` is
   dropped (`Lifetime::Run`), **Then** every process of the run is gone.
4. **Given** rlimits in the policy, **When** the child exceeds the process
   count or CPU time limit the job enforces, **Then** the OS stops it. A
   limit Windows has no equivalent for (open files, core size, file size)
   is a gap. The IR has no memory limit, so none is set.
5. **Given** the child's process before it runs a single instruction of
   the target, **When** procage verifies it, **Then** it runs in the
   expected security environment and job. A process that fails the check
   is terminated before it is resumed.

---

### User Story 3 - The escape classes answered on Windows (Priority: P2)

A security reviewer reads the threat model and finds every escape class
and hard-deny class answered for Windows: mitigated with a canary, typed
as a gap, or documented as out of scope.

**Why this priority**: Without its escape suite, the backend makes claims
only the profile text supports (constitution III).

**Independent Test**: The escape suite's Windows lane is green, and the
threat model has a Windows column.

**Acceptance Scenarios**:

1. **Given** each hard-deny class, **When** the Windows lowering is
   inspected, **Then** each class is either enforced, with a canary that
   fails without it, or a typed gap. Examples: secrets in the user
   profile; service handoff over named pipes such as the container
   engines' pipes; persistence through autorun registry keys and the
   Startup folder; synthetic input and clipboard (terminal injection);
   process access to the user's other processes.
2. **Given** a protected path inside a writable tree (`Protect`) or a
   hidden path inside a readable tree (`Hide`), **When** the child writes
   or reads it, **Then** the OS refuses. This holds for 8.3 short names,
   case variants, alternate data streams, `\\?\` and device paths,
   junctions and symbolic links, measured on a real host.
3. **Given** a writable root, **When** the child renames the root or an
   ancestor of a protected path, **Then** it is refused, or the class is a
   documented gap.

---

### User Story 4 - Network modes (Priority: P2)

A harness gives a build access to a package registry by address, or to
procage's egress proxy only.

**Why this priority**: The network gap is the third item of the ordering
rule. `None` comes with the OS filters at no extra cost. `Ip`, `All`,
`Loopback` and `Proxy` depend on build features.

**Independent Test**: Canaries for each mode: a direct connection, a
connection to an unrelated loopback listener, a connection through the
proxy.

**Acceptance Scenarios**:

1. **Given** `Network::None`, **When** the child connects anywhere,
   including loopback, **Then** it is refused.
2. **Given** `Network::Ip` on a host with the ingress feature, **When**
   the child connects to a public address or a host-loopback listener,
   or listens on a port, **Then** each succeeds, as the IR defines `Ip`.
   Unix sockets stay limited to `ipc.unix_sockets`, which is a gap on
   Windows. On a host without the ingress feature, `Ip` is a gap.
3. **Given** `Network::Proxy` on a host where the probe reports
   loopback-proxy support, **When** the child connects through the proxy,
   **Then** it succeeds. **When** it connects to any other loopback port
   or a public address, **Then** it is refused. On a host without the
   support, lowering returns a gap.

---

### User Story 5 - Evidence: plan, receipts, explain (Priority: P3)

The evidence features work on Windows as on the other OSes: the `Plan`
lists gaps and the base, receipts record what ran, and `explain` names the
deciding rule, including the OS base grant.

**Acceptance Scenarios**:

1. **Given** a cage on Windows, **When** a run ends, **Then** its receipt
   names the target (Windows, build and probed features), the policy hash,
   the degradations and the waivers.
2. **Given** a read of `C:\Windows\System32\kernel32.dll`, **When**
   `explain` is asked, **Then** it answers "allowed by the Windows base".
   For an operation it marks reliable, the answer agrees with the OS.
3. **Given** `CageOptions::with_violations` on Windows, **When** a cage
   is built, **Then** the option is a typed gap, not a silent no-op. The
   OS denial trace is left to a later record.

### Edge Cases

- The caller passes a path on a network share, a `subst` drive, a removable
  drive or a volume GUID path. A `subst` or mapped drive letter is resolved
  to its target before encoding. Removable drives are treated like fixed
  ones and covered by the matrix. UNC, `\\?\`, device and volume GUID
  paths are gaps.
- The child replaces a directory inside its writable tree with a junction
  or symbolic link before the next spawn resolves a grant below it. procage
  never follows it: a reparse point on a grant's path inside a writable
  tree refuses the spawn (the Windows form of R-33).
- A BitLocker-locked unrelated drive is attached (a known MXC failure).
  Construction fails typed, or succeeds; it never succeeds weaker.
- Many concurrent runs from a multithreaded parent: each gets its own
  security environment and job; none inherits another's handles.
- A Windows update changes the schema version the OS accepts. The probe
  reports the version, and a version procage was not tested with is
  `Unsupported`.
- The target is a GUI program. By default the UI is disabled
  (no window-system calls). A policy that needs a window is out of scope
  for this record and is a gap.
- `Tty::Inherit` (sharing the parent's console) needs the
  `TerminalInjection` waiver by name. `Tty::NewPty` is a gap in this
  record.
- The caller asks for `Cage::exec` or `exec_session`. Both return
  `Unsupported` on Windows.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: procage MUST offer a `windows` backend (and the `native`
  alias on Windows) behind the same `Cage` API, with a new lowering
  target, Windows, that carries the probed build and OS features.
- **FR-002**: The backend MUST resolve the OS interface at runtime,
  probe its version and optional features once per process, and return
  `Unsupported` when the interface, a required version or a required
  feature is missing. No restricted-token, ACL-rewriting or
  administrator-assisted fallback exists.
- **FR-003**: Lowering MUST map `Read`, `Write`, `Protect` and `Hide`
  rules and per-spawn grants to the OS's read-only, read-write and denied
  paths. `Exec::Granted` MUST lower exactly where a canary shows that
  execution is refused outside `Exec` rules. Otherwise it is the named
  approximation `exec-where-readable`. It MUST return a `CapabilityGap` for
  globs, for `Exec::Never` without a proven child-process restriction,
  for `Base::None`, for
  `ipc.unix_sockets`, for `Signals::SameUser`, and for every other construct
  without a measured equivalent.
- **FR-004**: The OS base (what the system grants every container) MUST be
  measured on each tested build, recorded on the `Plan` and in receipts,
  and reported by `explain`.
- **FR-005**: The backend MUST NOT change the ACL, owner or attributes of
  any path the caller names, nor of any path under them.
- **FR-006**: The child MUST be created suspended, inside its security
  environment and a job that forbids breakaway, with only stdio and
  declared handles inheritable, an environment block built from the
  policy's allowlist, and a new console without a window (never the
  parent's) unless `Tty::Inherit` is set with the `TerminalInjection`
  waiver. It MUST be verified before it is resumed; a failed check
  terminates it.
- **FR-007**: `Lifetime::Run` and `Lifetime::Tree` MUST kill every process
  of the run when the run ends or its `Child` is dropped, and when the
  parent exits.
- **FR-008**: Network modes MUST lower as decided in Clarifications. Any
  mode the host's features cannot enforce MUST be a gap.
- **FR-009**: Each hard-deny class MUST be enforced on Windows with a
  canary, or be a typed gap waivable by name. The threat model MUST show
  which, per class.
- **FR-010**: A Windows CI lane MUST run the backend's tests, the hygiene
  canaries and the escape suite on a host with the process security
  environment. Tests that find it missing MUST fail, never skip. A
  release MUST claim only the architectures a lane runs.
- **FR-011**: Adding the Windows target is a breaking change of the policy
  crate's public enums. It MUST ship with a migration note.
- **FR-012**: The README, the site and rustdoc MUST state the minimum
  build, the undocumented OS interface procage depends on, the Windows
  base and the gaps, and MUST claim nothing a Windows test does not show.
- **FR-013**: On Windows, `Cage::new`, `with_options`, `fit`, `spawn`,
  `spawn_with_handles`, the `Child` methods, receipts, `explain`, `diff`,
  `suggest` and the tokio feature MUST work. `Cage::exec` and
  `exec_session` MUST return `Unsupported`. `Tty::NewPty` and
  `with_violations` MUST be typed gaps.

### Key Entities

- **Windows target**: the lowering target, carrying the OS build, the
  interface version and the optional features the probe found.
- **Windows base**: the measured set of locations every container may read
  by system ACL. Recorded per build; never edited, only superseded by a
  new version.
- **Security environment**: the OS object built from a lowered `Plan` and
  attached to one process creation; released when the run ends.
- **Run job**: the job object holding every process of one run; carries
  the limits and the kill-on-close lifetime.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The backend MUST return Unsupported when the OS interface, a tested schema version or a required feature is missing, MUST return a typed gap for any construct whose OS feature the host lacks, and MUST NOT use any other mechanism (restricted tokens, ACL changes, local users) as a fallback.
  - Mitigates: `threat.silent-fallback` via `mitigation.probe-or-refuse`
  - Given a host whose probe reports no process security environment, when a cage is built, then Unsupported names what is missing and no process starts
  - Given a host without native denied paths and a policy with a Hide rule, when it is lowered for that host, then a CapabilityGap names the rule
- **SR-002** (P1): The Windows base MUST be measured per tested build, recorded on the Plan and in every receipt with the build and the probed features, and named by explain; Base::None MUST be a gap; the secret classes MUST be denied explicitly even where the base would allow them.
  - Mitigates: `threat.base-overreach`, `threat.unrecorded-run` via `mitigation.measured-base`
  - Given a cage on Windows, when a run ends, then its receipt names the build, the features and the base version
  - Given a read of a system DLL, when explain is asked, then it answers allowed by the Windows base
  - Given a secret-class path readable by the base, when the child reads it, then it is refused
- **SR-003** (P1): Protect, Hide, denied paths and rename anchors MUST hold for 8.3 short names, case variants, alternate data streams, \\?\ and device paths, junctions and symbolic links, each proven by a canary on a real host; an alias class the OS does not close MUST be a documented gap.
  - Mitigates: `threat.path-alias` via `mitigation.path-matrix`
  - Given a protected file inside a writable workspace, when the child writes it through its short name, an alternate data stream or a junction, then each write is refused
  - Given a hidden directory inside a readable tree, when the child reads it with a different case or a \\?\ prefix, then each read is refused
- **SR-004** (P1): The encoder MUST produce the schema version procage pins, MUST be tested against the vendored schema and on the OS, and an untested major version reported by the OS MUST be Unsupported.
  - Mitigates: `threat.schema-mismatch` via `mitigation.pinned-schema`
  - Given a plan with read-only, read-write and denied paths, when it is encoded and decoded with the vendored schema, then every list round-trips exactly
  - Given an OS reporting an untested major version, when a cage is built, then Unsupported is returned
- **SR-005** (P1): The backend MUST NOT change the ACL, owner or attributes of any caller path or any path below it.
  - Mitigates: `threat.acl-residue` via `mitigation.no-acl-writes`
  - Given a workspace whose security descriptors are recorded, when 1,000 runs complete, some killed and one parent killed abruptly, then every security descriptor is byte-identical and no procage process remains
- **SR-006** (P1): The backend MUST load the OS interface's DLL from the system directory only.
  - Mitigates: `threat.dll-hijack` via `mitigation.system32-load`
  - Given a DLL of the interface's name in the parent's working directory and on PATH, when a cage is built, then the planted DLL is not loaded
- **SR-007** (P1): Every child MUST be created with an explicit handle list of stdio and declared handles only, an explicit environment block built from the policy's allowlist, and no console unless the policy asks for one.
  - Mitigates: `threat.env-leak`, `threat.handle-leak` via `mitigation.explicit-handles-env`
  - Given an undeclared inheritable handle in the parent, created by another thread during the spawn, when the child enumerates its handles, then only stdio and declared handles are present
  - Given a secret-looking variable in the parent's environment, when the child prints its environment, then the variable is absent
- **SR-008** (P1): With Lifetime::Run, every process of a run MUST be in the run's job from its creation, MUST NOT break away, and MUST be killed when the run ends, its Child is dropped or the parent exits.
  - Mitigates: `threat.orphaned-run`, `threat.resource-exhaustion` via `mitigation.job-at-creation`
  - Given a run whose grandchild requests breakaway, when the Child is dropped, then every process of the run is gone
  - Given a running cage, when the parent is terminated abruptly, then every process of the run is gone
- **SR-009** (P1): The child MUST be verified from the parent (security environment and job membership) before it is resumed, and terminated without running if the check fails.
  - Mitigates: `threat.unverified-child` via `mitigation.verify-before-resume`
  - Given a fault injected so the security environment is not attached, when the child is spawned, then SpawnError is returned and the target never runs
- **SR-010** (P1): Each hard-deny class MUST be enforced on Windows with a canary that fails without the enforcement, or be a typed gap waivable by name; the threat model MUST state which per class.
  - Mitigates: `threat.persistence`, `threat.service-handoff`, `threat.ui-injection` via `mitigation.hard-deny-windows`
  - Given the default policy, when the child opens the Docker engine pipe, the OpenSSH agent pipe, writes an HKCU Run value or the Startup folder, creates a scheduled task, sends input to another window, or writes the console input buffer, then each is refused, or its class is a listed gap
  - Given a policy with Tty::Inherit and no TerminalInjection waiver, when it is lowered for Windows, then lowering refuses it, naming the waiver that would accept it
- **SR-011** (P1): Network::None MUST deny all IP traffic including host loopback; Network::Proxy MUST lower only where the probe reports support and a canary shows the proxy is the only destination reachable; Network::Loopback, Ip and All MUST lower only where the build has the ingress and host-loopback features; otherwise each MUST be a gap.
  - Mitigates: `threat.loopback-bypass` via `mitigation.loopback-canaries`
  - Given Network::Proxy on a supported host and an unrelated loopback listener, when the child connects to the listener, to a public address and through the proxy, then the listener and the public address are refused and the proxy connection succeeds
  - Given Network::None and a host loopback listener, when the child connects to it, then it is refused
- **SR-012** (P2): Each spawn MUST get its own security environment, released when the run ends; concurrent runs MUST NOT reach each other's per-spawn grants.
  - Mitigates: `threat.cross-run-grants` via `mitigation.environment-per-spawn`
  - Given two concurrent runs of one cage with different per-spawn grants, when each reads the other's grant, then both reads are refused
- **SR-013** (P1): The Windows CI lane MUST fail, never skip, when the host lacks the feature, and the README, rustdoc and threat model MUST claim only what the lane's caged tests show.
  - Mitigates: `threat.untested-claims` via `mitigation.lane-fails-closed`
  - Given the Windows lane on a host without the feature, when the tests run, then they fail
- **SR-014** (P2): The policy's process count and CPU time limits MUST be enforced by the run's job; a limit without a Windows equivalent (open files, file size, core size) MUST be a gap.
  - Mitigates: `threat.orphaned-run`, `threat.resource-exhaustion` via `mitigation.job-at-creation`
  - Given a process-count limit of 4, when the child starts a fifth process, then the creation fails
  - Given a policy with a core-size limit, when it is lowered for Windows, then a CapabilityGap names it
- **SR-015** (P2): The backend MUST build the command line with one quoting function whose output CommandLineToArgvW parses back to the exact argv, and MUST refuse a .bat or .cmd program in argv form.
  - Mitigates: `threat.cmdline-quoting` via `mitigation.argv-quoting`
  - Given arbitrary argv strings with quotes, backslashes, spaces and empty strings, when they are quoted and parsed back, then the parsed argv equals the input
  - Given a .cmd program with argv, when it is spawned, then SpawnError names the refusal
- **SR-016** (P1): procage MUST resolve policy and grant paths on Windows without following any reparse point inside a tree the policy makes writable, MUST refuse the spawn with GrantError::Link when one is found, and MUST resolve per-spawn grants again at every spawn.
  - Mitigates: `threat.planted-link` via `mitigation.no-follow-resolution`
  - Given a run that replaced a granted subdirectory with a junction to the user's .ssh directory, when the next spawn carries that grant, then it fails with GrantError::Link and no process starts
  - Given the same with a directory symbolic link, when the next spawn carries that grant, then it fails with GrantError::Link
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: The workspace preset runs a build of a Rust crate and a
  `git status` in the workspace on the Windows lane. The policy changes
  nothing beyond the preset except the approximations the `Plan` names
  and the caller accepts by name (at most `exec-where-readable`).
- **SC-002**: Every escape class and hard-deny class in the threat model
  has a Windows verdict (canary, gap or out of scope). No class is left
  unstated.
- **SC-003**: After 1,000 runs, including runs killed mid-way and a parent
  killed abruptly, no ACL entry, file, registry key or process belonging
  to procage remains on the host. One surviving process is a failure.
- **SC-004**: Cage construction and spawn overhead over a plain process
  creation are published from the benchmark harness for the Windows lane.
  The target is under 5 ms at the median.
- **SC-005**: Every policy shipped as a preset lowers on Windows either
  without gaps or with a gap list that names each construct and how to
  accept it.

## Assumptions

- The process security environment's schema evolves compatibly, as its
  published evolution rules require. procage pins a tested version and
  treats an untested major version as `Unsupported`.
- GitHub's hosted `windows-11-arm` image carries the minimum build: image
  `win11-arm64/20261006.188` is 10.0.26200.9457. It is below 26200.9550, so
  the loopback-dependent network modes stay gaps there until a later
  image. The x64 images (`windows-latest`) are Windows Server and are not
  assumed to carry the feature.
- The constitution is amended (2.4.0) for this record. Principle IV
  allows `unsafe` in `procage::windows::sys` and states the rule for an OS
  without `fork`: no procage code runs in the child; the child is created
  suspended, verified from the parent and resumed. Principles I, III and
  VI cover the OS interface and the Windows lane.
- WSL2 remains a supported way to run procage on Windows through the Linux
  backend. Nothing here changes it.

## Out of Scope

- Python and Node.js packages for Windows (a later record).
- Windows 10, Windows Server, Windows Sandbox, session containers,
  microVMs and other MXC backends.
- GUI programs and window access beyond the default (UI disabled).
- Mid-run grants.
- Violations from the OS denial trace, and `Tty::NewPty` (a pseudo
  console): each is a gap until a later record.
- Any fallback that weakens enforcement on a host without the feature.
