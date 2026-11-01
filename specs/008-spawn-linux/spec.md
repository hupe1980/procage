# Feature Specification: Spawning a caged child on Linux

**Feature Branch**: `008-spawn-linux`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "008-spawn-linux: Tier probe, T1/T2 plans built in the parent, mounts + Landlock + seccomp in-process, grants via rule fds, netns; must implement the data-driven hard-deny classes `secrets`, `trust-handoff`, `persistence` (T1 masks at spawn; T2 gap when a grant covers them) before Linux spawning ships."

## Context

procage lowers a policy to a Linux plan today (feature 003), but nothing
applies it: on Linux the crate cannot spawn a caged child. This feature adds
the Linux spawn backend, the counterpart of the macOS backend (004, 005,
006, 007).

Linux has no single sandbox call. procage combines several kernel features,
chosen by what the host allows, into a **tier**:

- **T1 (isolated)**: user, mount, network, IPC and UTS namespaces, mounts,
  Landlock and seccomp. Needs unprivileged user namespaces.
- **T2 (confined)**: Landlock (ABI 4 or later) and seccomp only. This is
  what a Docker container with default settings or an Ubuntu host that
  restricts user namespaces gives.
- **T3**: neither. procage refuses to spawn; it never runs a child
  unsandboxed.

Everything the child needs is prepared in the parent: the Landlock ruleset
with its rule descriptors, the seccomp filter, the mount list, the uid and
gid maps. The child applies it with system calls only, so no
helper binary and no setuid program is involved.

The three data-driven hard-deny classes from 007 (`secrets`,
`trust-handoff`, `persistence`) must work on Linux before Linux spawning
ships (007 made this a requirement). Landlock cannot deny inside a tree it allows, so on T1 the
existing matches are masked at spawn, and on T2 a policy whose rules would
cover them is refused unless the caller accepts the gap.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A Linux harness spawns a caged child (Priority: P1)

A harness author on Linux prepares a policy and spawns a command with the
same API shape as on macOS: prepare a cage once, spawn many times with
per-spawn grants, get a handle that kills the child tree when dropped.
procage picks the strongest tier the host allows and says which one it
picked.

**Why this priority**: Without it procage does nothing on Linux, and the
0.1.0 promise is "both OSes".

**Independent Test**: In a container with default Docker settings (T2) and
in one with seccomp unconfined (T1), a child with read access to one
directory and write access to another:
- reads the first and writes the second;
- is refused reading a file outside both;
- is refused writing the first;
- cannot open a network socket with `Network::None`;
- is refused `ptrace`, `io_uring_setup`, `bpf` and `unshare`.

**Acceptance Scenarios**:

1. **Given** a policy with read on `R` and write on `W`, **When** the child
   reads `R/f`, writes `W/g`, reads `/srv/secret` and writes `R/h`, **Then**
   only the first two succeed, on both tiers.
2. **Given** `Network::None`, **When** the child opens a TCP socket, **Then**
   it is refused.
3. **Given** any policy, **When** the child calls `ptrace`, `io_uring_setup`,
   `bpf`, `unshare` or `keyctl`, **Then** each is refused with `EPERM`.
4. **Given** a host, **When** the caller asks for the tier, **Then** it gets
   T1 or T2 with the Landlock ABI, matching the container's settings.

---

### User Story 2 - Never silently weaker (Priority: P1)

A policy construct the probed tier cannot enforce is an error at
preparation (a capability gap), unless the caller allowed that degradation
by name. A host without Landlock gets an `Unsupported` error. A step that
fails in the child names the step, and the target never runs.

**Why this priority**: procage's core promise on Linux is no best-effort
mode.

**Independent Test**: On T2, a policy that protects a subtree inside a
writable tree is refused at preparation with a gap naming `fs-protect`;
with that degradation allowed it is prepared and the plan lists it. A
forced failure in a child step is reported with the step name and the
target did not run.

**Acceptance Scenarios**:

1. **Given** T2 and a policy with `Protect` inside a write grant, **When** it
   is prepared, **Then** preparation fails with a gap naming `fs-protect`.
2. **Given** a host without Landlock, **When** a cage is prepared, **Then**
   it fails with `Unsupported` naming the missing feature.
3. **Given** a policy path that does not exist, **When** the child is
   spawned, **Then** spawning fails before any child runs, naming the path.
4. **Given** a failing step in the child, **When** spawning, **Then** the
   error names the step and the target did not run.

---

### User Story 3 - Secrets, trust handoff and persistence hold on Linux (Priority: P1)

The data-driven hard-deny classes from 007 hold on Linux.

- **T1**: existing secret paths in every home are masked (empty and
  inaccessible); existing trust-handoff paths under writable trees are made
  read-only; every existing `.git` directory under a writable tree is
  pinned so it cannot be renamed or removed; persistence locations are made
  read-only.
- **T2**: the classes hold wherever no rule covers them (Landlock denies by
  default). A policy whose rules could reach a class path is a capability
  gap. A grant bound to a path that contains or lies inside a class path is
  refused at spawn.

Paths created after the spawn are not covered on T1. Where a rule could
reach them, the lowering reports the class as an approximation, which the
caller must accept by name.

**Why this priority**: 007 made this a ship blocker for Linux spawning.

**Independent Test**: On T1, with read access to a home that holds `.ssh`
and `.aws`, the child cannot list either and can list the home. With write
access to a workspace with `.git/hooks`, `.vscode` and `.bashrc`, the child
cannot write any of them, cannot rename `.git`, and can write
`.git/objects/x` and `src/x`. On T2, the same workspace policy is refused
with gaps naming `hd-trust-handoff`; a policy that grants nothing in a home
is prepared with the classes exact.

**Acceptance Scenarios**:

1. **Given** T1 and read on home `H` with `H/.ssh` and `H/.aws`, **When** the
   child lists them, **Then** both are refused (empty or inaccessible) and
   listing `H` succeeds.
2. **Given** T1 and write on workspace `W` with `.git/hooks`, `.vscode` and
   `.bashrc`, **When** the child writes into each, **Then** each is refused,
   and writing `W/.git/objects/x` and `W/src/x` succeeds.
3. **Given** the same, **When** the child renames `W/.git`, **Then** it is
   refused.
4. **Given** `trust-handoff` waived, **When** the child writes
   `W/.git/hooks/x`, **Then** it succeeds.
5. **Given** T2 and write on `W`, **When** the policy is prepared, **Then** it
   fails with a gap naming `hd-trust-handoff`; with the class waived by
   name it is prepared and the plan lists the waiver.
6. **Given** T2 and a grant bound to a home directory that holds `.ssh`,
   **When** spawning, **Then** the grant is refused, naming the class.

---

### User Story 4 - Same hygiene as on macOS (Priority: P2)

The child gets the same process hygiene as on macOS (005): its own session
unless `Tty::Inherit`, the policy's environment with the passthrough
denylist, the policy's resource limits with core dumps off, only the
standard descriptors plus those handed over, a private `TMPDIR` with the
`tmpdir` grant, and the whole tree killed when the handle drops. Base
profile V1 lets ordinary programs start.

**Why this priority**: Parity keeps the API honest across OSes, but the
enforcement stories come first.

**Independent Test**: With base V1, `sh -c`, `cat`, `ls`, `env` and the
test binary itself run. A leaked descriptor does not reach the child; one
handed over does. Dropping the handle kills a grandchild. The environment
loses `GITHUB_TOKEN` and `LD_PRELOAD` under passthrough.

**Acceptance Scenarios**:

1. **Given** base V1 only, **When** the child runs `/bin/sh -c 'echo ok'`,
   **Then** it prints `ok`, and reading the caller's home is refused.
2. **Given** a descriptor left open without close-on-exec, **When** spawning,
   **Then** it is closed in the child; a descriptor handed over stays open.
3. **Given** a child that started a grandchild, **When** the handle drops,
   **Then** both are gone.
4. **Given** passthrough, **When** spawning, **Then** `GITHUB_TOKEN`,
   `LD_PRELOAD` and `SSH_AUTH_SOCK` are dropped and listed.
5. **Given** the `tmpdir` grant, **When** spawning, **Then** `TMPDIR` is a
   fresh private directory the child can write, removed on drop.

---

### User Story 5 - T1 isolation that the child cannot undo (Priority: P2)

On T1, a read-only subtree inside a writable tree stays read-only, a hidden
path is empty, the network namespace has no interface up, the child holds
no capabilities, and nothing it does can undo the mounts.

**Why this priority**: These are the T1-only constructs; T2 hosts get gaps
for them instead.

**Independent Test**: On T1, writing into a protected subtree fails with
`EROFS`; listing a hidden directory shows nothing; a socket connect to the
host's loopback fails; the child's effective capability set is empty; an
attempt to unmount or remount fails.

**Acceptance Scenarios**:

1. **Given** T1, write on `W` and `Protect` on `W/p`, **When** the child
   writes `W/p/x`, **Then** it fails with `EROFS`, and `W/x` succeeds.
2. **Given** T1 and `Hide` on `R/h` inside a read rule, **When** the child
   lists `R/h`, **Then** it sees no entries and cannot read `R/h/f`.
3. **Given** T1 and `Network::None`, **When** the child connects to a
   listener on the host's loopback, **Then** it fails.
4. **Given** T1, **When** the child reads its capabilities, **Then** the
   effective, permitted and bounding sets are empty.
5. **Given** T1, **When** the child tries `umount` or a remount, **Then** it
   is refused.

---

### Edge Cases

- **Tier choice**: the strongest available tier wins. A caller can ask for
  T2 explicitly (for parity tests or to avoid user namespaces); asking for
  T1 where it is unavailable is `Unsupported`, never T2.
- **Landlock ABI**: the plan is lowered for the ABI the kernel reports,
  capped at the newest ABI the crate knows. A right the kernel does not
  handle is never assumed.
- **Already restricted caller**: Landlock and seccomp stack, so a caged
  process can cage a child; the child is at least as restricted as its
  parent. No `AlreadySandboxed` error on Linux.
- **Missing paths**: a policy path that does not exist cannot carry a
  Landlock rule; spawning fails naming it. Base V1 system paths that a host
  lacks (`/lib64`) are skipped, as the plan says.
- **Root caller**: a caller running as root still gets a child with no
  capabilities (T1) and `no_new_privs` (both tiers).
- **Architectures**: x86_64 and aarch64. The seccomp filter kills a
  syscall from a foreign architecture (for example the x32 ABI or 32-bit
  compat calls on x86_64).
- **Loopback and proxy networks**: they need a relay between namespaces,
  which is not part of this feature. Both tiers report them as gaps.
- **Unix-socket allowlists below Landlock ABI 9**: masking discovered
  sockets is not part of this feature; they are gaps below ABI 9.
- **Hide on T2**: hiding by allowing siblings is not part of this feature;
  it is a gap on T2.
- **Glob allow rules**: expanding globs at spawn is not part of this
  feature; a glob allow rule is a gap on Linux.
- **Gaps versus approximations**: an approximation can be accepted by
  naming its construct; an unsupported construct cannot. A data class that
  T2 cannot enforce can only be waived by name, which the plan records.
- **PID namespace**: not part of this feature (it needs a reaper and a fresh
  `/proc`). Signal scoping uses Landlock (ABI 6 or later) on both tiers;
  below ABI 6, `signals: self-and-children` is a gap on both tiers.
- **Large writable trees**: finding existing trust-handoff paths and `.git`
  directories walks the writable trees at spawn. The walk is bounded; a
  tree larger than the bound fails the spawn rather than skipping part of
  it.

## Requirements *(mandatory)*

### Functional Requirements

**Tiers and probe**

- **FR-001**: procage MUST probe the host once per process and report the
  tier (T1, T2 or unsupported) with the Landlock ABI and errata. The probe
  MUST run its namespace and mount checks in a throwaway child, never in
  the caller.
- **FR-002**: A cage MUST be prepared for the probed tier, or for a tier the
  caller asks for. Asking for a tier the host cannot give MUST fail with
  `Unsupported`. A host without Landlock ABI 1 (T1) or 4 (T2) MUST get
  `Unsupported`.
- **FR-003**: Preparation MUST lower the policy for the tier and ABI and fail
  on every capability gap the caller did not allow by name.

**Applying the plan**

- **FR-004**: The parent MUST build everything before forking: the Landlock
  ruleset and its rule descriptors, the seccomp filter for the native
  architecture, the mount list, the uid and gid map contents, the resource
  limits and the environment. The child MUST only make system calls.
- **FR-005**: The child sequence MUST be: new session (unless
  `Tty::Inherit`) or new process group → parent-death signal → on T1:
  unshare the user, mount, IPC and UTS namespaces (and network unless the
  policy allows all), map the caller's uid and gid, deny `setgroups`, make
  mounts private, apply the mount list, drop all capabilities → resource
  limits → mark inherited descriptors close-on-exec → `no_new_privs` →
  Landlock → seccomp last → verify → exec.
- **FR-006**: The child MUST verify before exec that seccomp is in filter
  mode and Landlock was applied. A failed step MUST be reported as
  `Apply { step, errno }` and the target MUST NOT run.
- **FR-007**: seccomp denies MUST return `EPERM` (or `ENOSYS` where the plan
  says so, for `clone3`). A syscall from a foreign architecture or ABI MUST
  kill the process.
- **FR-008**: Every syscall the plan names MUST map to its number on the
  native architecture; a name procage cannot map MUST be an `Unsupported`
  error at preparation. A syscall that does not exist on the architecture
  needs no rule.
- **FR-009**: On T1, `Protect` MUST make the path a read-only bind mount and
  `Hide` MUST cover it with an empty, inaccessible mount. Both MUST keep the
  mount flags the kernel locks.
- **FR-010**: On T1, `Network::None` MUST give the child a new network
  namespace. On T2 it MUST deny socket creation through seccomp and handle
  Landlock's network rights.

**Grants and hygiene**

- **FR-011**: Per-spawn grants MUST be Landlock rules on descriptors the
  parent opens for that spawn. An undeclared or reserved grant name, or a
  missing path, MUST fail the spawn before forking.
- **FR-012**: Hygiene MUST match macOS (005): session, environment with the
  passthrough denylist, resource limits with core size 0 by default,
  descriptors above 2 closed except those handed over, private `TMPDIR`
  with the `tmpdir` grant, the child tree killed when the handle drops,
  and a parent-death signal so the child dies with the caller.

**Data-driven hard-deny classes**

- **FR-013**: The policy crate MUST hold frozen Linux lists for the three
  classes. Homes are every directory under `/home` plus `/root`.
  - `secrets`: the 007 list without the macOS `Library/...` entries, plus
    the Linux browser profiles and keyrings (`.mozilla`,
    `.config/google-chrome`, `.config/chromium`, `.config/BraveSoftware`,
    `.config/microsoft-edge`, `.local/share/keyrings`, `.password-store`).
  - `trust-handoff`: the 007 names in any directory, and the 007 home
    paths.
  - `persistence`: `.config/autostart`, `.config/systemd/user` and
    `.local/share/systemd/user` in every home, plus `/etc/cron.d`,
    `/etc/systemd/system`, `/etc/xdg/autostart` and `/var/spool/cron`.
- **FR-014**: The lowering MUST mark a class **exact** when no rule of the
  policy can reach its paths, **approximated** on T1 when one can (existing
  paths are masked at spawn; later ones are not), and **unsupported** on T2
  when one can.
- **FR-015**: On T1 the backend MUST, at spawn, for each class in force:
  - mask every existing secret path in every home;
  - make read-only every existing trust-handoff and persistence path in the
    homes, at the system locations, and under every writable rule or grant;
  - pin every existing `.git` directory under a writable rule or grant, so
    it cannot be renamed or removed.
- **FR-016**: On T2 the backend MUST refuse, at spawn, a grant whose path
  contains or lies inside a path of a class in force, naming the class.
  Waiving the class by name is the only way around it.
- **FR-017**: The walk of writable trees MUST NOT follow symbolic links and
  MUST be bounded; exceeding the bound MUST fail the spawn, naming the
  tree.

**Evidence and docs**

- **FR-018**: Each acceptance scenario MUST be a caged test on a real Linux
  kernel, run on T1 and on T2 where the scenario applies.
- **FR-019**: The lowering table MUST state the Linux outcome of every
  construct as this feature implements it, including the gaps this feature
  leaves (loopback and proxy networks, unix sockets below ABI 9, hide on T2,
  glob allow rules, signals below ABI 6).
- **FR-020**: The crate docs and the threat model MUST describe the Linux
  backend and keep the escape-class statuses unchanged until the escape
  suite (009).

### Key Entities

- **Tier**: T1 or T2, with the Landlock ABI and errata, or unsupported with
  the reason.
- **Cage (Linux)**: a policy lowered for a tier and ABI, with the seccomp
  filter built.
- **Child plan**: what the child applies, all prepared in the parent.
- **Class paths**: per class, the home-relative paths, the names in any
  directory, and the system paths.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On both tiers the child MUST be refused every file access its policy's rules and grants do not allow, and a grant MUST apply only to the spawn it was bound for.
  - Mitigates: `threat.fs-outside-policy` via `mitigation.landlock-ruleset`
  - Given read on R and write on W, on T1 and T2, when the child reads R/f, writes W/g, reads a file outside both and writes R/h, then only the first two succeed
  - Given a grant bound for one spawn, when a second spawn without the binding reads the path, then it is refused
- **SR-002** (P1): The child MUST be refused ptrace, io_uring_setup, bpf, keyctl, perf_event_open, userfaultfd, unshare, mount and the other hard-deny syscalls with EPERM, on both tiers.
  - Mitigates: `threat.foreign-abi-bypass`, `threat.kernel-surface-syscall` via `mitigation.seccomp-hard-deny`
  - Given any policy on T1 and T2, when the child calls ptrace, io_uring_setup, bpf, keyctl, unshare and mount, then each fails with EPERM
- **SR-003** (P1): The seccomp filter MUST kill a syscall made through a foreign architecture or the x32 ABI.
  - Mitigates: `threat.foreign-abi-bypass`, `threat.kernel-surface-syscall` via `mitigation.seccomp-hard-deny`
  - Given the built filter, when it is evaluated for a foreign audit architecture and for an x32 syscall number, then the verdict is kill
- **SR-004** (P1): Preparation MUST fail with a named capability gap for every construct the tier cannot enforce unless that degradation is allowed by name, and MUST fail with Unsupported on a host without the required Landlock ABI or when a tier the host lacks is requested.
  - Mitigates: `threat.silent-downgrade` via `mitigation.tier-gaps`
  - Given T2 and Protect inside a write rule, when the cage is prepared, then it fails with a gap naming fs-protect, and with that degradation allowed the plan lists it
  - Given a host without user namespaces, when T1 is requested, then it fails with Unsupported
- **SR-005** (P1): A failing step in the child MUST be reported as Apply with the step and errno, and the target MUST NOT run; the child MUST verify seccomp filter mode and Landlock before exec.
  - Mitigates: `threat.step-failure-runs-target` via `mitigation.verify-and-step-errors`
  - Given a forced failure in a child step, when spawning, then the error names the step and the target did not run
- **SR-006** (P1): On Linux the secret paths in every home MUST stay unreadable to the child on T1 even under a covering read rule, and on T2 a covering rule or grant MUST be a gap or a refused grant, unless the secrets class is waived by name.
  - Mitigates: `threat.linux-secret-read`, `threat.linux-trust-handoff` via `mitigation.linux-class-masks`
  - Given T1 and read on a home with .ssh and .aws, when the child lists them, then both are refused or empty and listing the home succeeds
  - Given T2 and a grant bound to a home that holds .ssh, when spawning, then the grant is refused naming secrets
- **SR-007** (P1): On T1 the child MUST NOT write existing trust-handoff or persistence paths under writable rules or in homes, nor rename or remove an existing .git, while .git/objects and ordinary files stay writable; on T2 a covering write rule MUST be a gap.
  - Mitigates: `threat.linux-secret-read`, `threat.linux-trust-handoff` via `mitigation.linux-class-masks`
  - Given T1 and write on W with .git/hooks, .vscode and .bashrc, when the child writes each and renames .git, then each is refused and W/.git/objects/x and W/src/x succeed
  - Given T2 and write on W, when the cage is prepared, then it fails with a gap naming hd-trust-handoff, and with the class waived the plan lists the waiver
  - Given trust-handoff waived on T1, when the child writes W/.git/hooks/x, then it succeeds
- **SR-008** (P1): On T1 the child MUST hold no capabilities and MUST NOT undo a mount (umount, remount, new namespace).
  - Mitigates: `threat.mount-undo` via `mitigation.no-caps-locked-mounts`
  - Given T1 with a protected subtree, when the child reads its capability sets and tries umount and a rw remount, then the sets are empty and both calls fail and the subtree stays read-only (EROFS)
- **SR-009** (P1): With Network::None the child MUST NOT reach any socket endpoint on T1 or T2.
  - Mitigates: `threat.network-exfil` via `mitigation.netns-or-socket-deny`
  - Given Network::None and a listener on the host loopback, when the child connects, then it fails on both tiers
- **SR-010** (P2): The Linux child MUST get macOS hygiene parity, with only standard and handed-over descriptors, the denylisted environment dropped, its own session, and the tree killed on drop.
  - Mitigates: `threat.hygiene-leak` via `mitigation.hygiene-parity`
  - Given a leaked descriptor and passthrough env with GITHUB_TOKEN, when spawning, then neither reaches the child and a handed-over descriptor does
  - Given a child with a grandchild, when the handle drops, then both are gone
- **SR-011** (P2): The spawn-time walk MUST NOT follow symbolic links and MUST fail the spawn when a tree exceeds the bound.
  - Mitigates: `threat.walk-shaped-by-earlier-run` via `mitigation.bounded-walk`
  - Given a writable tree with a symlink to a directory outside it, when spawning, then the walk does not enter the target
  - Given a bound lower than the tree size, when spawning, then the spawn fails naming the tree
- **SR-012** (P2): The lowering table MUST state each Linux outcome as the backend applies it, including the gaps this feature leaves, and the docs MUST keep the escape statuses unchanged.
  - Mitigates: `threat.linux-overclaim` via `mitigation.honest-linux-docs`
  - Given the lowering table fixture test, when it runs, then every Linux cell matches the lowering and names the gaps
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the acceptance scenarios pass in a T1 container and a
  T2 container on the local Docker kernel.
- **SC-002**: 0 constructs are weakened without a gap error or an allowed
  degradation recorded in the plan.
- **SC-003**: Spawning a caged `true` takes under 50 ms at the median on
  the local Docker kernel, T1 included.
- **SC-004**: `just ci` stays green on macOS, and the Linux lanes
  (`just linux`) pass in both containers.

## Assumptions

- **Local Linux is Docker Desktop.** Kernel 7.0.14-linuxkit, aarch64,
  Landlock ABI 8. Default settings give T2; seccomp unconfined gives T1
  (both measured by 001). x86_64 is compiled and linted, and runs in the CI
  lanes after a push.
- **No `landlock` or `seccomp` crate.** The rulesets and filters are small
  and already hand-written in the kernel facts; a direct implementation
  keeps the dependency set unchanged and every unsafe block in one module.
- **Probe cache is per process.** The design names a boot-id cache across
  processes; that needs a file, which is left for receipts.
- **The caller's uid and gid inside the namespace.** The child keeps its
  identity, and exec clears its capabilities; procage also drops them
  explicitly, so a root caller is covered.
- **Walk bound.** 200,000 directory entries per spawn by default,
  configurable.

## Out of Scope

- PID namespace and a fresh `/proc` (a later feature), network relays for
  loopback and proxy, unix-socket masking below ABI 9, hide on T2,
  seccomp user notification and violations (M2), cgroups, `Tty::NewPty`
  (022), a cross-platform `Cage` facade (before 0.1.0).
