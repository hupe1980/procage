# Feature Specification: Older Linux kernels — honest confinement from Landlock ABI 1

**Feature Branch**: `030-older-kernels` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "Keep going. Research it. We want a great DX." Need reported by a consumer harness: tier T2 needs Landlock ABI 4 (Linux 6.7), and the consumer's hosts ran ABI 3.

## Context

procage's Linux tier T2 (Landlock and seccomp, no user namespaces: Docker's
defaults, Ubuntu 23.10+ with AppArmor's restriction) refuses kernels below
Landlock ABI 4. ABI 4 adds TCP port rules, but with the network off T2
already denies creating IP sockets with seccomp, so the TCP rules only
repeat that. Research for this spec found three things that matter more:

1. **Truncation escape below ABI 3 (tier T1 today).** Landlock cannot deny
   truncation before ABI 3. Measured on Linux 7.0 with rulesets that handle
   only the ABI 1 or ABI 2 rights (what such a kernel enforces): with `/`
   readable and one directory writable, `truncate(path)`,
   `open(O_RDONLY | O_TRUNC)` and `open(3 | O_TRUNC)` each cut a file outside
   the writable directory to zero bytes; `open(O_WRONLY | O_TRUNC)` is
   refused; with ABI 3 rights all four are refused. Tier T1 accepts ABI 1
   and protects only `Protect` paths with read-only mounts, so on Debian 12
   (Linux 6.1, ABI 2) or Ubuntu 22.04 (5.15, ABI 1) with user namespaces a
   caged program can empty any file of the user that the policy lets it
   read.
2. **Signals.** `Signals::SelfAndChildren` needs Landlock's signal scope
   (ABI 6, Linux 6.12) and is a capability gap below it, on both tiers. Most
   agent and build policies need it (shells, `make`, test runners signal
   their children), so in practice they need ABI 6, not 4: Ubuntu 24.04 with
   its original 6.8 kernel (ABI 4) gets no sandbox. There is no rule that
   comes close below ABI 6 (a user namespace does not stop signals to the
   user's other processes), and no policy value lets a caller accept
   unscoped signals knowingly.
3. **No way to try an older kernel.** Every test host runs a new kernel
   (Docker Desktop 7.0, ABI 8; GitHub's Ubuntu image 6.17, ABI 7), so a
   consumer cannot see what its policy gets on an older one until a user
   reports it.

## Clarifications

### Session 2026-11-01

- Q: Is the truncation guard below ABI 3 an approximation callers must opt
  into? → A: No. It refuses more than the policy asks (truncating a file by
  path, or opening one with `O_TRUNC` without write access, fails everywhere,
  also inside writable paths), never less, like procage's refusal of
  cross-directory renames. It is documented, not a capability gap.
- Q: What is T2's lowest ABI? → A: 1, the same as T1. Constructs that need a
  newer ABI stay gaps as the lowering table states.
- Q: How does a caller accept unscoped signals on a kernel below ABI 6? →
  A: A new policy value, `Signals::SameUser`: the child may signal every
  process the operating system lets it (on Linux, the user's processes),
  except where a hard-deny class says otherwise. It is exact on every target.
  `SelfAndChildren` is never widened silently; below ABI 6 it stays a gap.
- Q: How does a developer try an older kernel? → A: A cage option that caps
  the Landlock ABI procage uses (`with_landlock_abi`). The plan is lowered for
  the capped ABI, so gaps and the plan say what is enforced. The cap never
  raises the ABI above what the kernel reports. It also lets a fleet run one
  plan on every host.
- Q: Is a PID namespace (exact signal scope on T1 below ABI 6) part of this
  row? → A: No; it needs a reaper and a fresh `/proc`. Recorded as
  a follow-up.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Nothing outside the writable paths can be emptied (Priority: P1)

A harness cages untrusted code on a kernel with Landlock ABI 1 or 2. The
code tries to truncate a readable file outside the writable paths by every
route the kernel offers. Each attempt fails and the file keeps its content.

**Why this priority**: It is an integrity escape in tier T1 today.

**Independent Test**: On both tiers with the ABI capped at 1, 2 and 3, the
child tries `truncate(path)`, `open(O_RDONLY | O_TRUNC)`,
`open(3 | O_TRUNC)` and `openat2` with `O_TRUNC` on a file outside the
writable paths; every attempt fails and the file's size is unchanged.

**Acceptance Scenarios**:

1. **Given** ABI 1 or 2 and `/` readable, **When** the child calls
   `truncate` on a file outside the writable paths, **Then** it fails and the
   file is unchanged.
2. **Given** ABI 1 or 2, **When** the child opens such a file with
   `O_TRUNC` and read-only or no access mode, **Then** the open fails.
3. **Given** ABI 1 or 2, **When** the child writes a file inside the
   writable path with `>` (open for writing with `O_TRUNC`) or truncates it
   through an open descriptor, **Then** it succeeds.
4. **Given** the guard removed (negative control), **When** scenario 1 runs,
   **Then** the test fails.

---

### User Story 2 - Tier T2 runs on kernels from ABI 1 (Priority: P1)

A harness in a Docker container on an older host kernel (or on Ubuntu
23.10 with AppArmor's restriction, ABI 3) gets tier T2 instead of no
sandbox, with the network off, writes confined and the hard-deny classes in
force.

**Why this priority**: a consumer harness hit this on ABI 3; containers on
older hosts are a common CI setup.

**Independent Test**: On T2 with the ABI capped at 1, 2, 3 and 5, a policy
with a writable workspace and the network off spawns; writes outside the
workspace, TCP and UDP sockets and the hard-deny syscalls are refused.

**Acceptance Scenarios**:

1. **Given** T2 and ABI 3, **When** a policy with signals `None` is caged,
   **Then** it spawns, writes stay in the workspace and `socket(AF_INET)`
   fails.
2. **Given** T2 and ABI 1, **When** the probe runs on such a kernel,
   **Then** it reports tier T2, not unsupported.
3. **Given** a kernel without Landlock, **When** a cage is built, **Then** it
   is refused as before.

---

### User Story 3 - A caller chooses unscoped signals knowingly (Priority: P2)

A harness whose commands need to signal their children runs on a kernel
below ABI 6. procage reports `signals-self-and-children` as a gap; the
harness switches the policy to `Signals::SameUser`, tells its user, and the
commands run.

**Why this priority**: Without it, every forking policy needs ABI 6.

**Independent Test**: With the ABI capped at 5, `SelfAndChildren` is a gap;
`SameUser` spawns, and the child can signal a process of the same user
started outside the cage. With ABI 6+, `SelfAndChildren` refuses that signal.

**Acceptance Scenarios**:

1. **Given** ABI 5 and `SelfAndChildren`, **When** the cage is built,
   **Then** lowering returns a gap naming `signals-self-and-children`.
2. **Given** `SameUser`, **When** the child signals a process of the same
   user outside the cage, **Then** the signal is delivered (Linux).
3. **Given** `SameUser` on macOS, **When** the child signals a process
   outside its sandbox, **Then** the hard-deny class still refuses it
   unless waived.

---

### User Story 4 - A developer tries an older kernel on a new one (Priority: P2)

A developer caps the Landlock ABI in the cage options and sees, on their own
machine or CI, the gaps and behaviour their policy gets on an older kernel.

**Why this priority**: DX; turns kernel reports into tests.

**Independent Test**: A cap of 3 on an ABI 8 kernel gives the same plan as
lowering for ABI 3, the cage reports ABI 3, and a cap above the kernel's ABI
is clamped to it.

**Acceptance Scenarios**:

1. **Given** a cap of 5, **When** a policy with `SelfAndChildren` is caged,
   **Then** the result is the gap the policy gets on an ABI 5 kernel.
2. **Given** a cap of 12 on an ABI 8 kernel, **When** the cage is built,
   **Then** it uses ABI 8.
3. **Given** a cap of 0, **When** the cage is built, **Then** it is refused as
   a kernel without Landlock.

### Edge Cases

- `openat2` carries its flags in a structure seccomp cannot read: below
  ABI 3 it fails with `ENOSYS`, so callers fall back to `openat`, which is
  checked.
- A program that truncates a workspace file by path (`truncate(2)`, Go's
  `os.Truncate`) fails below ABI 3; opening it for writing and truncating
  the descriptor works. Documented.
- Truncation through `io_uring` is already impossible (io_uring is a
  hard-deny syscall).
- An IP socket the caller passes in on purpose can still connect on T2
  below ABI 4 (no TCP rules); procage never passes one itself. Documented.
- The cap below a tier's minimum is refused like a kernel at that ABI.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Below Landlock ABI 3, on both tiers, the plan MUST refuse
  `truncate` by path, `open`/`openat` with `O_TRUNC` unless the access mode
  is write-only or read-write, and `openat2` (with `ENOSYS`); from ABI 3 it
  MUST NOT add these refusals.
- **FR-002**: Tier T2 MUST accept Landlock ABI 1 and later; the probe MUST
  report T2 on such kernels when user namespaces are unavailable.
- **FR-003**: `Signals::SameUser` MUST exist (serde `same-user`), lower
  exactly on every target (Linux: no signal scope and no signal syscall
  denies; macOS: signals allowed, the hard-deny class still applies), and
  MUST NOT be chosen by procage on its own.
- **FR-004**: `CageOptions::with_landlock_abi(n)` MUST cap the ABI used for
  lowering and enforcement at `min(n, kernel ABI)`; a cap below the tier's
  minimum MUST be refused as an unsupported kernel; `Cage` MUST report the
  ABI it uses.
- **FR-005**: Caged tests MUST run the user stories on T1 and T2 at capped
  ABIs 1, 2, 3, 5 and the kernel's own, including a negative control for the
  truncation guard.
- **FR-006**: The docs MUST give a per-ABI table (what each ABI adds, which
  common kernels have it, and what changes for a policy), the truncation
  guard, `SameUser` and the cap; the lowering table MUST state T2's new
  minimum and the `signals-same-user` row.
- **FR-007**: The escape-class catalog and threat model MUST record the
  truncation escape and its fix.

### Key Entities

- **Landlock ABI cap**: a cage option.
- **Signals::SameUser**: a policy value.
- **Truncation guard**: seccomp refusals in the plan below ABI 3.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Below Landlock ABI 3, on both tiers, caged code MUST NOT be able to truncate a file outside the writable paths by truncate(2), open or openat with O_TRUNC, or openat2.
  - Mitigates: `threat.truncation-below-abi3` via `mitigation.truncation-guard`
  - Given T1 or T2 with the ABI capped at 1 or 2 and / readable, when the child tries each truncation route on a file outside the writable paths, then each fails and the file keeps its size
  - Given the same cage, when the child writes a workspace file with > and truncates it through a write descriptor, then both succeed
- **SR-002** (P1): Tier T2 at Landlock ABI 1 to 3 MUST keep writes inside the writable paths, refuse IP sockets with the network off and refuse the hard-deny syscalls.
  - Mitigates: `threat.t2-weaker-on-old-abi` via `mitigation.abi-matrix`
  - Given T2 with the ABI capped at 1, 2, 3 and 5 and a writable workspace, when the child writes outside, opens an AF_INET socket and calls ptrace, then each fails
- **SR-003** (P1): procage MUST NOT widen Signals::SelfAndChildren on its own: below ABI 6 it MUST be a capability gap; only Signals::SameUser, chosen by the caller, lets signals reach the user's other processes.
  - Mitigates: `threat.unscoped-signals` via `mitigation.explicit-same-user`
  - Given the ABI capped at 5 and SelfAndChildren, when the cage is built, then it fails with a gap naming signals-self-and-children
  - Given the kernel ABI (6 or later) and SelfAndChildren, when the child signals a process outside the cage, then the signal is refused
- **SR-004** (P1): The Landlock ABI cap MUST NOT raise the ABI above the kernel's, and lowering and enforcement MUST use the same capped ABI, reported by the cage.
  - Mitigates: `threat.cap-raises-abi` via `mitigation.cap-is-min`
  - Given a cap above the kernel ABI, when the cage is built, then it reports the kernel ABI
  - Given a cap of 0, when the cage is built, then it is refused as a kernel without Landlock
- **SR-005** (P2): The docs MUST state, per Landlock ABI, what a policy gets, including the truncation guard's side effect, unscoped signals below ABI 6 and passed IP sockets on T2 below ABI 4.
  - Mitigates: `threat.overclaimed-old-kernels` via `mitigation.abi-docs`
  - Given the Linux docs, the lowering table and the threat model, when read for a kernel below ABI 6, then each limit is stated
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: At capped ABIs 1 and 2, zero of four truncation routes change
  a file outside the writable paths, on both tiers (today: three of four).
- **SC-002**: Tier T2 is available from ABI 1 (today: 4), covering kernels
  from Linux 5.13.
- **SC-003**: A forking policy runs on ABI 1–5 kernels with one explicit
  policy change (`SameUser`), instead of not at all.
- **SC-004**: `just ci`, `just linux` and `just linux-t1` pass.

## Assumptions

- A ruleset that handles only an older ABI's rights is enforced by a new
  kernel exactly as an older kernel enforces it (Landlock's compatibility
  contract: unhandled rights are allowed; cross-directory renames are always
  refused while `REFER` is unhandled or ungranted). Verified for truncation
  on Linux 7.0; no older kernel is available here.
- x86_64 and aarch64 only, as today.
