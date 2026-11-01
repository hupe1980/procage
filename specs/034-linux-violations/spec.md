# Feature Specification: Linux violations — exact reports of refused system calls

**Feature Branch**: `034-linux-violations` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: User description: "Keep going. Run the full spec kit workflow, include analyze. We want best-in-class/state-of-the-art." Follows 010-violations (macOS reporting).

## Context

010 gave macOS a violation record per run. On Linux, `Child::violations`
returns an empty record with coverage `NotObserved`. Two kinds of denial
exist on Linux:

- **Landlock** (files, TCP ports, signals, abstract sockets) returns
  `EACCES`/`EPERM` and reports only to the audit subsystem (ABI 7+), which an
  unprivileged process cannot read.
- **seccomp** (the system calls procage refuses: hard-deny classes such as
  `ptrace`, `io_uring_setup`, `bpf`, namespace creation and socket families;
  network without a grant; forking without a grant; `setsid`/`setpgid` under
  `Lifetime::Run`; the truncation guard below Landlock ABI 3; a raw layer)
  returns `EPERM`.

Research for this spec (`research.md`):

- seccomp user notification (`SECCOMP_RET_USER_NOTIF`, Linux 5.0; listener
  `POLLHUP` once no process uses the filter, 5.8) lets a supervisor receive
  each refused call (pid, number, arguments) and answer it. The caller's
  minimum kernel is 5.13 (Landlock ABI 1), so both are always there.
- A refused call **blocks until the supervisor answers**, so the record is
  exact and complete without timing assumptions: when the listener hangs up,
  every refused call of the run has been answered and recorded.
- No privilege is needed: the filter is installed with `no_new_privs`, which
  procage already sets. The listener is created close-on-exec in the child
  and passed to the parent over a socket pair before `execve`.
- A task's filter chain can hold only one listener: inside a sandbox that
  already uses notification, installing with a listener fails (`EBUSY`), and
  procage falls back to answering with `EPERM` in the kernel, recording why.
- If the supervisor is gone, the kernel answers `ENOSYS` instead: the call
  stays refused.
- `libc` 0.2.191 has the constants and structures.

Prior art: container runtimes (LXD, Sysbox, crun's notify hook) use user
notification to emulate calls; no process sandbox for agents reports refused
calls to its caller with the rule behind them.

## Clarifications

### Session 2026-11-01

- Q: Which denials are reported? → A: Every call the seccomp filter refuses
  with `EPERM`. `ENOSYS` answers (`clone3`, `openat2`, which make libc fall
  back to calls the filter can inspect) are not denials and are not
  reported. Landlock denials stay unreported; the record says so.
- Q: How does the record state that? → A: A new coverage,
  `Coverage::SystemCalls`: refused system calls are reported exactly; file
  and network denials are not.
- Q: What does a violation name? → A: The process (pid and name), the system
  call as its name (`ptrace`), a target where the arguments name one (socket
  family, ioctl command, clone flags), and why: the hard-deny class, not
  granted, the lifetime lock (`Lifetime::Run`), the older-kernel truncation
  guard, or the raw layer.
- Q: Is the answer to the caged process unchanged? → A: Yes: `EPERM`, as
  without reporting. Without the option the filter is the same as today.
- Q: What about `Cage::exec`? → A: No handle, no supervisor: the kernel
  answers with `EPERM` as today.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The harness learns which system call was refused (Priority: P1)

A harness runs a build tool on Linux with violations on. The tool fails with
`Operation not permitted`. The record lists `io_uring_setup` refused by the
kernel-surface class, and `socket` (AF_INET) refused because the policy has
no network.

**Independent Test**: In Docker (T2 and T1), a child calls `ptrace`, opens
an IP socket and calls `setsid`; the record has the three, each with its
reason, and is complete after the child exits.

**Acceptance Scenarios**:

1. **Given** a reporting cage, **When** the child is refused three calls and
   exits, **Then** `violations()` lists them with pid, process name,
   operation, target and reason, and is complete.
2. **Given** a cage without reporting, **Then** coverage is `Off` and the
   filter is unchanged.
3. **Given** two runs at once, **Then** each lists only its own calls.

---

### User Story 2 - The caged process sees no difference (Priority: P1)

The refused call fails with `EPERM` exactly as before, for the child and its
descendants; nothing else changes in what the cage allows.

**Acceptance Scenarios**:

1. **Given** reporting on, **When** the Linux escape suite runs, **Then**
   every canary holds.
2. **Given** a refused call, **Then** it returns `EPERM`.

---

### User Story 3 - Honest coverage on every host (Priority: P2)

The record says `SystemCalls` when the supervisor runs, `Unavailable` with
the reason when notification could not be set up (spawning still works,
with refusals answered by the kernel), and stays incomplete while any
process of the run is alive.

**Acceptance Scenarios**:

1. **Given** a running child, **Then** the record is not complete.
2. **Given** a descendant that outlives the child, **When** `kill_all`
   ends it, **Then** the record becomes complete.
3. **Given** a filter that cannot take a listener, **Then** the spawn
   succeeds and coverage is `Unavailable` with the reason.

### Edge Cases

- The harness stops reading: the supervisor answers regardless, and the
  record keeps at most 10,000 violations (as on macOS).
- The harness process dies: the kernel answers `ENOSYS`; still refused.
- A flood of refused calls: each is answered at once; the cap bounds memory.
- `Child::detach`: the supervisor keeps answering until the run's processes
  are gone, so detached processes never block.
- A process that receives a signal while blocked in a refused call: the
  kernel withdraws the notification; answering a withdrawn one fails
  harmlessly.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: With `CageOptions::with_violations`, Linux spawns MUST install
  the filter with a listener, every `EPERM` rule answered by the supervisor
  with `EPERM`; `ENOSYS` rules unchanged. Without it the filter MUST be
  identical to today's.
- **FR-002**: The child MUST pass the listener to the parent before `execve`
  and keep no copy; if the listener cannot be created, it MUST install the
  plain filter and report why.
- **FR-003**: One supervisor per run MUST answer every notification with
  `EPERM` and record a `Violation` (pid, name, system call, target, reason),
  until the listener hangs up.
- **FR-004**: The policy crate MUST record why each seccomp rule refuses
  (class, not granted, lifetime, older kernel, layer), and evaluate a rule's
  condition on given arguments exactly as the filter does.
- **FR-005**: The record MUST be complete only after the listener hung up and
  the child was reaped; coverage MUST be `SystemCalls`, `Unavailable(reason)`
  or `Off`.
- **FR-006**: Kernel fact KF-L15 MUST pin the notification protocol: the
  listener, the answer, `POLLHUP` once the filter is unused, and `EBUSY` for
  a second listener in one chain.
- **FR-007**: Docs (crate, site, README, THREAT_MODEL) MUST describe what
  Linux reports and what it does not.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): No process of the run MUST hold or be able to open the seccomp listener: the child closes it before execve, and a caged process scanning its descriptors and the parent's /proc entries MUST find none it can use.
  - Mitigates: `threat.listener-hijack` via `mitigation.no-copy`
  - Given a reporting run on T1 and T2, when the caged process lists its descriptors and tries to open the parent's listener through /proc, then it holds no seccomp listener and the open fails
- **SR-002** (P1): The supervisor MUST answer every notification with EPERM (value 0, no flags) before recording it, and MUST keep answering until the listener hangs up, also after detach.
  - Mitigates: `threat.blocked-run`, `threat.continue-answer`, `threat.record-flood` via `mitigation.eperm-only`, `mitigation.cap-answer-first`
  - Given a reporting run, when the child makes a refused call, then it fails with EPERM and the record lists it
  - Given a detached run, when its process makes a refused call, then the call returns EPERM instead of blocking
- **SR-003** (P1): Without reporting the filter MUST be byte-identical to today's; with it only the verdict of EPERM rules MUST differ, and the Linux escape suite MUST pass with reporting on.
  - Mitigates: `threat.filter-drift` via `mitigation.verdict-only`
  - Given every reference policy and target, when the filter is built with and without notification, then they differ only in EPERM verdicts, and without it equals the plain builder
  - Given the Linux escape suite, when run with reporting on, T1 and T2, then every canary holds
- **SR-004** (P1): If the listener cannot be created the child MUST install the plain filter before execve and the record MUST say Unavailable with the reason; no run MUST exec without a filter.
  - Mitigates: `threat.unfiltered-fallback` via `mitigation.plain-fallback`
  - Given an outer filter that already has a listener, when a reporting cage spawns, then the child is confined, its refused calls fail with EPERM, and coverage is Unavailable naming EBUSY
- **SR-005** (P2): A violation's reason MUST be the reason of the first rule whose condition matches, evaluated as the filter does, and its process name MUST be dropped if the notification is no longer valid.
  - Mitigates: `threat.wrong-reason` via `mitigation.same-oracle`
  - Given generated arguments for every condition, when matches() and the BPF interpreter evaluate them, then they agree
  - Given a refused socket, setsid and ptrace, when they are recorded, then the reasons are not granted, lifetime and the process-access class
- **SR-006** (P2): The record MUST keep at most 10,000 violations and count the rest; answering MUST NOT wait on the harness.
  - Mitigates: `threat.blocked-run`, `threat.record-flood` via `mitigation.cap-answer-first`
  - Given a child making 20,000 refused calls, when it runs, then every call returns EPERM promptly and the record holds the cap with the rest counted
- **SR-007** (P1): A Linux record MUST be complete only after the listener hung up and the child was reaped, and its coverage MUST be SystemCalls, Unavailable or Off; docs MUST say Landlock denials are not reported.
  - Mitigates: `threat.false-complete` via `mitigation.hup-complete`
  - Given a running child or a surviving descendant, when the record is read, then it is not complete
  - Given the run ended by kill_all, when the record is read, then it is complete with coverage SystemCalls
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: In Docker T1 and T2, 100 % of the induced refused calls appear
  with the right reason, and the record is complete after `kill_all`.
- **SC-002**: Without reporting, the filter of every reference policy is
  byte-identical to today's; with it, only the verdict of `EPERM` rules
  differs.
- **SC-003**: The median of 20 refused calls returns within 10 ms (the
  supervisor answers immediately).
- **SC-004**: `just ci`, `just linux`, `just linux-t1`, `just kf-linux`,
  `just kf-linux-t1` pass.

## Assumptions

- Linux 5.13 or later (procage's minimum), where user notification and the
  listener's `POLLHUP` exist.
- The Docker lanes' default seccomp profile allows `seccomp(2)` with a
  listener (verified by KF-L15).
