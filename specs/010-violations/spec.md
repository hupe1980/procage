# Feature Specification: Violations — what the sandbox denied, and why

**Feature Branch**: `010-violations` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "Keep going. Run the full spec kit workflow. We want best-in-class/state-of-the-art." Feature 010-violations (escape class R-17).

## Context

Today a denied operation inside a cage is an `EPERM` the caged program
prints (or swallows). The harness and its user cannot tell which access was
refused, by which rule, or whether the failure came from the sandbox at
all. Every agent harness then guesses from stderr text ("Operation not
permitted") whether to ask for more access.

Research for this spec (measured on macOS 26.6.2, `research.md`):

- The kernel logs every Seatbelt denial of a deny-default profile to the
  unified log (sender `Sandbox`), explicit `deny` rules included (an earlier
  "not logged" observation applied to allow-default profiles only). Each message ends
  with the denying rule's `(with message …)` text.
- The message accepts profile parameters and `string-append`, so one
  compiled profile per run slot can mark every denial with the run's
  identity and the kind of rule that denied it (not granted, a hard-deny
  class, a protect rule, a hide rule, a raw Seatbelt rule).
- `/usr/bin/log stream --style ndjson` delivered 5,001 of 5,001 distinct
  denials from one process in 0.12 s, and 300 of 300 across 300 processes.
  A fence that is itself a denial (a forked child denied one open) arrived
  after every earlier denial in 650 of 650 rounds, also with every CPU busy;
  a `syslog(3)` line from the caller was overtaken 4 times. The stream is ready ~70–120 ms
  after it starts. Identical denials by one process (same operation and
  path) are reported once.
- A plain `log stream` outlives a parent that dies; a `/bin/sh` watchdog
  that reads its standard input ends it.
- Linux reports no Landlock denial to an unprivileged process (Landlock
  audit needs the audit subsystem); seccomp denials can be observed exactly
  through user notification. That is its own feature (034-linux-violations);
  here Linux offers the same API and says that it observes nothing yet.

Prior art: sandbox-runtime and Codex parse stderr or watch the whole log
without attribution per run; none tells which rule denied an access.

## Clarifications

### Session 2026-11-01

- Q: Is reporting on by default? → A: No. A cage opts in
  (`CageOptions::with_violations`), because it starts a helper process
  (`log stream`) on first use and costs one compile per concurrent run
  slot. Without it the profile is byte-for-byte what it is today.
- Q: What identifies a run? → A: The run's slot marker (the per-process
  random prefix plus the slot number, already used for run markers),
  passed as a profile parameter. A slot is given to another run only after
  a fence showed every earlier denial of it was delivered.
- Q: How does the caller read them? → A: `Child::violations()` returns what
  arrived so far; once the child has exited it first waits (bounded) for
  the fence, so the list is complete when it says so. A live receiver
  (`Child::violation_receiver`) yields each violation as it arrives.
- Q: What if the stream cannot start (non-admin account, no `log`)? → A:
  Spawning never fails because of reporting; the record says it is
  unavailable and why.
- Q: Linux in this feature? → A: Same API on both backends (`procage::native`);
  on Linux the record says nothing is observed yet. Exact seccomp
  reporting is feature 034.
- Q: Which kind does a data-class deny report? → A: The class
  (`HardDeny(secrets)` etc.), not `Hide`/`Protect`: the class names why.
- Q: Is the helper binary trusted blindly? → A: No. Before use, `/bin/sh`
  and `/usr/bin/log` must be owned by root, not writable by group or
  others, and on a read-only volume (the sealed system volume); otherwise
  reporting is unavailable.

**Out of scope**: learning mode (moves to 011-explain-receipts);
Linux reporting (034).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - The harness learns what was denied (Priority: P1)

A harness spawns a command in a cage with violations on. The command fails
reading `~/.ssh/id_ed25519` and writing outside the workspace. After the
child exits, the harness lists two violations: the process, the operation,
the path, and why ("hidden by the policy", "not granted").

**Why this priority**: the feature's whole value; turns opaque `EPERM` into
an actionable message.

**Independent Test**: On macOS, a cage with a writable workspace and a
hidden file; the child reads the hidden file and writes outside; the list
has exactly those denials with their kinds, and it is marked complete.

**Acceptance Scenarios**:

1. **Given** a cage with violations on, **When** the child is denied a read
   and a write and has exited, **Then** `violations()` returns both, marked
   complete, each with pid, process name, operation, target and kind.
2. **Given** a cage without violations, **When** the child is denied,
   **Then** no helper runs, the record says reporting is off, and the
   compiled profile equals today's.
3. **Given** two runs at once, **When** each is denied different paths,
   **Then** each lists only its own.

---

### User Story 2 - The reason names the rule (Priority: P1)

Each violation says which kind of rule denied it: not granted (deny
default), a hard-deny class (with its name), a protect rule, a hide rule,
or a raw Seatbelt rule; and it reads as one sentence.

**Why this priority**: "why" decides the fix (grant a path, or accept that
a hard-deny class stays).

**Acceptance Scenarios**:

1. **Given** a write to a protected path, **Then** the kind is protect.
2. **Given** a set-user-id exec, **Then** the kind is the privilege class.
3. **Given** a read of an ungranted path, **Then** the kind is not granted.

---

### User Story 3 - Live and honest (Priority: P2)

A harness can show violations while the command runs, and the record never
pretends to be complete: it says when reporting is unavailable (and why),
when the fence timed out, and when records were dropped at the cap.

**Acceptance Scenarios**:

1. **Given** a running child, **When** it is denied, **Then** the receiver
   yields the violation before the child exits.
2. **Given** the stream cannot start, **Then** spawning succeeds and the
   record is unavailable with the helper's reason.
3. **Given** more denials than the cap, **Then** the record keeps the first
   ones and counts the rest.

### Edge Cases

- A path containing a newline followed by text that looks like another
  run's marker: the violation is attributed by the kernel-written last line
  only, so it stays with the run that caused it.
- The parent dies: the helper ends with it (watchdog).
- The helper dies mid-run: runs in flight are marked incomplete; the next
  spawn starts a new helper.
- `Child::detach`: the run's violations are no longer collected; its slot
  is never reused (as today).
- `Cage::exec`: no handle, so no violations (documented).
- The run-marker probe and the marker deny rule never produce violations.
- Duplicate denials by one process are reported once (kernel behaviour).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `CageOptions::with_violations()` MUST turn reporting on for a
  cage on both backends; without it nothing changes (no helper, identical
  profile).
- **FR-002**: On macOS with reporting on, every deny rule except the
  run-marker block MUST carry a message naming the run's marker and the
  rule's kind (a data class's rules name the class); the policy crate MUST render this from a lowering option.
- **FR-003**: One helper per process MUST run `log stream` with a predicate
  limited to this process's marker prefix and its own fences, behind a
  watchdog that ends it when the process dies; it starts on first need and
  restarts after it dies; it runs only binaries that pass the integrity
  check (root-owned, not group- or world-writable, read-only volume).
- **FR-004**: Each denial MUST be parsed into a `Violation` (pid, process
  name, operation, target, kind, time received) and routed to its run by the exact
  marker on the message's last line; lines that do not parse are ignored.
- **FR-005**: `Child::violations()` MUST return a record: the violations,
  whether it is complete, the coverage (on, off, unavailable with reason,
  not observed on this platform), and how many were dropped at the cap.
  After the child exited, it MUST wait for a fence (bounded) first.
- **FR-006**: A run's slot MUST NOT be freed before a fence passed after
  its last process ended.
- **FR-007**: `Child::violation_receiver()` MUST yield violations as they
  arrive.
- **FR-008**: Linux MUST offer the same API, with coverage "not observed
  on this platform".
- **FR-009**: Caged tests MUST show the stories on macOS; the escape suite
  MUST pass with reporting on; docs (crate, README, THREAT_MODEL) MUST
  describe reporting as best-effort and never as enforcement.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): A violation MUST be attributed only by the exact marker of a live run of this process on the last line of the message; a path containing a newline and another tag MUST stay with the run that caused it.
  - Mitigates: `threat.forged-attribution` via `mitigation.last-line`
  - Given two runs and a path containing a newline followed by the other run's marker, when the first run is denied that path, then the violation is in the first run's record with the full path, and not in the other's
  - Given a message whose last line is no live marker, when it is parsed, then it is ignored
- **SR-002** (P1): A run slot MUST NOT be freed before a fence passed after the run ended.
  - Mitigates: `threat.slot-reuse` via `mitigation.fence-before-free`
  - Given a run denied just before it ends, when its slot is reused by the next run, then the denial is in the first record and not in the second
- **SR-003** (P1): Without reporting the rendered profile MUST equal the lowering fixtures recorded before this feature; with reporting only rule messages MUST differ, the run-marker block MUST carry none, and the escape suite MUST pass with reporting on.
  - Mitigates: `threat.profile-drift` via `mitigation.identical-off`
  - Given every lowering fixture, when rendered with and without reporting, then removing the messages gives the same text, and without reporting it equals the fixture
  - Given the macOS escape suite, when run with reporting on, then every canary still holds
- **SR-004** (P2): A run record MUST keep at most a fixed number of violations and count the rest; the receiver MUST be bounded.
  - Mitigates: `threat.record-flood` via `mitigation.cap`
  - Given more distinct denials than the cap, when the record is read, then it holds the cap and counts the dropped ones
- **SR-005** (P1): A record MUST say complete only after a fence passed after the child exited, and MUST state its coverage (off, unavailable with reason, not observed on this platform); docs MUST call reporting best-effort and diagnostic.
  - Mitigates: `threat.enforcement-claim`, `threat.false-complete` via `mitigation.honest-record`
  - Given a running child, when the record is read, then it is not complete
  - Given a cage without reporting, or Linux, when the record is read, then coverage says off or not observed, never complete with zero violations as a claim
- **SR-006** (P2): The helper MUST run absolute /usr/bin/log under /bin/sh, both passing the integrity check (owned by root, not group- or world-writable, on a read-only volume), with an empty environment and no inherited descriptors, and MUST end when the process that started it dies.
  - Mitigates: `threat.helper-leak` via `mitigation.watchdog`
  - Given a process that started the helper, when it is killed with SIGKILL, then no helper of it remains within a second
  - Given a helper path that fails the integrity check, when the monitor starts, then it runs nothing and coverage is unavailable with the reason
- **SR-007** (P2): Waiting for the helper, a fence or a slot release MUST be bounded; a timeout MUST leave the record incomplete instead of blocking.
  - Mitigates: `threat.wait-hang` via `mitigation.bounded-waits`
  - Given a helper that never answers, when violations() is called after exit, then it returns within the limit, incomplete
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: In the caged tests, 100 % of the induced denials appear in
  the record, with the right kind, and the record is complete.
- **SC-002**: With reporting off, the compiled profiles of every existing
  test policy are byte-identical to today's.
- **SC-003**: The first spawn with reporting on waits at most 2 s for the
  helper (measured ~0.1 s); `violations()` after exit returns within 1 s
  (measured fence ~2–6 ms).
- **SC-004**: `just ci`, `just linux` and `just linux-t1` pass.

## Assumptions

- The unified log keeps its message format (`Sandbox: <name>(<pid>)
  deny(<n>) <operation> <target>` followed by the rule's message); a kernel
  fact test pins it on every macOS lane.
- `log stream` works for administrator accounts (measured) and in CI VMs
  (to be measured on the CI lane); non-administrator accounts are reported
  as unavailable; the account question stays open until measured.
- Reporting is diagnostic. Enforcement never depends on it.
