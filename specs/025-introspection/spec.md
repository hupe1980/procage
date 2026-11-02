# Feature Specification: Other processes stay opaque

**Feature Branch**: `025-introspection` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented (2026-11-02)

**Input**: A caged child can read the command lines and environments of the user's other processes (R-25, partial). Command lines and environments routinely hold tokens. On macOS the `KERN_PROCARGS2` sysctl returns them for any same-user process; on Linux, a granted `/proc` exposes `cmdline` (and on tier T2 more).

## Context

At 0.1.0:

- **macOS**: `process-info*` is allowed only for the same sandbox, but the
  numeric `KERN_PROCARGS2` sysctl is not mediated by that rule. A measurement
  on macOS 26.6.2 (25G83, 2026-11-01/02) found:
  - a deny-default profile that says nothing about it lets the read through;
  - `(deny process-info* (target others))` does not stop it;
  - the read passes if either `sysctl-read` or `process-info-pidinfo` allows
    it, and the default deny does not count for either: only explicit rules
    hold it;
  - an exact `(sysctl-name "kern.procargs2")` filter does not match the
    numeric call; a `(sysctl-name-prefix "kern.procargs")` filter does;
  - an explicit unfiltered `(deny process-info-pidinfo)` followed by an allow
    for `(target same-sandbox)` refuses other processes and keeps the run's
    own processes readable;
  - Seatbelt does not log `sysctl-read` denials.
  The base profiles allow `sysctl-read` without a filter; the `process-access`
  hard-deny class (in every policy unless waived) did not cover the query.
- **Linux T1**: the child has its own user and mount namespaces but shares the
  PID namespace; `/proc` shows every process of the user.
- **Linux T2**: no namespaces; Landlock's ptrace scoping protects `environ`
  but `cmdline` is world-readable through `/proc`.

## Clarifications

### Session 2026-11-01

- Q: macOS fix by a new base version? → A: *(Superseded by Session
  2026-11-02, no release users yet.)* Yes, if the base program set passes
  with a named sysctl allowlist: a new frozen base version (V4) with the
  allowlist and the pidinfo rule; V1–V3 stay as they are, and the docs say
  which base closes R-25 on macOS.
- Q: Linux T1 — PID namespace? → A: *(Superseded by Session 2026-11-02,
  after measurement.)* Yes: the child gets a new PID namespace and a fresh
  `/proc`, so other processes are invisible; the run's own descendants stay
  visible to each other. The lifetime rules (the whole run is killed) must
  keep holding.
- Q: Linux T2? → A: Hiding `/proc/<pid>` of others is not expressible; the
  docs state the residual (command lines readable), and a policy that grants
  `/proc` on T2 is an approximation by name.

### Session 2026-11-02 (after measurement and threat modelling)

- Q: Linux T1 — PID namespace after all? → A: Not in this change. A child in
  its own PID namespace is its PID 1: it ignores signals it has no handler
  for (a caller's SIGTERM does nothing) and inherits every orphan to reap, so
  procage would need an init process between the caller and the target —
  three processes per run and a new class of lifetime bugs. The default is
  already safe: the base grants no `/proc`. So a rule that lets the child
  read other processes under `/proc` becomes an approximation the caller
  accepts by name on both tiers (construct `proc-other-processes`); a PID
  namespace waits for a consumer that needs `/proc` and other processes
  hidden at once.
- Q: The macOS rule, as measured? → A: *(The allowlist part is superseded by
  the next session.)* The read of another process's arguments passes if
  either `sysctl-read` or `process-info-pidinfo` allows it, and only
  unfiltered rules match it. Base V4 = V3 with `(allow sysctl-read)` replaced
  by an explicit `(deny sysctl-read)` and an allowlist that never covers the
  procargs names, plus `(deny process-info-pidinfo)` with self and children
  allowed again.
- Q: Do the presets move to V4? → A: *(Superseded by the next session.)* New
  preset versions (v4) on base V4; v1–v3 stay as they are (frozen); the docs
  recommend v4.

### Session 2026-11-02 (no release users yet)

- Q: A new base V4 and presets v4, or fix in place? → A: In place, in the
  `process-access` hard-deny class of every policy: it applies to every base
  (V1–V3) and every preset version (v1–v3). No release users depend on the
  V1–V3 behaviour yet, and a frozen preset may only tighten, which this does.
  There is no base V4, no presets v4 and no sysctl allowlist; waiving
  `HardDenyClass::ProcessAccess` lifts the rule (the migration for a process
  monitor).
- Q: Which rule, then? → A: The measured narrow rule replaces the allowlist:
  `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))` (covers
  `kern.procargs` and `kern.procargs2`; a prefix matches the numeric call, an
  exact name does not), a quiet early unfiltered `(deny process-info-pidinfo
  (with no-report))`, and `(allow process-info-pidinfo (target
  same-sandbox))`. Same-sandbox rather than self and children keeps every
  process of the run readable, `sysctl-read` stays allowed otherwise, so the
  program set is unaffected.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - On macOS a caged child cannot read other command lines (Priority: P1)

**Why this priority**: tokens in command lines and environments of the user's
editor, agent or shell are the easiest secrets to steal on macOS today.

**Independent Test**: The R-25 canary, on the default policy, reads the
caller's `KERN_PROCARGS2`, `KERN_PROCARGS` and pidinfo by numeric call
(refused), its own and its own child's (readable), and, with `process-access`
waived, the caller's again (readable, the control).

**Acceptance Scenarios**:

1. **Given** any base (V1–V3) and the class in force, **When** the child
   reads another process's arguments or process information, **Then** it gets
   EPERM.
2. **Given** the class in force, **When** the child reads its own or its
   child's arguments and process information, **Then** they are readable.
3. **Given** the base program set (shells, compilers, package managers, the
   developer tools), **When** it runs with the class in force, **Then** every
   program works as before.
4. **Given** `ps` or `pgrep` in a cage, **Then** the limit is documented
   (`ps` is setuid, and the privilege class refuses setuid execution in any
   cage; `pgrep` relies on `sysmond`, which the base does not reach).
5. **Given** `process-access` waived, **Then** other processes are readable
   again.

---

### User Story 2 - On Linux other processes stay out of reach by default (Priority: P1)

**Independent Test**: The Linux canary reads another process's `cmdline`
and `environ` from a child on the default policy (refused: no `/proc`), and
makes a cage whose rule reaches `/proc` (refused, naming
`proc-other-processes`, unless accepted by name); a rule on a symbolic link
to `/proc` and a grant bound to one are refused the same way.

**Acceptance Scenarios**:

1. **Given** the base and no `/proc` rule, **When** the child reads another
   process's command line or environment, **Then** it is denied.
2. **Given** a rule reaching `/proc` (literally, through `/`, through a
   symbolic link, as a raw Landlock rule or a glob), **When** the cage is
   made without the approximation accepted, **Then** it is refused, naming the
   construct.
3. **Given** a grant bound at spawn to a path that reaches `/proc`, **When**
   the approximation is not accepted, **Then** the spawn is refused, naming
   the construct.
4. **Given** the approximation accepted, **Then** the cage is made and the
   approximation is listed in the plan (rules) or the run's receipt (grants),
   and the receipt is not enforced as written.

---

### User Story 3 - The record says what stays open (Priority: P2)

**Acceptance Scenarios**:

1. **Given** Linux with `proc-other-processes` accepted, **Then** the docs and
   the threat model state that other processes' command lines are readable
   and their environment is not.
2. **Given** the CHANGELOG, **Then** it carries the migration for both
   behaviour changes (macOS: waive `process-access`; Linux: allow
   `proc-other-processes`).

### Edge Cases

- A program of the base program set that reads another process's arguments
  or information: none found; the run's own processes stay readable because
  the allow is same-sandbox, not self and children.
- `ps` is setuid and refused in any cage (the privilege class's setuid-exec
  deny, tested with `sudo` in the spawn tests); `pgrep` relies on `sysmond`,
  which the base does not reach (observed 2026-11-02 on macOS 26.6.2). Both
  are documented limits; no canary runs either tool.
- The run's own violation reporting on macOS (it reads the log, in the
  parent): unaffected. Seatbelt does not log `sysctl-read` denials, so the
  refusal shows only as EPERM.
- Linux: a path with a `..` component is refused by the path type; a rule on
  a symbolic link is resolved at cage creation, a grant at spawn.
- No PID namespace (PID 1 semantics need an init; deferred).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: On macOS the `process-access` hard-deny class MUST refuse
  `KERN_PROCARGS` and `KERN_PROCARGS2` and the process information (pidinfo)
  of processes outside the run, on every base, while the run's own processes
  stay readable; waiving the class MUST lift it.
- **FR-002**: The preset profiles (v1–v3) MUST change only by these rules,
  pinned by their fixtures, and the base program set MUST keep working on
  V1–V3 (macOS 26; macOS 27 re-measured on its lane when it exists).
- **FR-003**: On Linux (both tiers), a rule or grant that lets the child read
  other processes' entries under `/proc` MUST be an approximation the caller
  accepts by name (construct `proc-other-processes`); without it the cage or
  the spawn is refused, naming the rule. The base and the presets grant no
  `/proc`.
- **FR-004**: The threat model MUST state the Linux residual: with the
  approximation accepted, other processes' command lines are readable.
- **FR-005**: The R-25 canaries MUST be non-ignored on macOS (default policy)
  and on Linux (the default without `/proc`, the refusal, the link and the
  grant), and the threat model MUST give R-25's per-platform status.

### Key Entities

- **Process-access class**: the three Seatbelt rules the class adds on
  every base (prefix deny of the argument sysctls, early pidinfo deny,
  same-sandbox pidinfo allow).
- **Preset fixtures**: the frozen preset profiles v1–v3, each three lines
  longer.
- **proc-other-processes**: the Linux approximation construct, with its
  shared predicate and note.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On macOS, on every base, the process-access class MUST refuse with EPERM the child's reads of the arguments, environment and process information of any process outside the run (KERN_PROCARGS2 and KERN_PROCARGS by numeric MIB, pidinfo), while its reads of its own and its children's MUST succeed; waiving the class MUST lift the refusal.
  - Mitigates: `threat.numeric-unnamed-sysctl`, `threat.procargs-variant` via `mitigation.deny-then-name`
  - Given a same-user process outside the run and a child on the default policy, when the child reads that process's KERN_PROCARGS2, KERN_PROCARGS and pidinfo by numeric call, then each read fails with EPERM
  - Given the same child with a child of its own, when it reads its own and its child's KERN_PROCARGS2 and pidinfo, then every read succeeds
  - Given the same policy with HardDenyClass::ProcessAccess waived, when the child reads the other process's KERN_PROCARGS2, then it succeeds
- **SR-002** (P1): The process-access class MUST add exactly (deny sysctl-read (sysctl-name-prefix "kern.procargs")), the quiet early unfiltered (deny process-info-pidinfo) and (allow process-info-pidinfo (target same-sandbox)) and MUST allow nothing else; the preset profiles v1 to v3 MUST change only by these three lines, pinned by their fixtures.
  - Mitigates: `threat.rule-weakened` via `mitigation.literal-allowlist`
  - Given the empty policy, when it is lowered for macOS, then the only allow is (allow process-info-pidinfo (target same-sandbox))
  - Given the reference policies, when every allow is traced to its source, then the same-sandbox pidinfo allow is the only allow without a policy rule
  - Given every preset version v1 to v3, when it is lowered, then it equals its fixture, which contains the prefix deny, the early pidinfo deny and the same-sandbox allow
- **SR-003** (P1): The R-25 canaries MUST run on the default policy and MUST fail, never skip, when another process's arguments are readable, in every just escape variant and on every macOS lane; the macOS 27 lane MUST re-measure the rule when it exists.
  - Mitigates: `threat.prefix-future-name`, `threat.unmeasured-release` via `mitigation.measure-before-freeze`
  - Given every just escape variant (default, with reporting, base V3 with reporting), when r25_other_processes_arguments_are_unreadable runs, then it passes, and it is not ignored
  - Given a lane where the read succeeds, when the canary runs, then it fails the lane
- **SR-004** (P1): On Linux (T1 and T2) the base and every preset MUST grant nothing under /proc beyond /proc/self and /proc/thread-self, so on the default policy a child's read of another process's cmdline or environ MUST be denied.
  - Mitigates: `threat.t2-silent-proc` via `mitigation.no-default-proc`
  - Given Linux T1 or T2, the base policy and a same-user process outside the run, when the child reads that process's cmdline and environ, then both reads are denied
  - Given every preset version v1 to v3 on T1 and T2, when its rules are lowered, then none names proc-other-processes
- **SR-005** (P2): With the class in force the run's own processes MUST stay readable (the pidinfo allow is same-sandbox, not self and children) and the base program set MUST work as before; ps (setuid, refused in any cage) and pgrep (needs sysmond) MUST be documented as limits.
  - Mitigates: `threat.program-set-gap` via `mitigation.program-set-v4`
  - Given a child on the default policy with a child of its own, when it reads its own and its child's arguments and pidinfo, then every read succeeds
  - Given the base program set, when it runs with the class in force, then every program works as before
  - Given the macOS docs, when they describe R-25, then they state what of ps of the run works and the ps and pgrep limits
- **SR-006** (P1): On Linux T1 and T2 a policy whose file rule, raw Landlock rule or glob reaches /proc other than /proc/self and /proc/thread-self (literally, through an ancestor such as /, or through a symbolic link resolved at cage creation), or a grant whose resolved path does at spawn, MUST be refused naming proc-other-processes unless the caller accepts it by name; an accepted rule MUST be listed in the plan and an accepted grant in the run's receipt, which is then not enforced as written; other processes' environ MUST stay unreadable.
  - Mitigates: `threat.linux-root-refused`, `threat.proc-reach-bypass`, `threat.t2-silent-proc` via `mitigation.proc-gap`
  - Given T1 or T2 and a rule on /proc, when the cage is made without the approximation, then it is refused naming proc-other-processes
  - Given the approximation accepted by name, when the child reads another process's environ and cmdline and its own environ, then environ is refused, cmdline is readable (the residual), its own environ is readable, and the plan lists the approximation
  - Given a rule on a symbolic link to /proc, when the cage is made without, then with the approximation, then it is refused naming the construct, then made with the approximation in the plan
  - Given a grant bound at spawn to a symbolic link to /proc, when the run is spawned without, then with the approximation, then the spawn is refused naming the construct, then the receipt lists the approximation and enforced_as_written is false
- **SR-007** (P2): THREAT_MODEL MUST mark R-25 mitigated with per-platform text (macOS: the class on every base, lifted by waiving it; Linux: no /proc by default, the approximation by name with its residual), the site docs MUST say the same, and the CHANGELOG MUST carry the migration notes (macOS: waive ProcessAccess; Linux: allow ProcOtherProcesses).
  - Mitigates: `threat.linux-root-refused`, `threat.status-overclaim` via `mitigation.per-platform-status`
  - Given THREAT_MODEL, the crate docs and the site, when they describe R-25, then they give the macOS class and its waiver, the Linux default and the residual with the approximation, and no base or preset that does not exist
  - Given the CHANGELOG, when the release is cut, then it lists the macOS refusal under Security and the Linux approximation under Changed, each with its migration
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: No caged child on macOS (any base, the class in force) or on
  Linux (default policy, both tiers) can read another same-user process's
  arguments or environment (canaries in every `just escape` variant and on
  both Linux tiers).
- **SC-002**: The base program set and the escape suite (on its default
  base and on V3) pass with the class in force on every macOS lane, and
  every preset fixture differs from 0.1.0 by exactly the class's three
  lines.

## Assumptions

- The measured rule holds on macOS 27 (re-measured on the macOS 27 lane when
  it exists; the canaries fail that lane otherwise).
- No release user depends on V1–V3 or presets v1–v3 reading other
  processes; the CHANGELOG migration covers any that do.

## Out of Scope

- Other users' processes (already refused by the kernel).
- Making the caller's own process restricted (code-signing flags).
- A Linux PID namespace (deferred: PID 1 semantics need an init).
