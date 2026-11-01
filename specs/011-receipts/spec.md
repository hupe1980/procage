# Feature Specification: Receipts — evidence of how a run was caged

**Feature Branch**: `011-receipts` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: A harness that runs commands for an agent must be able to show, afterwards, that a command ran caged and how: which policy, which preset and base, which backend and tier, which approximations, relaxations and waivers were accepted, on which OS build or kernel, what was denied and how it ended. procage 0.1.0 records approximations and waivers on its lowering plan, but hands nothing back per run.

## Context

procage refuses to weaken a policy silently: a construct a host cannot enforce
is a typed gap; an approximation needs the caller's name for it; `fit` relaxes
only named constructs and says what would lift each. All of that is known when
the cage is built, and the tier, kernel and violations are known per run. A
**receipt** collects it per run, in a stable, serialisable form, so a harness
can attach it to a log, a pull request or an audit trail.

## Clarifications

### Session 2026-11-01

- Q: Unknown fields when reading? → A: Refused, like the policy format: a
  reader never presents a receipt it did not fully understand; older format
  versions stay readable.
- Q: Are grants and the library version recorded? → A: Grant names and the
  procage version, yes; grant paths only with the policy, on request.
- Q: Is the receipt signed? → A: No. It is evidence produced by the caller's
  own process, not an attestation; signing would claim more than it proves.
- Q: Does a receipt include the full policy? → A: It includes a digest of the
  policy's canonical serialised form, and the policy itself only on request,
  so receipts stay small and contain no paths the caller did not ask to log.
- Q: When is a receipt available? → A: When the run ends (the child exited or
  was killed and the violation record is complete or closed as interrupted);
  a partial view is available while it runs.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A harness attaches proof of caging (Priority: P1)

After each command, a harness serialises the receipt and stores it with the
command's output.

**Why this priority**: it is the first thing an auditor or a reviewer asks
("did this run in the sandbox, and in which one?").

**Independent Test**: Spawn a caged child on each backend and tier, wait, take
the receipt, serialise it, read it back; every field matches what the cage and
the run reported.

**Acceptance Scenarios**:

1. **Given** a run on macOS, **When** it ends, **Then** the receipt names the
   policy digest, preset and base versions, backend, apply method, macOS
   build, waivers, approximations, relaxations, violation summary and exit.
2. **Given** a run on Linux, **Then** it names the tier, Landlock ABI and
   errata, kernel release, and the same policy fields.
3. **Given** two runs of the same policy, **Then** their policy digests are
   equal; for two policies that differ in any rule, they differ.

---

### User Story 2 - A relaxed run says so (Priority: P1)

A cage made with `fit` lists each relaxation with what would lift it; a run
with an accepted approximation lists it by construct.

**Acceptance Scenarios**:

1. **Given** a fitted cage, **When** a run ends, **Then** the receipt lists
   every relaxation and its lift; a reader can tell a fully enforced run from
   a relaxed one from the receipt alone.

---

### User Story 3 - The format is stable (Priority: P2)

Receipts written by one version are readable by the next minor version.

**Acceptance Scenarios**:

1. **Given** a receipt from the previous format version, **When** it is
   read, **Then** it parses.
2. **Given** a receipt from a newer format version, or with a field the
   reader does not know, **When** it is read, **Then** the reader refuses it
   with a typed error; it never reports a receipt it only partly understood.

### Edge Cases

- A run killed by the caller, by a signal or a timeout: the exit field says
  which.
- Violation reporting off: the receipt says "not observed", never "none".
- Lossy macOS reports: the receipt carries the record's coverage and dropped
  count; an empty, complete record is still not proof of no denial.
- `Cage::exec` (the helper becomes the command): no receipt (the caller's
  process is replaced); documented.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every spawned run MUST provide a receipt when it ends.
- **FR-002**: The receipt MUST contain: format version; procage version;
  per-spawn grant names (not their paths); policy digest
  (stable hash of the canonical serialised policy); preset name and version
  and base version, if any; backend; apply method (macOS) or tier, Landlock
  ABI and errata (Linux); OS release and build or kernel release; accepted
  approximations; relaxations with their lift; waived hard-deny classes;
  violation summary (coverage, counts, completeness); exit (code, signal,
  killed by the run's end).
- **FR-003**: The receipt MUST be serialisable to and from a documented,
  versioned format with the same rules as the policy format.
- **FR-004**: The receipt MUST NOT contain environment values, file
  contents, or the policy's paths unless the caller asks for the policy to
  be included.
- **FR-005**: Producing the receipt MUST NOT add work to the child between
  fork and exec.
- **FR-006**: The docs MUST state what a receipt proves and what it does not
  (it is the caller's record, not an attestation; macOS violation coverage is
  best effort).

### Key Entities

- **Receipt**: the per-run record of FR-002.
- **Policy digest**: a hash of the canonical serialisation; equal for equal
  policies.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The policy digest MUST be SHA-256 over one canonical encoding of the policy (fixed field order, sets sorted, order kept only where it changes meaning, every path as its bytes, no omitted defaults) prefixed by a format tag and version; equal policies MUST have equal digests however they were built, and policies that differ in any rule, waiver, base or preset tag MUST have different digests.
  - Mitigates: `threat.digest-collision` via `mitigation.canonical-digest`
  - Given two equal policies built with their sets in a different order, when both are digested, then the digests are equal
  - Given a policy and a copy that differs in one path byte, one waiver, the base or the preset tag, when both are digested, then the digests differ
  - Given a fixture policy with a pinned digest, when it is digested on every CI lane and after a round trip through the serialised form, then the digest equals the pinned value
- **SR-002** (P1): The receipt MUST list every accepted approximation by construct, every fit relaxation with its lift and every waived hard-deny class held by the cage's plan, and MUST carry one field that says enforced as written only when all three lists are empty.
  - Mitigates: `threat.relaxation-omitted` via `mitigation.plan-is-the-source`
  - Given a fitted cage with relaxations, a cage with an accepted approximation and a cage with each waivable class waived, when a run of each ends, then the receipt lists exactly the plan's entries and enforced as written is false
  - Given a cage with none of them, when a run ends, then the three lists are empty and enforced as written is true
- **SR-003** (P1): A receipt reader MUST refuse a receipt of a newer format version with a typed error, and MUST NOT report a run as enforced as written when the receipt holds a field or value it does not know.
  - Mitigates: `threat.unknown-field-dropped` via `mitigation.fail-closed-reader`
  - Given a receipt with an added relaxation kind the reader does not know, when it is read, then it is refused, or read with enforced as written false or unknown, never true
  - Given a receipt of the next format version, when it is read, then the reader returns an unsupported-version error
  - Given a receipt of the previous format version, when it is read, then it parses with every field intact
- **SR-004** (P1): The violation summary MUST carry the record's coverage, completeness and dropped count; with reporting off or unavailable it MUST say not observed (with the reason) and MUST NOT carry a violation count.
  - Mitigates: `threat.not-observed-as-none` via `mitigation.typed-coverage`
  - Given a run with reporting off, and a run where reporting was unavailable, when their receipts are serialised, then the summary is not observed (unavailable naming the reason) and holds no count, so no reader can read zero
  - Given a macOS run whose record dropped reports, when its receipt is built, then the summary carries coverage observed, the dropped count and completeness as the record reports them
- **SR-005** (P2): Without the caller asking for the policy, the receipt MUST NOT contain environment values, command arguments, file contents, policy paths, violation paths or process names; asking for the policy MUST add only the policy.
  - Mitigates: `threat.receipt-leaks-secrets` via `mitigation.field-allowlist`
  - Given a canary string in an environment value, an argument, a policy path, a file the child reads and a path the child is denied, when the run's receipt is serialised, then no canary bytes appear in it
  - Given the same run with the policy requested, when the receipt is serialised, then only the policy-path canary appears
- **SR-006** (P2): Every receipt field MUST come from the parent's cage and plan, the kernel's reports and the reaped exit status; strings the caged code controls MUST NOT appear in a receipt.
  - Mitigates: `threat.child-shaped-fields`, `threat.fork-exec-work` via `mitigation.parent-only-facts`
  - Given a child that names itself and its paths with format-breaking bytes and exits with a chosen code, when its receipt is read back, then the exit code is recorded, none of its strings appear, and every other field equals the cage's own values
- **SR-007** (P2): The child's call sequence between fork and exec MUST be identical with and without receipts; the receipt MUST be built in the parent only.
  - Mitigates: `threat.child-shaped-fields`, `threat.fork-exec-work` via `mitigation.parent-only-facts`
  - Given the multithreaded spawn tests on every lane, when they run with receipts, then they pass, and the child-side code holds no receipt state
  - Given the spawn benchmark, when it runs with and without receipts, then spawn latency is unchanged within noise
- **SR-008** (P2): A final receipt MUST be available only after the child was reaped and its violation record is complete or closed as interrupted; the partial view MUST be a distinct type that cannot be serialised as a final receipt; the exit MUST distinguish an exit code, a signal and a kill by the caller, a timeout or the end of the run.
  - Mitigates: `threat.final-state-misstated` via `mitigation.final-after-reap`
  - Given a running child, when the receipt is asked for, then only the partial view is returned, and it serialises marked partial
  - Given runs ended by a normal exit, a signal, a caller kill and a timeout, when their receipts are read, then each exit field names its cause
- **SR-009** (P1): The receipt docs MUST state that a receipt is the caller's own unsigned record and not an attestation, that whoever can write where it is kept can change it (so keep it outside every path a later run may write), that an empty complete record does not prove nothing was denied, and that `Cage::exec` produces no receipt.
  - Mitigates: `threat.not-observed-as-none`, `threat.receipt-as-attestation` via `mitigation.honest-docs`
  - Given the crate docs and the site page on receipts, when they describe what a receipt proves, then each states all four points, and no text calls a receipt proof, attestation or signature
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: On every CI lane, receipts round-trip through the serialised
  form for every preset and both backends.
- **SC-002**: A receipt reader can answer "was anything relaxed, waived or
  approximated?" with one field check.
- **SC-003**: Spawn latency is unchanged within noise (the receipt is built in
  the parent).

## Assumptions

- The policy's serialised form is canonical enough to hash (fields in a fixed
  order, sets sorted); the plan confirms or adds a canonical encoder.

## Out of Scope

- Signing or remote attestation.
- `explain` and policy diffs (spec 042).
