# Feature Specification: Fitting a policy to the host

**Feature Branch**: `032-fit` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "Keep going. Research it. We want a great DX." Need reported by a consumer harness: fitting a profile to the host.

## Context

When a host cannot enforce part of a policy, procage refuses the cage and
returns typed capability gaps. That is the right default (never silently
weaker), but every consumer that wants to run on more hosts has to turn the
gaps back into policy changes by hand. One consumer harness does it in
~150 lines:

- it matches gap constructs and parses gap subjects to find the rule to
  drop (`fs-protect`, `fs-hide`), waives `hd-trust-handoff`, clears
  `ipc.unix_sockets`, switches signals to `same-user`, and retries;
- it hard-codes why each part is missing ("this machine does not allow user
  namespaces", "this kernel is too old") to tell its user what would lift
  it, and got that wrong once (the kernel's age was blamed on user
  namespaces).

Research for this spec found that procage can answer the second question
itself: lowering is a pure, fast function of policy and target, so
lowering the same policy for tier T1, or for a newer Landlock ABI, shows
exactly which change lifts each gap — no hand-kept table.

## Clarifications

### Session 2026-11-01

- Q: Can fitting relax anything on its own? → A: No. The caller names each
  relaxation it accepts; any gap without an accepted relaxation still fails
  the cage, with every remaining gap.
- Q: Which relaxations exist? → A: One fixed meaning per gap kind:
  leave out a `Protect` rule, leave out a `Hide` rule (both by the gap's
  path), waive a data class (`secrets`, `trust-handoff`, `persistence`),
  allow no Unix sockets instead of some (stricter), let signals reach the
  user's processes (`same-user`), and no network instead of loopback
  (stricter). No other construct can be relaxed.
- Q: What does the caller get back? → A: The cage and a list of what was
  relaxed: the gap, the change made, and what would lift it (tier T1, a
  Landlock ABI, both, or unknown), with a readable message.
- Q: Where does it live? → A: `Cage::fit` on both backends (so
  `procage::native` works on both), built on a pure `Relax` in the policy
  crate.
- Q: Does the consumer harness adopt it in this row? → A: No; this row
  adds the API. The consumer adopts it separately.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A harness runs on more hosts in one call (Priority: P1)

A harness names the relaxations it accepts and calls `Cage::fit`. On a host
that enforces everything it gets the same cage as `Cage::with_options` and
an empty list; on a host without user namespaces it gets a cage without the
named parts and the list of what was left out.

**Why this priority**: removes the hand-written retry loops.

**Independent Test**: On Linux T2, a policy with a writable workspace, a
protected `.git` and a hidden `.env` inside it, trust handoff reached and
workspace Unix sockets fits with the matching relaxations: the cage spawns,
the list names each part, and writes outside the workspace still fail.

**Acceptance Scenarios**:

1. **Given** a host that enforces the policy, **When** fitted, **Then** the
   list is empty and the plan equals `with_options`.
2. **Given** T2 and the four relaxations, **When** fitted, **Then** the list
   has the protect, hide, trust-handoff and sockets entries, and the cage
   confines the rest.
3. **Given** T2 and only some relaxations, **When** fitted, **Then** it fails
   with the gaps that have none, and nothing is relaxed silently.

---

### User Story 2 - The harness can say what would lift each limit (Priority: P1)

Each relaxed entry says whether tier T1 (user namespaces) or a newer
Landlock ABI (with its number) would make the part enforceable, so the
harness can tell its user which fix applies.

**Independent Test**: With the ABI capped at 5 on T2, `same-user` signals
report "Landlock ABI 6"; the protect rule reports "tier T1"; workspace
sockets report "tier T1" (ABI 9 is beyond what procage uses).

**Acceptance Scenarios**:

1. **Given** the signal gap at ABI 5, **Then** its lift is ABI 6, not T1.
2. **Given** a protect gap on T2, **Then** its lift is T1.
3. **Given** a gap no target lifts, **Then** its lift is unknown.

---

### User Story 3 - Docs show the pattern (Priority: P2)

The crate docs show fitting with relaxations and printing the list.

### Edge Cases

- A relaxation that makes a new gap appear: fitting retries a bounded
  number of rounds, then fails with the remaining gaps.
- Approximations are not relaxations: they stay in `LowerOptions` (a gap
  of kind approximation is never relaxed).
- macOS: gaps are rare; fitting behaves the same.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy crate MUST offer `Relax`, a set of named
  relaxations built by explicit methods, and a pure function that applies it
  to a policy for a list of gaps: all unsupported gaps relaxed and reported,
  or none applied and the unrelaxable gaps returned.
- **FR-002**: Each relaxation MUST have exactly one documented effect; a gap
  of kind approximation MUST NOT be relaxed.
- **FR-003**: The policy crate MUST compute, per relaxed gap, whether tier
  T1 or a Landlock ABI up to a given maximum lifts it, by lowering the
  original policy for those targets.
- **FR-004**: Both backends MUST offer `Cage::fit(policy, options, relax)`
  returning the cage and the list, or the error with every remaining gap.
- **FR-005**: Caged tests MUST show the stories on Linux T1/T2 (with the ABI
  cap) and macOS.
- **FR-006**: The crate docs MUST document fitting, and THREAT_MODEL MUST
  state that fitting only relaxes what the caller names.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Fitting MUST relax only unsupported gaps whose relaxation the caller named, and only the rule the gap names; any other gap MUST fail the cage with every remaining gap and no change applied.
  - Mitigates: `threat.silent-relaxation`, `threat.unreported-relaxation` via `mitigation.named-only`
  - Given gaps of which one has no named relaxation, when the relaxation is applied, then it returns the unrelaxable gaps and the policy is unchanged
  - Given an approximation gap of a relaxable construct, when the relaxation is applied, then it is not relaxed
  - Given two protect rules and a gap for one, when the relaxation is applied, then only that rule is removed
- **SR-002** (P1): Every relaxation applied MUST appear in the returned list with its gap and effect.
  - Mitigates: `threat.silent-relaxation`, `threat.unreported-relaxation` via `mitigation.named-only`
  - Given T2 and four relaxations, when Cage::fit runs, then the list has exactly the four entries
- **SR-003** (P2): The lift of each relaxed gap MUST be derived by lowering the original policy for tier T1 and for newer Landlock ABIs up to the backend maximum, and be unknown when neither lifts it.
  - Mitigates: `threat.wrong-lift` via `mitigation.relower-lift`
  - Given the signal gap at ABI 5 on T2, when the lift is computed, then it is ABI 6 without T1
  - Given a protect gap on T2, when the lift is computed, then it is T1
  - Given unix sockets on T2 with maximum ABI 8, when the lift is computed, then it is T1 only
- **SR-004** (P1): A fitted cage MUST still enforce every part of the policy that was not relaxed.
  - Mitigates: `threat.fit-escape` via `mitigation.caged-fit-tests`
  - Given a cage fitted on T2, when the child writes outside the workspace and opens an IP socket, then both fail
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A consumer replaces its gap-handling loop with one call and a
  relaxation list (the consumer harness: ~150 lines to ~30, measured when it adopts it).
- **SC-002**: Every relaxed entry names its lift or says it is unknown.
- **SC-003**: `just ci`, `just linux` and `just linux-t1` pass.

## Assumptions

- Lowering stays pure and deterministic, so re-lowering is a faithful
  oracle for "what lifts this gap" (data-class gaps found at spawn from the
  home directories are not reproduced by lowering; their lift is unknown).
