# Feature Specification: Explain and diff, checked against the kernel

**Feature Branch**: `042-explain` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: When a caged command fails, its author asks "why was this denied, and which rule would allow it?"; a reviewer of a policy change asks "what does this change allow that the old one did not?". procage should answer both from the policy itself, and prove its answers by comparing them with the kernel.

## Context

A policy is lowered to an exact plan per target (macOS Seatbelt profile, Linux
tier T1 or T2). Violation records already say *that* something was denied and
by which kind of rule. What is missing is an evaluator over the plan:

- `explain(operation, path)`: allowed or denied, by which rule (an allow, a
  protect, a hide, a hard-deny class, the base, or the default), for a
  canonical path on a given target;
- `diff(a, b)`: the operations and path sets one policy allows and the other
  does not.

Seatbelt and Landlock semantics are partly undocumented. So the evaluator is
only trusted where a **differential oracle** agrees: the same questions asked
of the kernel (macOS `sandbox_check` for operations proven reliable; observed
errno in a caged child on Linux) must give the same answers. A disagreement is
a test failure, which turns undocumented semantics into procage's own
regression suite.

## Clarifications

### Session 2026-11-01

- Q: For which operations does `explain` answer? → A: File read, write,
  create, unlink, rename, exec, metadata; network connect and bind by
  family; Unix-socket connect; signal; process info. Others return "not
  modelled", never a guess.
- Q: Which kernel answer is the oracle on macOS? → A: `sandbox_check` only for
  operations a kernel fact proves reliable; others are checked by a caged
  child's observed result.
- Q: Does `explain` follow symbolic links? → A: It answers for canonical
  paths only, like the policy; a non-canonical query is an error that names
  the canonical form.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Why was this denied? (Priority: P1)

A harness receives a violation and shows the user which rule denied it and what
grant or relaxation would allow it.

**Why this priority**: it turns a denial into an actionable message, the step
before grant-on-denial (spec 017).

**Independent Test**: For each preset on each target, a generated set of
(operation, path) questions; `explain` names a rule for each, and the
oracle agrees on every operation it covers.

**Acceptance Scenarios**:

1. **Given** a read of a hidden file, **When** explained, **Then** the answer
   is "denied by hide <path>".
2. **Given** a write to `.git/hooks/x`, **Then** "denied by hard deny
   trust-handoff" and the waiver that would change it.
3. **Given** an operation `explain` does not model, **Then** "not modelled".

---

### User Story 2 - What does this change allow? (Priority: P2)

A reviewer diffs two policies (or two preset versions) and sees every newly
allowed or newly denied operation.

**Acceptance Scenarios**:

1. **Given** preset v2 and v3, **When** diffed, **Then** the result lists
   exactly the quiet denies v3 added and no new allows.
2. **Given** a policy and the same policy with one more writable path,
   **Then** the diff names that path and its operations only.

---

### User Story 3 - The oracle guards the semantics (Priority: P1)

**Acceptance Scenarios**:

1. **Given** the oracle suite on each lane, **When** `explain` and the kernel
   disagree, **Then** the test fails and names the question.

### Edge Cases

- Grants (per-spawn paths): `explain` takes the grants as an input, as spawn
  does.
- Spawn-snapshot approximations on Linux T1: answers say "covered at spawn"
  and the cover's limits.
- Hard links (spec 023) and same-file aliases: answered for the path asked.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy crate MUST provide `explain` over a lowered plan,
  for the operations listed in the clarifications, returning the decision and
  the deciding rule.
- **FR-002**: The policy crate MUST provide `diff` between two policies for
  one target, as sets of (operation, path pattern) allowed by one and not
  the other.
- **FR-003**: The evaluator MUST stay portable (no system calls, `no_std`
  with allocation), like the rest of the policy crate.
- **FR-004**: A differential oracle MUST compare `explain` with the kernel on
  every CI lane for every operation it covers, with generated questions per
  preset and target.
- **FR-005**: Unmodelled operations and non-canonical paths MUST return
  explicit answers, never a guess.
- **FR-006**: The docs MUST list the operations whose answers are proven by
  the oracle.

### Key Entities

- **Question**: operation, canonical path (or socket, signal target), grants.
- **Answer**: allowed or denied, deciding rule, what would change it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On every CI lane, a differential oracle MUST ask the kernel at least 1,000 generated questions per preset and target, reaching every rule kind (allow, protect, hide, hard-deny class, base, default, grant, T1 cover), for every operation listed as proven, and MUST fail naming the question on any disagreement; a lane that cannot confine its children MUST fail, never skip.
  - Mitigates: `threat.false-denied`, `threat.misleading-remedy`, `threat.oracle-overclaim` via `mitigation.differential-oracle`
  - Given the oracle suite on each lane, when it runs, then every rule kind is reached, at least 1,000 questions per preset and target are asked, and all agree
  - Given an evaluator mutated to flip the decision of one rule kind, when the oracle runs, then it fails and names a question of that kind
  - Given a lane that is itself sandboxed, when the oracle starts, then it fails with AlreadySandboxed
- **SR-002** (P1): The oracle MUST classify a kernel outcome as allowed, denied or unresolved (absent file, other error), MUST fail on an unresolved question rather than count it as agreement, and MUST use sandbox_check only for operations a kernel fact proves reliable.
  - Mitigates: `threat.false-denied`, `threat.misleading-remedy`, `threat.oracle-overclaim` via `mitigation.differential-oracle`
  - Given a question about a file that does not exist, when the caged child observes ENOENT, then the question is unresolved and the suite fails unless the generator creates the file first
  - Given an operation without a kernel fact for sandbox_check, when the oracle checks it, then it uses a caged child's observed result
- **SR-003** (P1): The docs MUST list, per target, exactly the operations the oracle suite proves, and MUST NOT call any other answer proven.
  - Mitigates: `threat.oracle-overclaim` via `mitigation.proven-list`
  - Given the docs list and the oracle suite's covered operations, when a test compares them, then they are equal per target
- **SR-004** (P1): A question MUST carry the target, the Linux tier and the per-spawn grants; on Linux T1 a path outside the spawn-time covers MUST answer covered at spawn with the cover's limits, never a plain denied.
  - Mitigates: `threat.false-denied` via `mitigation.full-question`
  - Given a protected directory on T1 and a file created in it after spawn, when a write to it is explained, then the answer says covered at spawn and names the limit, and the oracle agrees with the kernel's observed result
  - Given a path outside the policy and a grant for it, when it is explained with and without the grant, then it is allowed by the grant with it and denied by the deciding rule without it, as the kernel observes
- **SR-005** (P1): What would change an answer MUST be the narrowest change that flips that question (a literal rule or grant for the path asked, a waiver by class only when a hard-deny class decides), and MUST name every other question it also flips.
  - Mitigates: `threat.misleading-remedy` via `mitigation.minimal-remedy`
  - Given every generated denied question of a preset, when its suggested change is applied and the old and new policies are diffed, then the question flips and the diff lists only the path asked, or exactly the questions the suggestion names
  - Given a write to .git/hooks/x, when explained, then the answer is denied by hard deny trust-handoff and names that waiver, and no subpath grant
- **SR-006** (P1): explain MUST accept only a canonical absolute path; a relative path, dot or dot-dot components, repeated separators, a trailing separator and a known alias or firmlink spelling MUST return an error naming the canonical form; pattern characters in a question path MUST stay literal.
  - Mitigates: `threat.non-canonical-query` via `mitigation.canonical-question`
  - Given /etc/hosts on macOS and /a/../b, when they are explained, then each is an error naming /private/etc/hosts and /b
  - Given a path containing * and [ under a protect rule for a sibling, when it is explained, then the answer is about that literal path only, and the oracle agrees
- **SR-007** (P2): An operation outside the modelled set MUST return not modelled, never allowed, denied or a default.
  - Mitigates: `threat.unmodelled-guess` via `mitigation.closed-operations`
  - Given each operation kind the kernel knows and explain does not model, when it is explained under every preset, then the answer is not modelled
- **SR-008** (P1): For two policies on one target, every question whose explain answers differ MUST be covered by a diff entry naming its direction; changes to waivers, the base, the preset version, network, process and signal rules MUST appear; anything diff does not compare MUST be listed as not compared, never as unchanged.
  - Mitigates: `threat.diff-hides-loosening` via `mitigation.sound-diff`
  - Given generated policy pairs and generated questions, when explain disagrees between the two for a question, then a diff entry covers that question with the right direction
  - Given a policy and the same policy with one more writable path, or one more waiver, when they are diffed, then the diff names that path and its operations only, or that class and its operations only
  - Given every frozen preset pair vN and vN+1, when diffed, then the result matches the changelog entry of that version
- **SR-009** (P3): explain MUST run in time linear in the plan size and under 1 ms per question on the reference machine; diff MUST have a documented bound on pattern pairs and MUST return an error beyond it instead of running unbounded.
  - Mitigates: `threat.evaluator-exhaustion` via `mitigation.bounded-evaluation`
  - Given the largest preset and a path of the maximum length with deep globs in the policy, when explain is benchmarked, then it answers in under 1 ms
  - Given two policies over the diff bound, when diffed, then diff returns the bound error
- **SR-010** (P3): The explain docs MUST state that an answer names the deciding rule and is meant for the user, and that a harness MUST NOT relay it into the cage unfiltered.
  - Mitigates: `threat.answer-reveals-rules` via `mitigation.relay-guidance`
  - Given the crate docs and the site page on explain, when they describe answers, then both say so
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: For every preset on every lane, the oracle agrees on 100% of
  covered questions (at least 1,000 per target).
- **SC-002**: `diff(vN, vN+1)` of every frozen preset pair matches the
  changelog's description of that version.
- **SC-003**: The evaluator runs in under 1 ms per question on the reference
  machine.

## Assumptions

- `sandbox_check` is reliable for the file read/write operations it was
  measured on; other operations use caged children.

## Out of Scope

- A learning mode that writes policies from traces (none exists on current
  macOS; spec 017 builds suggestions from violations instead).
