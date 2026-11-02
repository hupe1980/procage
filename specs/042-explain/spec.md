# Feature Specification: Explain and diff, checked against the kernel

**Feature Branch**: `042-explain` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

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
of the kernel (the observed result of a caged child, on every lane) must give
the same answers. A disagreement is
a test failure, which turns undocumented semantics into procage's own
regression suite.

## Clarifications

### Session 2026-11-01

- Q: Does `explain` follow symbolic links? → A: It answers for canonical
  paths only, like the policy; a non-canonical query is an error that names
  the canonical form.

### Session 2026-11-02

- Q: For which operations does `explain` answer in 0.2.0? → A: Opening a
  file for reading, opening an existing file for writing, and executing a
  file. Every other operation returns "not modelled", never a guess.
- Q: Does an answer say whether it is proven by the oracle? → A: No marker
  is needed: `explain` models exactly the operations the oracle proves on
  every target, and the docs list them.
- Q: How does a reviewer see a change that loosens only one target or tier?
  → A: `diff` takes the targets to compare and tags every entry with its
  target.
- Q: Who resolves symbolic links in a question path? → A: procage's
  `Cage::explain` resolves the path first; the policy crate alone refuses
  lexically non-canonical paths and the macOS alias spellings (`/etc`,
  `/tmp`, `/var`) by naming the canonical form.
- Q: What does the oracle ask the kernel on macOS? → A: A caged child's
  observed result, as on Linux; `sandbox_check` is not used. On Linux the
  homes and grants the cage resolved at spawn are part of the question.

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
  for file read, file write and exec (Session 2026-11-02), returning the
  decision and the deciding rule.
- **FR-002**: The policy crate MUST provide `diff` between two policies for
  the targets given, as entries (target, operation, path pattern, direction)
  allowed by one and not the other.
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

- **Question**: operation, canonical path, and a context of the per-spawn
  grants and (on Linux) the homes.
- **Answer**: allowed or denied, deciding rule, what would change it.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): On every CI lane, a differential oracle MUST ask the kernel at least 1,000 generated questions per preset and target, reaching every rule kind (allow, protect, hide, hard-deny class, base, default, grant, T1 cover), for every operation listed as proven, and MUST fail naming the question on any disagreement; a lane that cannot confine its children MUST fail, never skip.
  - Mitigates: `threat.false-denied`, `threat.misleading-remedy`, `threat.oracle-overclaim` via `mitigation.differential-oracle`
  - Given the oracle suite on each lane, when it runs, then every rule kind is reached, at least 1,000 questions per preset and target are asked, and all agree
  - Given an evaluator mutated to flip the decision of one rule kind, when the oracle runs, then it fails and names a question of that kind
  - Given a lane that is itself sandboxed, when the oracle starts, then it fails with AlreadySandboxed
- **SR-002** (P1): The oracle MUST ask a caged child on every lane and classify its observed result as allowed (success), denied (EACCES, EPERM, EROFS) or unresolved (anything else, including ENOENT for a file the generator made), and MUST fail on an unresolved question rather than count it as agreement.
  - Mitigates: `threat.false-denied`, `threat.misleading-remedy`, `threat.oracle-overclaim` via `mitigation.differential-oracle`
  - Given a question whose open fails with ENOENT or another unexpected errno, when the oracle compares it, then the suite fails naming the question
  - Given any lane, when the oracle asks the kernel, then it uses a caged child's observed open or execve result, never sandbox_check
- **SR-003** (P1): explain MUST model exactly the operations the oracle suite proves on every target, and the docs MUST list exactly those; no other answer is called proven.
  - Mitigates: `threat.oracle-overclaim` via `mitigation.proven-list`
  - Given the modelled operations, the oracle suite's covered operations and the docs list, when a test compares them, then they are equal on every target
- **SR-004** (P1): A question MUST carry the target, the Linux tier, the per-spawn grants and the homes; on Linux an answer that holds only for paths existing at spawn (class covers on T1, piecewise hides on T2) MUST say so with the limit, never a plain denied.
  - Mitigates: `threat.false-denied` via `mitigation.full-question`
  - Given a trust-handoff name under a writable tree on T1, when a write to a file in it is explained, then the answer is denied by that class with the spawn caveat, and the oracle agrees for a file that existed at spawn
  - Given a path outside the policy and a grant for it, when it is explained with and without the grant, then it is allowed by the grant with it and denied by the deciding rule without it, as the kernel observes
- **SR-005** (P1): A remedy MUST be the narrowest change for the deciding rule (a literal rule of the asked access for the path asked, a waiver by class only when a hard-deny class decides, the removal of the deciding protect or hide rule), MUST be offered only when re-lowering confirms it flips the question, and MUST carry the diff of the change so it names every other question it also flips.
  - Mitigates: `threat.misleading-remedy` via `mitigation.minimal-remedy`
  - Given every generated denied question of a preset, when its remedy is applied and the old and new policies are diffed, then the question flips and the diff equals the remedy's diff
  - Given a write to .git/hooks/x, when explained, then the answer is denied by hard deny trust-handoff, the remedy is that waiver, and no subpath rule
- **SR-006** (P1): explain MUST accept only a canonical absolute path: a relative path, dot or dot-dot components, repeated separators, a trailing separator and the macOS alias spellings MUST return an error naming the canonical form; Cage::explain MUST resolve symbolic links on the host first; pattern characters in a question path MUST stay literal.
  - Mitigates: `threat.non-canonical-query` via `mitigation.canonical-question`
  - Given /etc/hosts on macOS and /a/../b, when they are explained, then each is an error naming /private/etc/hosts and /b
  - Given a path containing * and [ under a protect rule for a sibling, when it is explained, then the answer is about that literal path only, and the oracle agrees
  - Given a symbolic link to a protected file, when Cage::explain is asked about the link, then the answer is about the file it resolves to
- **SR-007** (P2): An operation outside the modelled set MUST return not modelled, never allowed, denied or a default.
  - Mitigates: `threat.unmodelled-guess` via `mitigation.closed-operations`
  - Given each operation kind the kernel knows and explain does not model, when it is explained under every preset, then the answer is not modelled
- **SR-008** (P1): For two policies and the targets given, every question whose explain answers differ on a target MUST be covered by a diff entry for that target naming its direction; changes to waivers, the base, the preset version, network, process and signal rules MUST appear; every other plan field that differs MUST be listed as a changed setting, never as unchanged.
  - Mitigates: `threat.diff-hides-loosening` via `mitigation.sound-diff`
  - Given generated policy pairs and generated questions, when explain disagrees between the two for a question, then a diff entry covers that question with the right direction
  - Given a policy and the same policy with one more writable path, or one more waiver, when they are diffed, then the diff names that path and its operations only, or that class and its operations only
  - Given every frozen preset pair vN and vN+1, when diffed on every target, then every entry comes from the base and the base setting is listed, as the changelog says
  - Given a change only Linux expresses (a Linux layer rule), when diffed for macOS and Linux, then every entry is tagged with the Linux target
- **SR-009** (P3): explain MUST run in time linear in the plan size and path length and under 1 ms per question in release on the reference machine; diff MUST run in O(n log n) in the plans' rules, with no pattern intersection.
  - Mitigates: `threat.evaluator-exhaustion` via `mitigation.bounded-evaluation`
  - Given agent_workspace v3 and a 4,000-byte path, when explain is timed in release, then it answers in under 1 ms per question (a debug build is bounded at 20 ms)
  - Given two policies of 10,000 rules each, when diffed in release, then it finishes in under a second (a debug build is bounded at 10 s)
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

- A caged child's observed `open` and `execve` results are the kernel's
  answer; a missing file is unresolved, never agreement.

## Out of Scope

- A learning mode that writes policies from traces (none exists on current
  macOS; spec 017 builds suggestions from violations instead).
