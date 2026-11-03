# Feature Specification: Grant on denial

**Feature Branch**: `017-grant-on-denial` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

**Input**: When a caged command is denied something it legitimately needs, the user should be able to allow it — once, for the session, or permanently — without rewriting the policy by hand. Other agent sandboxes ask for "elevated permissions with a reason" or offer "sandbox expansion". procage already reports typed violations and offers named relaxations; it should turn one into the other, safely.

## Context

Mid-run grants (widening a running child's sandbox) are not safely possible on
today's kernels: on macOS a new extension must be consumed by the child
itself; on Linux a seccomp user-notification supervisor that opens files for
the child is open to time-of-check races until the kernel can copy the
arguments first (proposed, not merged), and Landlock cannot widen a domain
(a supervisor design exists only as a proposal). So procage does it the way
that is sound today: the denial becomes a **suggestion**, the harness asks
the user, and the **next spawn** carries the approved grant.

## Clarifications

### Session 2026-11-01

- Q: Does procage ask the user? → A: No. procage returns typed suggestions;
  the harness decides, asks and remembers. procage never persists approvals.
- Q: What can be suggested? → A: Only what the policy can express safely: a
  read or write grant for a path (narrowest form: the file, or its directory
  when the operation creates), a Unix socket path, a waiver of a hard-deny
  class by name, a named relaxation. Never "allow all", never a parent of a
  protected or secret path.
- Q: Hard-deny classes? → A: Suggested only as an explicit waiver, marked as
  such, and never for secrets.

### Session 2026-11-03

Decided by the project's scope rule (best-in-class, no overengineering).

- Q: Where does the API live? → A: The `Suggestion` type and its
  `apply(&Policy) -> Policy` live in `procage-policy` (portable, no
  violation types); `procage::suggest(&Policy, &Violation)` derives one
  from a violation.
- Q: When a creating operation is denied, does the suggestion name the file
  or its directory? → A: The file (a literal rule), because Seatbelt checks
  the created path itself; a backend that needs the directory to create
  (Landlock) reports no file denials, so it never gets such a suggestion.
- Q: What does a proxy refusal suggest? → A: Nothing: the allowlist is part
  of the cage options, not the policy, and the violation already names the
  host and port.
- Q: Which denials map to a waiver or a relaxation? → A: A hard-deny class
  other than `secrets` → its waiver, marked as weakening; `protect` or
  `hide` → leaving out the rule that covers the target, marked as
  weakening; a denied signal to another process → `SignalsSameUser`,
  marked as weakening. The raw layer, `Lifetime::Run` and the older-kernel
  truncation guard → none: they are the caller's own rules or a kernel
  limit.
- Q: Does procage merge suggestions of a whole record? → A: No; the harness
  calls `suggest` per violation and decides. Equal suggestions compare
  equal, so it can deduplicate.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A denial becomes an approvable suggestion (Priority: P1)

A caged `npm install` is denied writing `~/.npm/_cacache`. The harness shows
"allow writing ~/.npm/_cacache for this session?"; the user agrees; the retry
succeeds.

**Independent Test**: For each violation kind on each backend, the suggestion
API returns the narrowest grant; applying it and respawning makes the same
operation succeed, and nothing else changes in the plan.

**Acceptance Scenarios**:

1. **Given** a denied write to a path outside the policy, **Then** the
   suggestion is a write grant for that path only.
2. **Given** a denial by a secret class, **Then** no suggestion is made.
3. **Given** a denial inside a protected path, **Then** the suggestion is
   the protect rule's removal, marked as weakening a protection.

---

### User Story 2 - Approvals are explicit and recorded (Priority: P2)

**Acceptance Scenarios**:

1. **Given** an applied suggestion, **Then** the new policy's receipt shows the
   added grant or waiver, and `diff` against the old policy shows exactly it.

### Edge Cases

- Violations with no target (some macOS operations): a suggestion only if a
  named relaxation covers it, otherwise none.
- Lossy macOS records: a missing denial means a missing suggestion;
  documented.
- Linux reports no Landlock file or network denials: file suggestions exist
  on macOS only; Linux suggestions come from seccomp denials (hard-deny
  classes, signals).
- A denial under a hidden or secret path: never a grant. The deny rule
  wins there, so it is reported as `hide` (the rule's removal, marked) or
  as the secrets class (no suggestion).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: procage MUST derive from a violation a typed suggestion: the
  narrowest policy change that would allow exactly that operation, or none.
- **FR-002**: Suggestions MUST never widen beyond the operation and path
  denied, never touch the secrets class, and MUST mark any suggestion that
  weakens a protection, hide or hard deny.
- **FR-003**: Applying a suggestion MUST produce a new policy (respawn); a
  running child's sandbox MUST NOT be widened.
- **FR-004**: The applied change MUST appear in the receipt and in `diff`.
- **FR-005**: A denial of the `secrets` class, of the policy's raw layer, of
  `Lifetime::Run`, of the older-kernel guard or of the proxy MUST yield no
  suggestion.

### Key Entities

- **Suggestion**: the change, the violation it answers, whether it weakens a
  protection.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): A suggestion for a denied file operation MUST be a literal rule on the denied path with the access kind of that operation (read, write or exec), or a Unix socket path for a denied connect; it MUST NOT be a subpath, parent or glob.
  - Mitigates: `threat.overbroad` via `mitigation.exact-literal`
  - Given a caged child denied writing a file outside the policy, when the harness asks for the suggestion, then it is a literal write rule on that file
  - Given the suggestion applied and the run respawned, when the child writes the file and a sibling file, then the file write succeeds and the sibling write is still denied
- **SR-002** (P1): A denial by the secrets class, the raw layer, Lifetime::Run, the older-kernel guard or the proxy MUST yield no suggestion.
  - Mitigates: `threat.secret-suggested` via `mitigation.never-secrets`
  - Given a caged child denied reading a file of the secrets class, when the harness asks for the suggestion, then there is none
- **SR-003** (P1): A suggestion that waives a hard-deny class, leaves out a protect or hide rule, or widens signals MUST be marked as weakening; grants MUST NOT be.
  - Mitigates: `threat.provoked-prompt`, `threat.unmarked-weakening` via `mitigation.mark-weakening`
  - Given a caged child denied writing under a protected path, when the harness asks for the suggestion, then it leaves out that protect rule and is marked as weakening
  - Given a denial by a hard-deny class other than secrets, when the harness asks for the suggestion, then it waives that class by name and is marked as weakening
- **SR-004** (P1): Applying a suggestion MUST return a new policy and MUST NOT change the running child's sandbox.
  - Mitigates: `threat.midrun-widening` via `mitigation.respawn-only`
  - Given a running child and an applied suggestion, when the child retries the operation, then it is still denied until a new spawn
- **SR-005** (P2): The policy a suggestion produces MUST differ from the old one only by the suggested change: explain::diff shows that change alone, and the new run's receipt records an added waiver.
  - Mitigates: `threat.unrecorded` via `mitigation.exact-apply`
  - Given an applied grant, when the harness diffs the old and new policy, then only the granted path and access differ
  - Given an applied waiver, when the respawned run ends, then its receipt lists the waiver
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: For every violation kind in the escape and spawn suites, the
  suggestion either makes the operation succeed on respawn and changes
  nothing else, or is absent by rule.

## Assumptions

- Violation records name operation and target precisely enough (they do for
  file and socket operations on both systems).

## Out of Scope

- Mid-run grants (until the kernels support them safely).
- Any approval UI or storage.
