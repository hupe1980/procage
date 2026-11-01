# Feature Specification: Grant on denial

**Feature Branch**: `017-grant-on-denial` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

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

### Key Entities

- **Suggestion**: the change, the violation it answers, whether it weakens a
  protection.

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
