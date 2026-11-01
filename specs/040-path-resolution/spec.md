# Feature Specification: Path resolution that cannot be redirected or mis-spelled

**Feature Branch**: `040-path-resolution` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: Two path questions procage 0.1.0 leaves open. (1) On Linux tier T1 the child makes its mounts by path name; a symbolic link planted in a writable tree between the parent's plan and the child's mounts could redirect a mount — the same class as a 2026 bubblewrap advisory (setup that followed symbolic links). (2) The published claim of a canonicalisation test matrix (case, Unicode normalisation, case-folding file systems) is only partly backed by tests.

## Context

**Mounts on T1.** The parent resolves each policy path and builds a mount plan
(read-only binds for protected paths, empty file systems or `/dev/null` over
hidden ones, covers for data-class files and foreign sockets). The child then
creates its namespaces and mounts each target **by name**. Between the two,
another process with write access to the tree — a concurrent caged run on the
same workspace, or a link left behind by an earlier run — can replace a path
component with a symbolic link. A mount that follows it lands somewhere else:
the intended path stays writable or visible, and an unrelated path is covered.
bubblewrap fixed this class in 2026 by resolving every mount target beneath
its root without following links (CVE-2026-87766).

**Spelling.** On macOS the default file system is case-insensitive and
normalisation-insensitive but preserving; a rule spelled `Project` must cover
`project`, or be refused — never silently match nothing. Linux has
case-folding directories (ext4 `casefold`). 0.1.0 tests symbolic links,
missing leaves and firmlinks; it has no case or normalisation logic and no
tests for them.

## Clarifications

### Session 2026-11-01

- Q: Measure first or fix first? → A: Measure first. A canary that tries to
  redirect a T1 mount is written before the change; it decides whether this
  is a fix (a security entry in the changelog) or hardening.
- Q: What does a mount do when a target component is a link at mount time?
  → A: The spawn fails with a typed error naming the path. Following a link
  that appeared after the plan is never acceptable; skipping the mount would
  weaken the cage.
- Q: Case and normalisation on macOS — normalise the rule, or ask the
  kernel? → A: Neither guess: the matrix measures what Seatbelt does with
  each spelling, and procage either emits the spelling that matches or
  refuses the rule with a typed error.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A planted link cannot move a mount (Priority: P1)

Two caged runs share a writable workspace. One of them replaces a directory
the other's policy protects with a symbolic link while the second run spawns.
The protected path stays protected, or the spawn fails; nothing else is
covered.

**Why this priority**: it is a potential escape of procage's own setup.

**Independent Test**: A canary races link replacement against T1 spawns of a
policy that protects and hides paths inside the writable tree; after the
change, no spawn ever runs with a redirected mount (thousands of attempts),
and before it the canary shows whether the race was winnable.

**Acceptance Scenarios**:

1. **Given** a protected directory replaced by a link to another directory
   before the child mounts, **When** the child mounts, **Then** the spawn
   fails with an error naming the path, and the link target is untouched.
2. **Given** a hidden file whose parent directory became a link, **When** the
   spawn runs, **Then** it fails the same way.
3. **Given** no interference, **When** the existing spawn and escape suites
   run, **Then** they pass unchanged and spawn latency grows by no more than
   a small, measured amount.

---

### User Story 2 - A rule's spelling never silently misses (Priority: P2)

A harness writes paths as the user typed them. Whatever the case or Unicode
form, the rule covers the file the user meant, or the cage refuses it.

**Independent Test**: A matrix of caged tests on a case-insensitive APFS
volume, a case-sensitive APFS volume (a disk image) and, on Linux, a
case-folding directory, each with paths in mixed case and in composed and
decomposed Unicode.

**Acceptance Scenarios**:

1. **Given** a read deny spelled in another case than on disk, on a
   case-insensitive volume, **When** the child reads the file, **Then** it is
   denied — or the cage was refused with a typed error.
2. **Given** a name in decomposed Unicode on disk and composed in the rule,
   **When** the child accesses it, **Then** the result is the same as for the
   on-disk spelling, or the cage was refused.
3. **Given** a case-sensitive volume, **When** a rule names `A` and the file
   is `a`, **Then** the rule covers only `A` (they are different files).

### Edge Cases

- The planted link points into a path the child may write: the spawn still
  fails (the mount target must be the planned one, not merely an allowed one).
- A mount target that vanished: data-class and socket covers keep their
  existing behaviour (skipped when gone); declared mounts stay strict.
- Bind sources are resolved the same way as targets.
- Hard links are out of scope here (spec 023).

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: An escape canary MUST attempt to redirect each kind of T1 mount
  (protect, hide, data-class cover, socket cover, grant bind) by replacing a
  path component with a symbolic link between planning and mounting, and
  MUST record whether it succeeded before the change.
- **FR-002**: On T1, every mount source and target MUST be resolved beneath
  its planned root without following symbolic links, and the mount MUST
  apply to exactly the object resolved; a link in any component MUST fail
  the spawn with a typed error naming the path.
- **FR-003**: The child's mount sequence MUST stay system calls only, with
  every path and buffer prepared in the parent.
- **FR-004**: The macOS canonicaliser MUST be covered by caged tests for: a
  case-insensitive and a case-sensitive APFS volume, composed and decomposed
  Unicode names, nested symbolic links, missing leaves and firmlinks.
- **FR-005**: A rule whose spelling the backend cannot match exactly MUST be
  refused with a typed error; it MUST NOT silently match nothing.
- **FR-006**: On Linux, the same matrix MUST run on a case-folding directory
  where the lane supports one, and otherwise the docs MUST say it is
  untested.
- **FR-007**: The threat model MUST gain an escape class for setup that
  follows a planted link, with this canary as its evidence.

### Key Entities

- **Mount target**: a planned path and the object it resolved to at plan
  time; the child mounts only that object.
- **Spelling matrix**: the set of (volume kind, rule spelling, on-disk
  spelling, expected outcome) cases.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): An escape canary MUST, for each T1 mount kind (protect, hide, data-class cover, socket cover, grant bind), replace a source or target component with a symbolic link between plan and mount, both at a deterministic hook and in at least 10,000 racing attempts, and MUST record the outcome before and after the change.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.source-redirect`, `threat.vacuous-canary` via `mitigation.race-canary`
  - Given the build before the change and the deterministic hook, when the link is planted for each mount kind, then the canary records whether the mount was redirected
  - Given the build after the change, when 10,000 racing attempts run per mount kind, then no spawn runs with a redirected mount
- **SR-002** (P1): On T1 every mount source and target MUST be resolved beneath its planned root without following a symbolic link in any component; a link MUST fail the spawn with a typed error naming the path, even when the link points into a path the child may write.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.source-redirect` via `mitigation.no-follow-resolution`
  - Given a protected directory replaced by a link to another directory before the child mounts, when the spawn runs, then it fails with an error naming the path and the link target is unchanged
  - Given a hidden file whose parent directory became a link, when the spawn runs, then it fails the same way
  - Given a grant bind whose source became a link into the writable workspace, when the spawn runs, then it fails the same way
- **SR-003** (P1): The mount MUST apply to exactly the object resolved; no step MUST resolve the path name again after the no-follow resolution.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.resolve-then-remount` via `mitigation.mount-by-descriptor`
  - Given a hook that replaces a component after resolution and before the mount call, when the child mounts, then the mount lands on the originally resolved object, or the spawn fails; never on the link target
- **SR-004** (P1): If the kernel lacks a call needed to resolve without following links or to mount by descriptor, the cage MUST fail with a typed error at build time and MUST NOT fall back to mounting by path.
  - Mitigates: `threat.kernel-fallback` via `mitigation.no-fallback`
  - Given a T1 test where the needed call returns ENOSYS, when the cage is built, then it fails with a typed error naming the call, and no child runs
- **SR-005** (P2): The child's mount sequence MUST issue system calls only, with every path and buffer prepared in the parent, and MUST be covered by the multithreaded spawn test.
  - Mitigates: `threat.child-unsafe` via `mitigation.syscalls-only`
  - Given a parent whose other threads allocate and lock continuously, when 1,000 T1 spawns run with the new sequence, then all complete and the child sequence contains no allocation (review of the sys module)
- **SR-006** (P2): A spawn failed by a link MUST name the path, the component that is a link and the mount kind; vanished snapshot covers MUST keep being skipped and declared mounts MUST stay strict.
  - Mitigates: `threat.spawn-sabotage` via `mitigation.named-failure`
  - Given a planted link, when the spawn fails, then the error names the path, the linked component and the mount kind
  - Given the existing spawn and escape suites, when they run, then they pass unchanged
- **SR-007** (P1): On macOS a rule whose spelling differs from the on-disk name (case on a case-insensitive volume, Unicode form) MUST either enforce on the file under every spelling the volume treats as the same name, or the cage MUST be refused with a typed error naming the rule; it MUST NOT silently match nothing.
  - Mitigates: `threat.case-miss`, `threat.unicode-miss` via `mitigation.exact-or-refuse`
  - Given a case-insensitive APFS volume and a read deny spelled in another case than on disk, when the child reads the file by its on-disk spelling, then it is denied, or the cage was refused
  - Given a name decomposed on disk and composed in the rule, when the child accesses it, then the result equals that of the on-disk spelling, or the cage was refused
- **SR-008** (P1): No rule MUST be widened by case folding or normalisation; on a case-sensitive volume a rule MUST cover only its exact name.
  - Mitigates: `threat.fold-overgrant` via `mitigation.no-widening`
  - Given a case-sensitive APFS disk image with files A and a and a write grant for a, when the child writes A, then the write is denied
- **SR-009** (P1): The spelling matrix MUST run as caged tests on a case-insensitive and a case-sensitive APFS volume with composed and decomposed names, nested links, missing leaves and firmlinks, and on a Linux case-folding directory where the lane supports one; a macOS lane that cannot create the disk image MUST fail, not skip.
  - Mitigates: `threat.case-miss`, `threat.unicode-miss`, `threat.vacuous-canary` via `mitigation.spelling-matrix`
  - Given each macOS lane, when the matrix runs, then every case enforces as intended or is refused
  - Given a macOS lane where the disk image cannot be created, when the matrix runs, then it fails
- **SR-010** (P2): The published canonicalisation claim MUST list exactly the cases the matrix covers and say where Linux case-folding is untested, and the threat model MUST carry the escape class for setup that follows a planted link with the race canary as evidence.
  - Mitigates: `threat.claim-overstates` via `mitigation.claim-from-matrix`
  - Given the claim and the matrix, when they are compared, then every claimed case has a test and every test a claim
  - Given the threat model, when it is read, then it lists the class with the race canary
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: The race canary runs at least 10,000 attempts per mount kind
  with zero redirected mounts after the change.
- **SC-002**: Every spelling-matrix case either enforces as intended or is
  refused; none silently misses.
- **SC-003**: Median T1 spawn time rises by at most 10% (measured with the
  benchmark of spec 043 or the existing latency probe).
- **SC-004**: The published canonicalisation claim lists exactly the cases
  the matrix covers.

## Assumptions

- Linux T1 kernels (Landlock ABI ≥ 1, unprivileged user namespaces) have
  the system calls needed to resolve a path without following links and to
  mount by descriptor; the plan confirms which, per kernel.
- Disk images for the case-sensitive volume can be created without root on
  the macOS lanes.

## Out of Scope

- Hard links to protected files (spec 023).
- Tier T2, which makes no mounts.
