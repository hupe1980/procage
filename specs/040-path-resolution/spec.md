# Feature Specification: Path resolution that cannot be redirected or mis-spelled

**Feature Branch**: `040-path-resolution` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

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

### Session 2026-11-03

- Q: What does Seatbelt do with spellings, as measured? → A: On macOS
  26.6.2 every path filter (`literal`, `subpath`, `prefix`, `regex`)
  matches case-insensitively and normalization-insensitively, on every
  volume. `realpath` keeps the spelling it is given. On a case-insensitive
  volume (the default), a rule in any spelling enforces on the file, so no
  rewrite is needed. On a case-sensitive volume a deny also covers the
  case variants (over-denying is safe). An allow does too: a write grant
  for `work` lets the child write and create `WORK` and `Work`, which are
  other files.
- Q: What does procage do about allows on a case-sensitive volume? → A: It
  refuses them. Building a cage fails with a typed error naming the path
  when an allow rule or a grant lies on a case-sensitive volume, as the
  longest existing prefix reports through `pathconf(_PC_CASE_SENSITIVE)`.
  Denies stay as they are. This is a fix and gets a security entry in the
  changelog.
- Q: Is a planted link the only way to move a T1 mount? → A: No. Renaming
  another directory into place moves it too. The parent records each
  planned object's device and inode. The child resolves the path without
  following links (`openat2` with `RESOLVE_NO_SYMLINKS`), checks the
  identity, and mounts on that descriptor (`open_tree`/`fsmount` with
  `move_mount`, read-only and sealing flags set by `mount_setattr` before
  the mount is attached). A cover whose path is gone is skipped, as
  before: an object moved to a new name is like a file created after the
  spawn, which is never covered.
- Q: What if the kernel lacks these calls? → A: The T1 probe makes the same
  calls. A host where they fail is not T1: the default choice is T2 with its
  typed gaps, and a cage that asks for T1 fails with `Unsupported::Tier`
  and the errno. Mounting by path is never a fallback.
- Q: What does the error name? → A: The path. When the child refuses a
  mount, the parent finds the first planned path that now resolves
  through a link or to another object, and returns
  `SpawnError::MountMoved` with that path and, if there is one, the link.
- Q: Linux case-folding directories? → A: Untested. Landlock rules and the
  T1 mounts follow inodes, not spellings. Matching data-class names in a
  case-folding directory is not covered by a lane, and the docs say so.
- Q: Which root is a mount path resolved beneath? → A: `/`. Plan paths are
  canonical (host links resolved at plan time), so every component from
  the root is resolved without following links, and a link found at mount
  time is new.
- Q: A rule for a path that does not exist yet, in a spelling that differs
  from a name created later? → A: It is emitted as written. Seatbelt
  matches it in any case and Unicode form, and on a case-sensitive volume
  an allow is refused by the longest existing prefix.
- Q: Is a link planted on macOS between canonicalisation and the child's
  access in scope? → A: No. Seatbelt evaluates at access time on the path
  the kernel resolves, and R-02 and R-04 cover renames and links there.

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
volume and a case-sensitive APFS volume (a disk image), each with paths in
mixed case and in composed and decomposed Unicode. Linux case-folding
directories are untested (FR-006).

**Acceptance Scenarios**:

1. **Given** a read deny spelled in another case than on disk, on a
   case-insensitive volume, **When** the child reads the file, **Then** it is
   denied — or the cage was refused with a typed error.
2. **Given** a name in decomposed Unicode on disk and composed in the rule,
   **When** the child accesses it, **Then** the result is the same as for the
   on-disk spelling, or the cage was refused.
3. **Given** a case-sensitive volume, **When** an allow rule names `a`,
   **Then** the cage is refused with a typed error naming the path. A deny
   naming `a` is kept, and also denies `A`.

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
  (protect, hide, data-class cover, socket cover, pin) by replacing a
  path component with a symbolic link or another directory between
  planning and mounting, and
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
  refused with a typed error; it MUST NOT silently match nothing. On macOS,
  an allow rule or grant on a case-sensitive volume MUST be refused, because
  Seatbelt would also allow its case variants.
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

- **SR-001** (P1): An escape canary MUST, for each T1 mount kind (protect, hide, data-class cover, socket cover, pin), replace a target component with a symbolic link or another directory between plan and mount, both at a deterministic hook and in racing attempts (10,000 in CI), and MUST record the outcome before and after the change.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.source-redirect`, `threat.vacuous-canary` via `mitigation.race-canary`
  - Given the build before the change and the deterministic hook, when the link is planted for each mount kind, then the canary records whether the mount was redirected
  - Given the build after the change, when 10,000 racing attempts run per mount kind, then no spawn runs with a redirected mount
- **SR-002** (P1): On T1 every mount source and target MUST be resolved beneath its planned root without following a symbolic link in any component; a link MUST fail the spawn with a typed error naming the path, even when the link points into a path the child may write.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.source-redirect` via `mitigation.no-follow-resolution`
  - Given a protected directory replaced by a link to another directory before the child mounts, when the spawn runs, then it fails with an error naming the path and the link target is unchanged
  - Given a hidden file whose parent directory became a link, when the spawn runs, then it fails the same way
  - Given a pin whose path was replaced by a link into the writable workspace, when the spawn runs, then it fails the same way
- **SR-003** (P1): The mount MUST apply to exactly the object planned: the child MUST check the resolved object's device and inode against the plan and attach by descriptor, and no step MUST resolve the path name again afterwards.
  - Mitigates: `threat.hide-redirect`, `threat.mount-redirect`, `threat.resolve-then-remount` via `mitigation.mount-by-descriptor`
  - Given a hook that renames a planned directory away and moves another real directory into its place, when the child mounts, then the spawn fails and the moved-in directory is not covered
- **SR-004** (P1): If the kernel lacks a call needed to resolve without following links or to mount by descriptor, T1 MUST be unavailable (the probe makes the same calls): the default is T2 with its typed gaps, a cage that asks for T1 MUST fail with Unsupported::Tier, and no mount MUST fall back to a path name.
  - Mitigates: `threat.kernel-fallback` via `mitigation.no-fallback`
  - Given the T1 probe, when it runs, then it mounts its tmpfs with fsopen, fsmount, openat2 and move_mount, so a host without them reports no T1
  - Given the child sequence, when it is reviewed, then no mount call takes a path name except the propagation change of the root
- **SR-005** (P2): The child's mount sequence MUST issue system calls only, with every path and buffer prepared in the parent, and MUST be covered by the multithreaded spawn test.
  - Mitigates: `threat.child-unsafe` via `mitigation.syscalls-only`
  - Given a parent whose other threads allocate and lock continuously, when 1,000 T1 spawns run with the new sequence, then all complete and the child sequence contains no allocation (review of the sys module)
- **SR-006** (P2): A spawn refused for a moved mount MUST return SpawnError::MountMoved naming the planned path and, if there is one, the link; vanished snapshot covers MUST keep being skipped and declared mounts MUST stay strict.
  - Mitigates: `threat.spawn-sabotage` via `mitigation.named-failure`
  - Given a planted link, when the spawn fails, then the error names the planned path and the link
  - Given the existing spawn and escape suites, when they run, then they pass unchanged
- **SR-007** (P1): On macOS a rule whose spelling differs from the on-disk name (case on a case-insensitive volume, Unicode form) MUST enforce on the file under every spelling the volume treats as the same name, or the cage MUST be refused with a typed error naming the rule; it MUST NOT silently match nothing.
  - Mitigates: `threat.case-miss`, `threat.unicode-miss` via `mitigation.exact-or-refuse`
  - Given a case-insensitive APFS volume and a read deny spelled in another case than on disk, when the child reads the file by its on-disk spelling, then it is denied, or the cage was refused
  - Given a name decomposed on disk and composed in the rule, when the child accesses it, then the result equals that of the on-disk spelling, or the cage was refused
- **SR-008** (P1): No allow MUST be widened by case folding or normalisation: an allow rule, an allowed Unix socket or a grant on a case-sensitive volume MUST refuse the cage with SpawnError::CaseSensitive naming the path, since Seatbelt would also allow its case variants.
  - Mitigates: `threat.fold-overgrant` via `mitigation.no-widening`
  - Given a case-sensitive APFS disk image with a write rule for a, when the cage is built, then it fails with CaseSensitive naming the path
  - Given a grant bound to a path on that image, when the spawn runs, then it fails the same way
  - Given a deny for a on that image, when the child reads A, then it is denied
- **SR-009** (P1): The spelling matrix MUST run as caged tests on the default volume and on a case-sensitive APFS image with case and Unicode variants, nested links, missing leaves and firmlinks; a macOS lane that cannot create the image MUST fail, not skip. Linux case-folding directories are untested and the docs MUST say so.
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
- **SC-003**: Median T1 spawn time rises by at most 10% (measured with
  `just bench` on T1 before and after).
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
