# Feature Specification: Moves between writable directories, and link-check exemptions

**Feature Branch**: `045-moves-and-link-exemptions` (planning directory; commits land on `main`)

**Created**: 2026-11-02

**Status**: Implemented (2026-11-02)

**Input**: A harness that runs every command of a coding agent in a cage reports three problems with 0.2.0. (1) On Linux no file can move or link between directories, even inside one writable tree: Landlock answers `EXDEV`, so rustc's rename of its metadata into `target/` fails and no `cargo build` works; package managers and atomic saves fail the same way. (2) Running in place with `.git` protected, a local `git clone`'s hard-linked objects refuse every spawn. (3) git's automatic `gc --auto` prints `setsid failed` in a cage.

## Context

procage never grants Landlock's `REFER` right, which every rename or link
to another directory needs, so that a move could not carry a protected file
out from under its rule (escape classes R-04 and R-30) or give it a second
name (R-08). Landlock itself refuses a move or link that would give the file
a right it lacks where it is, or that leaves a directory without `REFER`;
on tier T1 protected and hidden targets are separate mounts, which no move
or link crosses; on tier T2 a protected or hidden path inside a writable
tree is a gap, refused unless relaxed. Withholding `REFER` from writable
trees therefore protects nothing that is not already protected, and breaks
builds.

The link check refuses a spawn when a protected file has a second name. A
local clone hard-links every object to the source repository's object
store. Git objects are written once, read-only, and never rewritten in
place; the check is right for `.git/config`, hooks and refs.

## Clarifications

### Session 2026-11-02

- Q: Where is `REFER` granted? → A: With `Write`, wherever the ABI handles
  it (2 and later), on both tiers; never with read, exec, protect or hide.
  On T2 nothing protected lies in a writable tree without a reported gap, so
  no per-tree withholding is needed.
- Q: ABI 1 (Linux 5.13 to 5.18)? → A: Landlock cannot grant `REFER` there:
  every move between directories fails. Documented as a limit, not a gap
  (it denies more, never less).
- Q: The shape of the exemption? → A: `CageOptions::with_link_exemption(path)`,
  any number, absolute paths (a relative one fails the cage with
  `Unsupported::Setting`). An exempt subtree is neither walked nor counted
  for protected names; hidden files are examined everywhere, since a second
  name there would expose a secret. `Audit::links_exempt` lists a run's
  exemptions. The receipt keeps its fields (no format change).
- Q: `setsid`? → A: No code change: `Lifetime::Run` refuses it by design.
  The lifetime docs name git's `gc.autoDetach=false`.

## User Scenarios & Testing

### User Story 1 - Builds move files between directories (Priority: P1)

A build in a writable workspace with a private `TMPDIR` renames and links
files between directories of the workspace and the temporary directory.

**Acceptance Scenarios**:

1. **Given** a policy writing `ws` and a `tmpdir` grant on Landlock ABI 2 or
   later, **When** the child renames `ws/a/x` to `ws/b/x`, links it back to
   `ws/a/y` and moves a file from `TMPDIR` into `ws/b`, **Then** each
   succeeds on T1 and T2; on ABI 1 each fails with `EXDEV`.
2. **Given** `ws/bin` executable on top of the write rule, **When** the child
   moves a file of `ws/a` into `ws/bin`, **Then** Landlock refuses it with
   `EXDEV` (the file would gain execute).
3. **Given** a read-only tree, **When** the child moves or links a file of it
   into `ws`, **Then** both fail and the file is unchanged.

### User Story 2 - Protected and hidden files stay out of reach (Priority: P1)

**Acceptance Scenarios**:

1. **Given** T1 with `ws/sub/p` protected, **When** the child renames
   `ws/sub` in place and then into another directory, **Then** the protected
   file is unwritable under every name and keeps its content.
2. **Given** T1 with the file `ws/f` protected, **When** the child renames a
   file from another directory of `ws` onto it, **Then** the rename fails
   with `EBUSY`.
3. **Given** a hidden file and a protected one (on T2 a file of a read-only
   tree stands in), **When** the child links either into `ws`, **Then** both
   fail.
4. **Given** T2, **When** a policy protects a path, or hides one in a
   writable tree, **Then** the cage is refused with a gap, as before.

### User Story 3 - A local clone runs in place (Priority: P2)

**Acceptance Scenarios**:

1. **Given** a clone whose objects are hard-linked to the source's and
   `.git` protected, **When** spawning without an exemption, **Then** the
   spawn is refused naming the object.
2. **Given** the same with `.git/objects` exempt, **When** spawning, **Then**
   the run starts and its audit lists the exemption.
3. **Given** the exemption and a second name for `.git/config`, **When**
   spawning, **Then** the spawn is refused naming the config.
4. **Given** a hidden tree containing the exempt path, **When** a file there
   has a second name, **Then** it is a finding.
5. **Given** a relative exemption, **When** building the cage, **Then** it
   fails with `Unsupported::Setting`.

### Edge Cases

- An exempt path that is itself a protect target, or contains a literal
  target: neither is examined for protected names.
- An exempt path that does not exist: kept as given; nothing to skip.
- macOS: Seatbelt already allows moves within writable trees; the
  exemption works the same.

## Requirements

### Functional Requirements

- **FR-001**: `procage_policy::linux::rights(Access::Write, handled)` MUST
  include `REFER` when `handled` does, and no other access MUST include it.
- **FR-002**: The Linux escape suite MUST show moves and links between
  writable directories working from ABI 2, a move that gains a right
  refused, moves out of a read-only tree refused, and R-04, R-08 and R-30
  holding with cross-directory variants.
- **FR-003**: `CageOptions::with_link_exemption` MUST exist on both backends,
  skip exempt subtrees for protected names only, record the exemptions in
  `Audit::links_exempt`, and refuse relative paths.
- **FR-004**: The link-check refusal message MUST name the exemption as a way
  out besides `LinkAudit::Report` and `LinkAudit::Off`.
- **FR-005**: The lowering table, the Linux limits, the audits and lifetime
  docs, the threat model and the changelog MUST describe the new behaviour.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): A move between directories MUST NOT take a protected target out from under its protection or replace it: on T1 it stays unwritable under every name and a rename onto it fails; on T2 protect stays a refused gap.
  - Mitigates: `threat.link-gives-second-name`, `threat.move-carries-protected`, `threat.move-gains-right` via `mitigation.refer-with-write-only`
  - Given T1 with ws/sub/p protected, when the child renames ws/sub in place and into another directory, then the protected file is unwritable under every name and keeps its content
  - Given T1 with the file ws/f protected, when the child renames a file from another directory onto it, then the rename fails with EBUSY (EXDEV at ABI 1)
  - Given T2, when a policy protects a path, then the cage is refused with an fs-protect gap
- **SR-002** (P1): During a run no hidden or protected file MUST gain a second name in a writable tree.
  - Mitigates: `threat.link-gives-second-name`, `threat.move-carries-protected`, `threat.move-gains-right` via `mitigation.refer-with-write-only`
  - Given a hidden file and a protected one (on T2 a file of a read-only tree), when the child links either into the writable tree, then both links fail on every tier
- **SR-003** (P1): REFER MUST be granted only with write; a move or link that would give a file a right it lacks, or take it out of a read-only tree, MUST be refused, while moves between writable directories MUST work from ABI 2.
  - Mitigates: `threat.link-gives-second-name`, `threat.move-carries-protected`, `threat.move-gains-right` via `mitigation.refer-with-write-only`
  - Given the rights of every access kind, when computed at ABI 1, 2 and 12, then only write at ABI 2 or later includes REFER
  - Given ws writable with ws/bin executable and a read-only tree, when the child moves a file into ws/bin, or moves or links one out of the read-only tree, then each is refused, while moves and links between ws directories and from TMPDIR succeed (EXDEV at ABI 1)
- **SR-004** (P1): A link exemption MUST skip only the named subtrees, and only for protected files; a second name of any other protected file MUST still refuse the spawn, and the run audit MUST list the exemptions.
  - Mitigates: `threat.exempt-object-rewritten`, `threat.exemption-hides-handoff`, `threat.exemption-hides-secret`, `threat.relative-exemption` via `mitigation.exemption-scoped`
  - Given a clone with hard-linked objects and .git protected, when spawning without and then with .git/objects exempt, then the first is refused naming the object; the second runs and its audit lists the exemption
  - Given the exemption and a second name for .git/config, when spawning, then the spawn is refused naming the config
- **SR-005** (P1): Hidden files MUST be examined inside exempt subtrees.
  - Mitigates: `threat.exempt-object-rewritten`, `threat.exemption-hides-handoff`, `threat.exemption-hides-secret`, `threat.relative-exemption` via `mitigation.exemption-scoped`
  - Given a hidden tree containing an exempt subtree with a two-name file, when the link check runs, then the file is a finding
- **SR-006** (P2): A relative link exemption MUST fail the cage.
  - Mitigates: `threat.exempt-object-rewritten`, `threat.exemption-hides-handoff`, `threat.exemption-hides-secret`, `threat.relative-exemption` via `mitigation.exemption-scoped`
  - Given CageOptions with a relative exemption, when the cage is built, then it fails with Unsupported::Setting
<!-- threatspec:end -->

## Success Criteria

- **SC-001**: `cargo build` inside a Linux cage writing the workspace with a
  private `TMPDIR` succeeds on ABI 2 and later (the escape canary stands in:
  rustc's rename into `target/` is the same system call).
- **SC-002**: Every existing R-04, R-08 and R-30 canary passes unchanged in
  meaning on macOS, T1 and T2.
