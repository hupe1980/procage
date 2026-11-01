# Feature Specification: The escape suite

**Feature Branch**: `009-escape-suite`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "009-escape-suite: Feature `escape-suite`: one canary per escape class, both OSes, every CI lane."

## Context

procage publishes a catalog of 20 escape classes in `THREAT_MODEL.md`
(feature 002). Each class has a disposition and a status. Today every
status is `planned` or `documented`: no release has claimed a class as
handled, because the evidence rule demands a test that runs a
caged child on a real kernel and observes the outcome.

Features 004–008 built most of the machinery the classes need, on both
systems:

- the macOS canonicaliser;
- the hard-deny tier: fcntl, service handoff, process access, rename
  anchors, terminal injection, the data-driven classes;
- the fd sweep, environment hygiene, private temporary directories and
  tree kill;
- Linux seccomp, mounts and Landlock.

Several of these have no caged test aimed at the escape itself. Some
classes are known to be open in this release:

- the macOS double-fork escape (R-23);
- the helper, which does not exist yet (R-26);
- the hard-link audit (R-08).

This feature builds the **escape suite**: for every class and every
platform the class applies to, at least one **canary**. A canary is a
caged child that attempts the escape and asserts that the kernel refuses
it, or, for a `detect` class, that procage reports it. The suite then
decides the catalog: a class becomes `mitigated` only when its canaries
pass on every platform it applies to.

The suite is a contract. A gate checks that every class has its canaries,
that every claimed status is backed by a passing canary, and that open
variants are named. The suite runs in every CI lane.

## Clarifications

### Session 2026-10-30

- Q: What happens to a class whose canaries pass on one platform or for
  one variant but not another (for example R-23: tree kill works, the
  double-fork variant escapes on macOS)? → A: A new status `partial`. It
  needs at least one passing canary as evidence and a published note
  under `### Open variants` that names what is still open. `mitigated`
  needs a passing canary on every platform the class applies to.
- Q: How is an open variant represented in the suite? → A: As a canary
  that asserts the refusal like any other, marked ignored with a reason
  that starts `open: R-NN`. Running the ignored tests shows the escape.
  An ignored canary is never evidence.
- Q: Does this feature add new mitigations when a canary shows an escape?
  → A: No. It fixes a defect in a mitigation that procage already claims
  or emits (the hard-deny tier, hygiene, the canonicaliser). A class with
  no mitigation in the code stays `planned` or `partial`; its fix becomes
  a follow-up feature.
- Q: Where do the canaries live, and how does the gate find them? → A: In
  two integration-test files, one per system (`tests/escape_macos.rs` and
  `tests/escape_linux.rs`). A canary's function name starts with the class
  id in lower case (`r21_…`), so the gate can map functions to classes by
  name alone.
- Q: Must downstream crates be able to run the suite in their own CI?
  → A: Not in this feature. The canaries are integration tests of this
  repository. A packaged, reusable suite is a later feature.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Each escape class has canaries that run caged children (Priority: P1)

A maintainer runs the escape suite on a macOS host and in both Linux
containers (T1 and T2). For every escape class and platform it applies
to, at least one canary spawns a caged child that tries the escape. The
run shows which classes procage stops and which remain open.

**Why this priority**: Without the canaries, procage can claim nothing.
This is the evidence the constitution (principle III) asks for.

**Independent Test**: `cargo test --test escape_macos` on macOS and the
Linux escape tests in the T1 and T2 containers pass. Every class in the
catalog has at least one canary function per platform it lists.

**Acceptance Scenarios**:

1. **Given** a class that applies to macOS, **When** the macOS suite runs,
   **Then** at least one canary for it spawns a caged child and asserts the
   escape attempt is refused (or, for R-08, reported), and the canary
   passes or is marked open with the class id.
2. **Given** a class that applies to Linux, **When** the Linux suite runs
   on T1 and on T2, **Then** each canary either asserts refusal on that
   tier or asserts that the cage refuses to start with a typed error (fail
   closed), and none skips silently.
3. **Given** a canary for a closed class, **When** the corresponding
   mitigation is removed from the code (defect injection), **Then** the
   canary fails.
4. **Given** the development machine runs inside another Seatbelt
   sandbox, **When** the macOS suite runs, **Then** it fails with
   `AlreadySandboxed`; it never skips.

---

### User Story 2 - The published catalog tells the truth (Priority: P1)

A user reading `THREAT_MODEL.md` sees, per class:

- whether this release mitigates it, mitigates part of it, or not yet;
- which canary proves it;
- for a partial class, what is still open.

**Why this priority**: The catalog is the contract users rely on to
decide whether procage fits their threat model. A status without
evidence, or open variants without a note, misleads them.

**Independent Test**: The catalog gate passes. Every injected defect
below makes exactly one rule fire:

- a `mitigated` class with a canary on one platform only;
- evidence that is an ignored canary;
- a `partial` class without a note;
- a class missing a canary.

**Acceptance Scenarios**:

1. **Given** a class marked `mitigated`, **When** the gate runs, **Then** its
   evidence lists at least one non-ignored canary in the escape-suite file
   of every platform the class applies to.
2. **Given** a class marked `partial`, **When** the gate runs, **Then** its
   evidence lists at least one non-ignored canary and an entry for it
   exists under `### Open variants`.
3. **Given** any published class, **When** the gate runs, **Then** each
   platform it lists has at least one canary function named for the class
   in that platform's escape-suite file.
4. **Given** the release-status section, the README and the crate docs,
   **When** a reader compares them with the catalog, **Then** none claims
   more than the catalog does, and each class still open is named in the
   release status.

---

### User Story 3 - The suite runs in every CI lane (Priority: P2)

A maintainer pushes and every CI lane runs the escape suite:

- the macOS lanes;
- the Ubuntu lanes, as shipped (T2) and with the user-namespace
  restriction lifted (T1);
- the Debian container (T2).

Each Linux lane states the tier it expects, so a lane that silently runs
on a lower tier fails.

**Why this priority**: A canary that runs on one developer kernel proves
little. CI lanes give the second kernel, the second architecture and the
newest macOS. It is P2 because the lanes run only after a push, which the
user triggers.

**Independent Test**: The workflow file lists the escape suite in every
macOS and Linux lane, each Linux lane sets its expected tier, and the
local `just` recipes run the same suite in both containers.

**Acceptance Scenarios**:

1. **Given** the CI workflow, **When** it is read, **Then** every macOS
   lane runs the macOS escape suite and every Linux lane runs the Linux
   escape suite and the Linux spawn tests with an expected tier.
2. **Given** a Linux lane whose host offers a lower tier than the lane
   expects, **When** the suite runs, **Then** it fails with a tier
   mismatch.

### Edge Cases

- **Kernel blocks for its own reasons.** Docker's default seccomp
  profile, AppArmor or Yama refuse the attempt without procage. On T2 in
  Docker, most syscall canaries are uninformative. The canary still
  passes; its evidence comes from the T1 lane, and the suite records which
  lanes were informative.
- **Missing tools.** A canary needs a program the host may lack (for
  example `osascript`). It uses system calls from the test binary itself
  instead of external programs wherever it can.
- **Side effects on the host.** A canary that tries Launch Services,
  Apple events or the pasteboard must not open an application or change
  the pasteboard if the escape succeeds. The attempt is a service lookup,
  not an action.
- **Persistence attempts.** A canary that tries persistence writes only
  into a fake home or a scratch directory, never the real launch-agent or
  cron locations, so a failing canary leaves nothing behind.
- **Time.** No canary waits longer than a few seconds. A descendant that
  outlives the run is detected by polling with a bound.
- **Tier-dependent outcomes.** On T2, some constructs (protect, hide) are
  refused before any child runs. For those classes the canary asserts the
  typed refusal: fail closed counts as handled.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Every published escape class MUST have at least one canary
  for each platform its catalog row lists.
- **FR-002**: A canary MUST spawn a real caged child through the public
  spawn API and observe the outcome from the kernel or from procage's
  report. An emitted profile or filter is never a canary's only check.
- **FR-003**: A canary for a `mitigate` class MUST assert that the escape
  attempt fails with the expected refusal. On a tier that cannot express
  the protection, it MUST instead assert a typed refusal before any child
  runs. A canary for a `detect` class MUST assert that procage reports the
  condition.
- **FR-004**: A canary for a variant this release does not handle MUST be
  marked ignored with a reason starting `open: R-NN`. It still asserts
  refusal, so running it shows the escape.
- **FR-005**: A canary's function name MUST start with its class id in
  lower case followed by an underscore (`r09_…`).
- **FR-006**: The catalog MUST gain the status `partial`, allowed for the
  `mitigate` and `detect` dispositions. It needs evidence and an entry
  under a new `### Open variants` subsection that names what is open.
- **FR-007**: The gate MUST check:
  - every listed platform has a canary for every class;
  - evidence entries point to the platform escape-suite files;
  - an ignored canary is never evidence;
  - a `mitigated` or `detected` class has non-ignored evidence on every
    listed platform;
  - a `partial` class has evidence and an `### Open variants` entry.
  Each rule has a defect-injection test.
- **FR-008**: Each class status MUST follow from the suite's results on
  the local macOS host and both Linux containers. A class is `mitigated`
  only when every canary for every listed platform passes un-ignored.
- **FR-009**: Where a canary shows that a mitigation procage already
  emits or claims does not hold, this feature MUST fix the defect, or
  keep the class open and name the variant. It MUST NOT add a mitigation
  that the code does not have.
- **FR-010**: The release status in `THREAT_MODEL.md`, the README and
  the crate docs MUST be updated to match the catalog, and MUST still name
  every open variant.
- **FR-011**: Every macOS CI lane MUST run the macOS escape suite. Every
  Linux CI lane MUST run the Linux escape suite and the Linux spawn tests,
  with the tier the lane expects.
- **FR-012**: The `just` recipes that run the Linux containers MUST run the
  escape suite, and a recipe MUST run the macOS suite.
- **FR-013**: Canaries MUST NOT change state outside scratch directories:
  - no real pasteboard writes;
  - no application launches;
  - no writes to the real launch-agent, cron or shell-startup locations.
- **FR-014**: Every class that stays open MUST have a recorded follow-up
  item, kept in the project planning (not in published files).

### Key Entities

- **Escape class**: a published catalog row (id, class, platforms,
  disposition, status, evidence, observed on). Ids are unchanged.
- **Canary**: a test function in a platform escape-suite file. Its name
  is prefixed with a class id. It is either active or open (ignored with
  the class id).
- **Open variant**: a named way a class still escapes in this release. It
  is published under `### Open variants` and linked to an open canary.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every active canary MUST assert the specific refusal (errno or typed error) and MUST include a positive control showing the same operation succeeds where the policy allows it.
  - Mitigates: `threat.false-pass`, `threat.uninformative-lane` via `mitigation.positive-control`
  - Given a canary for a file-based class, when the child attempts the escape and the control, then the control succeeds and the attempt fails with the expected errno
  - Given a canary whose attempt target does not exist, when it runs, then it fails rather than passes
- **SR-002** (P1): A syscall canary MUST report whether its lane was informative, and a kernel-surface class MUST NOT be marked mitigated from uninformative lanes alone.
  - Mitigates: `threat.false-pass`, `threat.uninformative-lane` via `mitigation.positive-control`, `mitigation.informative-report`
  - Given the Docker default seccomp lane, when the R-28 canary runs, then it passes and prints which attempts were uninformative
  - Given the T1 lane, when the R-28 and R-29 canaries run, then the uncaged controls succeed and the caged attempts fail with EPERM
- **SR-003** (P1): The gate MUST reject a mitigated or detected class without a non-ignored canary on every listed platform, evidence outside the platform escape-suite files, ignored canaries as evidence, and a mitigated class that has an open canary.
  - Mitigates: `threat.hidden-open-variant`, `threat.overclaimed-status` via `mitigation.gate-rules`
  - Given a class marked mitigated with a macOS canary only but listing Linux, when the gate runs, then exactly the per-platform evidence rule fires
  - Given evidence naming an ignored canary, when the gate runs, then the ignored-evidence rule fires
  - Given an open canary for a mitigated class, when the gate runs, then the open-canary rule fires
- **SR-004** (P1): Every class MUST have a canary per listed platform, and a partial class MUST have an entry under Open variants; the release status MUST name every open class.
  - Mitigates: `threat.hidden-open-variant`, `threat.overclaimed-status` via `mitigation.gate-rules`
  - Given a class with no canary for one listed platform, when the gate runs, then the coverage rule fires
  - Given a partial class without a note, when the gate runs, then the open-variant rule fires
- **SR-005** (P1): The suite MUST fail, never skip, when the parent is already sandboxed or the host tier differs from the expected tier, and every CI lane MUST run it with its expected tier.
  - Mitigates: `threat.silent-skip` via `mitigation.no-skip`
  - Given a T2 container with PROCAGE_EXPECT_TIER=T1, when the Linux suite runs, then it fails with a tier mismatch
  - Given the CI workflow, when it is read, then every macOS and Linux lane runs the suite and Linux lanes set the expected tier
- **SR-006** (P2): Canaries MUST NOT write outside scratch directories, write the real pasteboard, launch applications, or leave processes running.
  - Mitigates: `threat.canary-side-effect`, `threat.surviving-descendant` via `mitigation.scratch-only`
  - Given a full suite run including the open canaries, when it ends, then no canary process is alive and no file outside scratch directories changed
- **SR-007** (P2): For each system at least one covered mitigation MUST be removed in a defect-injection run and a canary MUST fail; at least five defects in total.
  - Mitigates: `threat.false-pass`, `threat.mitigation-regression` via `mitigation.defect-injection`
  - Given a mitigation removed from the code, when the suite runs, then the canary for its class fails
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the 20 published classes have at least one canary on
  each listed platform (32 class-platform pairs).
- **SC-002**: Every class status in the catalog matches the suite's
  results, and the gate passes.
- **SC-003**: Every defect injected into a mitigation that a passing
  canary covers is caught by at least one canary: at least one defect per
  system, of at least five.
- **SC-004**: The full escape suite runs in under 60 seconds per platform
  and per tier on the development machine.
- **SC-005**: Zero canaries leave files outside scratch directories or
  running processes after the suite finishes.

## Assumptions

- The local evidence comes from macOS 26.6.2 on arm64 and Docker Desktop
  Linux 7.0.14-linuxkit on aarch64 (T1 and T2, Landlock ABI 8). CI lanes
  run after a push, which the user triggers.
- Linux network policies other than `None` and `All` are gaps on Linux in
  this release (008), so the Linux R-09 canaries cover `None` and the
  typed refusal of `Loopback` and `UnixSockets` below ABI 9.
- R-26 (helper replacement) has no helper to attack in this release, so
  its canaries are open until the helper ships.
- The kernel-facts suite stays as it is: its observations never count as
  evidence.
