# Feature Specification: CI lanes for the releases people run

**Feature Branch**: `039-ci-lanes` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

**Input**: procage 0.1.0 was verified on macOS 26.6.2 and Ubuntu 24.04 (x86_64) only. macOS 27 and Ubuntu 26.04 are generally available, `ubuntu-latest` moves to 26.04 during November 2026, and many users run arm64 Linux and macOS 15. Every claim procage makes must hold on the releases its users run, and say which ones those are.

## Context

The kernel is the oracle: procage claims nothing about enforcement without a
caged child on a real kernel. At 0.1.0 the CI lanes were `macos-26` (arm64,
26.6.2), `ubuntu-24.04` (x86_64, Linux 7.0.0-azure, Landlock ABI 8) as shipped
(tier T2) and with the AppArmor user-namespace restriction lifted (tier T1),
plus gates and fuzzing.

Since then:

- **macOS 27** shipped (27.0 on 2026-09-14, 27.2 on 2026-10-26). GitHub's
  `xcode-27` image runs macOS 27 on arm64 and is generally available
  (2026-10-15). macOS 27 removed Seatbelt's *named* profiles from the SDK
  and `sandbox-exec -n` now kills the program; procage never used them, but a
  public report says deny-default profiles abort (exit 134) on 27.0.1 with
  narrow read rules, cause unknown. The base profiles were measured on 26.6.2
  only.
- **Ubuntu 26.04** is generally available on `ubuntu-26.04` and
  `ubuntu-26.04-arm`. Reports say its AppArmor defaults restrict unprivileged
  user namespaces more than 24.04, and that lifting the sysctl may no longer
  be enough for tier T1.
- **arm64 Linux** (`ubuntu-24.04-arm`) runs the same kernel as x86_64 but a
  different seccomp architecture check and syscall table.
- **macOS 15** is still offered (`macos-15`, arm64); macOS 14 retires on
  2026-11-02.

The repository is public, so standard runners cost nothing; the earlier sizing
of five jobs is no longer a constraint.

## Clarifications

### Session 2026-11-01

- Q: Which releases does procage support? → A: Exactly those with a green
  lane. README and SECURITY name them; a release without a lane is
  "untested", never "supported".
- Q: If macOS 27 needs more allowances, does a base profile change? → A: No
  frozen base changes. A needed entry becomes a new frozen base version with
  its own measurement; V1–V3 stay byte-identical.
- Q: Does a lane that cannot reach tier T1 fail? → A: No. Each lane states the
  tier it expects (`PROCAGE_EXPECT_TIER`); the kernel facts print what they
  observed. A lane that expected T1 and got T2 fails, and so does the reverse.
- Q: Does the Ubuntu 26.04 lane try to obtain T1? → A: It runs as shipped
  first (the tier users get). A second job lifts the restriction only if a
  documented, user-level way exists; otherwise T1 on 26.04 is recorded as
  unavailable without host changes.

### Session 2026-11-03

- Q: Does a documented host change made as root count as the way to reach
  T1? → A: Yes, if the distribution documents it for this purpose (Ubuntu's
  `kernel.apparmor_restrict_unprivileged_userns=0`). Turning AppArmor off or
  running the tests as root does not count. The tests always run as the
  runner user.
- Q: While a lane is temporarily unavailable, is its release still
  supported? → A: No. Supported means a green lane, with no grace period.
  The docs name the release untested and keep its last measured result
  with the date.
- Q: Where is the list of supported releases? → A: In the README's platform
  table: one row per lane, with the runner label, OS release and build or
  kernel, the measured tier and the date. SECURITY links that table instead
  of repeating it.
- Q: How does a lane assert its macOS major version and architecture? → A:
  The kernel-facts runner reads `PROCAGE_KF_EXPECT_MACOS` and
  `PROCAGE_KF_EXPECT_ARCH`, as it reads the expected tier, and fails the
  step naming what it expected and what it measured. On macOS the label
  names an Xcode image (`xcode-27`), not an OS.
- Q: What checks the workflows and the docs? → A: One `workflows` gate in
  the justfile, written in bash, with no new tool. It checks that actions
  are pinned to full SHAs, the token is read-only and no test job widens
  it, no secrets, no `pull_request_target` or `workflow_run`, no
  `github.event` or `github.head_ref` inside a run script, no cache steps
  and no `continue-on-error`. It also checks that every runner label in
  `ci.yml` is in the README's platform table, and the reverse.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - procage is proven on macOS 27 (Priority: P1)

A maintainer of an agent harness on macOS 27 reads that procage is tested
there, with the build number, and that the base profiles run the reference
program set.

**Why this priority**: macOS 27 is the current macOS; a deny-default regression
there would break every caged program, and procage could not see it.

**Independent Test**: The `xcode-27` lane runs the kernel facts, the spawn
tests, the base program-set tests, the escape suite (also with violation
reporting and on the newest base) and the profile-compile check, and passes.

**Acceptance Scenarios**:

1. **Given** the macOS 27 lane, **When** the kernel facts run, **Then** the
   report header shows macOS 27.x with its build and `sandboxed: no`, and
   every fact passes or a changed fact is recorded with the build.
2. **Given** a base profile that fails a program on 27, **When** the cause is
   measured, **Then** a new frozen base version carries the entry, and the
   older versions are unchanged.
3. **Given** the fact that compiles `(import "system.sb")`, **When** macOS 27
   no longer ships that profile, **Then** the fact records the change; no
   shipped profile depends on it.

---

### User Story 2 - The tier on Ubuntu 26.04 is known (Priority: P1)

A user on Ubuntu 26.04 (the new `ubuntu-latest`) learns which tier procage
gives as shipped, and what it would take to get T1.

**Independent Test**: The `ubuntu-26.04` lane runs the Linux kernel facts,
spawn tests and escape suite with its expected tier and passes.

**Acceptance Scenarios**:

1. **Given** stock Ubuntu 26.04, **When** the probe runs, **Then** the lane
   prints the observed tier, Landlock ABI and errata, and the tests pass
   for that tier.
2. **Given** the docs, **When** a user reads the platform table, **Then** it
   states the tier for 26.04 as measured.

---

### User Story 3 - arm64 Linux and macOS 15 (Priority: P2)

Users on arm64 Linux servers and on macOS 15 get the same evidence.

**Independent Test**: `ubuntu-24.04-arm` (T1 and T2) and `macos-15` lanes
pass the same suites as their x86_64 / macOS 26 counterparts.

**Acceptance Scenarios**:

1. **Given** arm64 Linux, **When** the seccomp tests run, **Then** the
   architecture check and every refused system call behave as on x86_64.
2. **Given** macOS 15, **When** the suites run, **Then** they pass, or the
   lane is removed and macOS 15 is named "untested" — never kept red.

### Edge Cases

- A runner image updates its OS mid-month: the lane prints the build, so a
  change in a fact is attributable to an image.
- The `xcode-27` label maps to an Xcode version, not an OS version: the lane
  asserts the major macOS version it expects, so a silent image change fails
  loudly.
- A lane is temporarily unavailable (preview withdrawn): the job is
  removed, and the docs name its release untested with the last measured
  result and its date.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: CI MUST run, on macOS 27 (arm64), the kernel facts, the caged
  spawn tests, the base program-set tests, both escape-suite variants and
  the profile-compile check.
- **FR-002**: CI MUST run the Linux kernel facts, spawn tests and escape
  suite on Ubuntu 26.04 as shipped, and on arm64 Ubuntu in tiers T1 and T2.
- **FR-003**: CI MUST run the macOS suites on macOS 15 (arm64), or the docs
  MUST name macOS 15 untested.
- **FR-004**: Every lane MUST print its OS release and build (or kernel
  release), architecture, sandbox status and observed tier, and MUST assert
  the macOS major version or Linux tier it expects.
- **FR-005**: The README's platform table MUST list the supported releases
  as exactly the green lanes, with the runner label, build or kernel,
  measured tier (Linux) and date. SECURITY MUST link that table.
- **FR-006**: A base-profile change needed by a newer macOS MUST be a new
  frozen base version with its own program-set measurement; existing base
  versions MUST stay byte-identical (their fixtures unchanged).
- **FR-007**: The workflow MUST keep SHA-pinned actions, read-only tokens and
  no secrets in test jobs.

### Key Entities

- **Lane**: a CI job with an OS image, architecture, expected tier (Linux) or
  macOS major version and architecture, and the suites it runs.
- **Lane report**: the printed header (OS, build, arch, sandboxed, tier, ABI,
  errata) kept in the job log as evidence.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Every action a workflow uses MUST be referenced by a full 40-character commit SHA; a gate MUST fail on any tag, branch or short-SHA reference.
  - Mitigates: `threat.action-supply-chain` via `mitigation.sha-pins`
  - Given a workflow step using an action at a tag such as v4, when the workflows gate runs, then it fails naming the file and line
  - Given the workflows on main, when the workflows gate runs, then it passes and every reference carries its version as a comment
- **SR-002** (P1): Every workflow MUST default to a read-only token; test lanes MUST NOT widen permissions or reference secrets, and no workflow MAY run pull-request code under pull_request_target or workflow_run.
  - Mitigates: `threat.cache-poisoning`, `threat.expression-injection`, `threat.token-overreach` via `mitigation.least-privilege-workflow`
  - Given the CI workflow, when the workflows gate parses it, then the top-level permissions are contents read, no test job sets permissions, and no step references secrets
  - Given a pull request from a fork, when its lanes run, then the token cannot push, and the job has no secrets
- **SR-003** (P2): Run steps MUST NOT interpolate pull-request or commit text into scripts (pass it through environment variables), and the CI workflow MUST NOT use cache steps, so no lane restores a cache a pull-request job saved.
  - Mitigates: `threat.cache-poisoning`, `threat.expression-injection`, `threat.token-overreach` via `mitigation.least-privilege-workflow`
  - Given the workflows, when the workflows gate searches run steps for github.event and github.head_ref expressions, then none appear inside a run script
  - Given a cache step added to the CI workflow, when the workflows gate runs, then it fails naming the file and line
- **SR-004** (P1): Every lane MUST print its OS release and build (or kernel release), architecture, sandbox status, observed tier, Landlock ABI and errata, and MUST fail when the macOS major version, architecture or Linux tier differs from what it expects.
  - Mitigates: `threat.silent-image-change`, `threat.silent-tier-change` via `mitigation.assert-expected`
  - Given the macOS 27 lane expecting major version 27 on arm64, when the image reports another major version or architecture, then the lane fails naming expected and observed
  - Given a Linux lane with PROCAGE_EXPECT_TIER=T1, when the probe observes T2, or a T2 lane observes T1, then the lane fails
  - Given any green lane, when its log is read, then the report header shows release, build, architecture, sandboxed no and tier
- **SR-005** (P1): In CI an enforcement test MUST fail, never skip, when it cannot run (AlreadySandboxed, missing administrator rights, a missing feature), and a lane whose release is named supported MUST NOT be continue-on-error.
  - Mitigates: `threat.pass-without-evidence` via `mitigation.no-skip-green`
  - Given a lane run inside an outer sandbox, when the enforcement tests run, then they fail with AlreadySandboxed
  - Given the workflow, when the workflows gate reads it, then no lane of a supported release has continue-on-error
- **SR-006** (P2): The README platform table MUST list as supported exactly the releases with a green lane, each with its runner label, build or kernel, architecture, measured Linux tier and measurement date; SECURITY MUST link that table, and the docs MUST name every other release untested.
  - Mitigates: `threat.evidence-expiry`, `threat.stale-claims` via `mitigation.docs-from-lanes`
  - Given a lane removed from the workflow while its label stays in the README table, when the workflows gate runs, then it fails naming the label
  - Given a runner label in the workflow missing from the README table, when the workflows gate runs, then it fails naming the label
  - Given the platform table, when it is read, then every Linux lane has its measured tier and date, and macOS 14 and any lane removed are named untested
- **SR-007** (P1): Existing base profile versions MUST stay byte-identical; an entry a newer macOS needs MUST be a new frozen base version with its own program-set measurement on that release.
  - Mitigates: `threat.frozen-base-drift` via `mitigation.new-base-version`
  - Given the fixtures of base V1 to V3, when CI compiles each base, then the output equals the fixture byte for byte
  - Given a base entry added for macOS 27, when it is reviewed, then it is in a new base version whose program-set test passed on the 27.x lane with the build recorded
- **SR-008** (P2): A T1 job MUST apply only the documented step that lifts the user-namespace restriction, MUST log that step and run the tests unprivileged; where no such step exists, the docs MUST record T1 as unavailable without host changes.
  - Mitigates: `threat.t1-unrepresentative` via `mitigation.representative-t1`
  - Given a T1 job, when its log is read, then it shows the exact step applied and the tests ran as a non-root user
  - Given Ubuntu 26.04 with no documented step, when the docs are read, then they state T1 is unavailable there without host changes
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: All lanes of FR-001…FR-003 are green on `main`, or a lane is
  removed and its release named untested.
- **SC-002**: The macOS 27 deny-default question is answered with the 27.x
  build: either no change needed (base program set green) or a new base
  version with the entries and their evidence.
- **SC-003**: The platform table in the README states the tier for every
  Linux lane as measured, with the date.

## Assumptions

- GitHub keeps `xcode-27`, `ubuntu-26.04`, `ubuntu-24.04-arm` and `macos-15`
  available to public repositories at no cost.
- The macOS runners run as an administrator account (violation reporting
  works there, as measured on `macos-26`).

## Out of Scope

- Intel macOS lanes and Rosetta (no Intel image for macOS 27).
- Kernel version matrices beyond the runners' kernels (spec 044).
