# Feature Specification: Base profile V2 — developer tools work in a cage

**Feature Branch**: `027-base-v2` (planning directory; commits land on `main`)

**Created**: 2026-10-31

**Status**: Draft

**Input**: User description: "027-base-v2: macOS `Base::V2`: `com.apple.bsd.dirhelper` and other services measured from consumer workloads; V1 stays frozen. Research it; we want a great developer experience."

## Context

procage's base profile V1 lets ordinary programs start on macOS. It was
measured with Apple's command-line tools and shells, not with developer
tools. A consumer harness found Xcode's tool shims (`git`,
`python3`) running a second slower without one Mach service. Research
for this spec ran 27 developer workloads under V1 in an agent-shaped policy
(writable workspace, private `TMPDIR`, fork, no network) on macOS 26.6.2,
recorded exit codes, timing and stderr, and read every sandbox denial from
the unified log (session harness, `research-harness.rs.txt`):

- **Every Xcode shim fails** under V1 (`git`, `clang`, `make`, `xcrun`,
  `swift`, `python3`): `xcode-select` cannot read
  `/var/db/xcode_select_link` or the developer directory.
- Ruby fails (its gem directory under `/Library/Ruby`); Homebrew tools
  cannot run (`/opt/homebrew` is not readable); Homebrew's `node` and `npm`
  also need OpenSSL's configuration under `/opt/homebrew/etc`.
- The service the consumer suggested, `com.apple.bsd.dirhelper` (and
  `com.apple.system.opendirectoryd.membership`), is **harmful**: with
  either, `confstr(_CS_DARWIN_USER_TEMP_DIR)` returns the user's shared
  per-user temporary directory, so `mktemp` and xcrun write there (refused,
  and they must be: xcrun's tool cache in that directory is read by
  unsandboxed `xcrun` later). Without them, libSystem falls back to
  `$TMPDIR`, the run's private directory, and everything works.
- With the developer directory readable and the system Xcode preferences
  file readable (the license check), the shims work; the first call per
  `TMPDIR` takes about a second (xcrun fills its cache, running
  `xcodebuild` once), later calls run at native speed (10 ms against 13 ms
  uncaged).
- `git` exits when it cannot read `~/.gitconfig` (macOS returns `EPERM`,
  which git treats as fatal): a setting for the caller (`GIT_CONFIG_GLOBAL`
  or `HOME`), not for a base profile.
- On Linux, V1 already runs `git`, `python3`, `cc`, `make`, `perl`, `curl`,
  `tar`, `mktemp`, `cargo` and `rustc` (Docker, T1 and T2) when `TMPDIR`
  and the toolchain variables are set.
- Denials that stay: logging (`logd`, `diagnosticd`), analytics, the
  DTrace helper ioctl (kernel attack surface), other processes' info,
  LaunchServices and the Command Line Tools installer (unsandboxed
  helpers), user preferences in the home directory, the terminal.

## Clarifications

### Session 2026-10-31

- Q: Does V2 include `com.apple.bsd.dirhelper` as the consumer suggested? → A: No.
  Measured: it makes tools write the user's shared temporary directory.
  Without it they use the run's private `TMPDIR`. V2 records the reason.
- Q: Which developer locations does V2 read? → A: The Command Line Tools,
  every `/Applications/Xcode*.app` bundle (code), the `xcode-select` link,
  the system Xcode preferences file (license state), `/Library/Ruby`,
  `/Library/Perl`, `/Library/Preferences/.GlobalPreferences.plist`,
  `/dev/autofs_nowait`, Homebrew's and `/usr/local`'s code directories (not
  their `etc` or `var`, except OpenSSL's configuration and CA bundle),
  each home's `.CFUserTextEncoding`, and metadata of `/Users`, each home
  directory itself and the parents on the way.
- Q: What about presets? → A: Each preset gets a version 2 on base V2
  (`minimal`, `agent_readonly`, `agent_workspace`, `build`); `build::v2`
  also allows Unix sockets in the workspace (spec 028). Version 1 presets
  stay frozen.
- Q: Linux? → A: `Base::V2` lowers to the same content as V1 there; the
  measured tools need nothing more.
- Q: How do developers learn the setup a tool needs (a persistent `TMPDIR`
  for fast shims, `GIT_CONFIG_GLOBAL`)? → A: A "Running developer tools"
  section in the base docs, and the example helper uses V2.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Developer tools run in a cage (Priority: P1)

An agent harness on macOS runs `git`, `clang`, `make`, `python3`, Ruby,
Perl and Homebrew tools (`node`, `npm`, `rg`, `jq`) in a cage with base V2
and a workspace. They run and give the same output as uncaged.

**Why this priority**: Without it every Xcode tool fails in a cage.

**Independent Test**: The program-set test runs each tool that is
installed on the machine under V2 and compares with the uncaged output;
tools that are not installed are reported, not failed.

**Acceptance Scenarios**:

1. **Given** V2 and a writable workspace, **When** `clang` compiles and runs
   a program there, **Then** it prints its output.
2. **Given** V2, **When** `git` runs with `GIT_CONFIG_GLOBAL=/dev/null`,
   **Then** it initialises a repository and commits.
3. **Given** V2 and a `TMPDIR` reused between runs, **When** a shim runs a
   second time, **Then** it takes less than 200 ms.
4. **Given** V1, **When** the same tools run, **Then** the Xcode shims fail
   as before (V1 is frozen).

---

### User Story 2 - Nothing personal or shared becomes reachable (Priority: P1)

V2 adds no access to user data, shared temporary directories or services
that act outside the sandbox.

**Why this priority**: The base applies to every policy that names it.

**Independent Test**: Under V2, the per-user temporary directory reported
to the child is its private `TMPDIR`; reading `~/.ssh`, `~/Library/Preferences`,
Homebrew's other `etc` files, listing the home directory, writing
`/usr/local` and the network stay refused.

**Acceptance Scenarios**:

1. **Given** V2, **When** the child asks for the per-user temporary
   directory, **Then** it gets its private `TMPDIR`.
2. **Given** V2, **When** the child lists the home directory or reads a file
   in `~/Library/Preferences`, **Then** it fails; **When** it stats the home
   directory, **Then** it succeeds (documented).
3. **Given** V2, **When** the child reads a file in `/opt/homebrew/etc` other
   than OpenSSL's configuration, **Then** it fails.

---

### User Story 3 - The right defaults for new code (Priority: P2)

A developer starting with procage picks the version-2 presets and gets
working developer tools; the docs say what a tool needs from the caller.

**Why this priority**: DX.

**Independent Test**: `agent_workspace::v2` runs `clang` and `python3` in a
workspace; the docs list the developer-tool setup.

**Acceptance Scenarios**:

1. **Given** `agent_workspace::v2(workspace)`, **When** `clang` builds in the
   workspace, **Then** it succeeds.
2. **Given** the presets, **When** their tags are read, **Then** version 2
   presets say version 2.

### Edge Cases

- No Xcode or Command Line Tools installed: the shims print their own
  "no developer tools" error; procage's test skips them.
- Xcode installed under another name (`Xcode-beta.app`): covered by the
  `Xcode*.app` pattern.
- Homebrew on Intel (`/usr/local`): covered.
- A rule list that would be empty must never be emitted (an SBPL rule with
  no filter allows everything): a test checks every base rule.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: `Base::V2` MUST exist; on macOS it MUST be V1 plus the
  measured additions in the clarifications, and nothing else; V1 MUST stay
  byte-for-byte unchanged.
- **FR-002**: V2 MUST NOT allow `com.apple.bsd.dirhelper` or
  `com.apple.system.opendirectoryd.membership`, and the child's per-user
  temporary directory MUST resolve to its private `TMPDIR`.
- **FR-003**: V2's content MUST be pinned by a test, and every base rule
  (V1 and V2) MUST carry at least one filter, except the unconditional
  `sysctl-read` of V1.
- **FR-004**: On Linux, `Base::V2` MUST lower to V1's content.
- **FR-005**: Presets `minimal`, `agent_readonly`, `agent_workspace` and
  `build` MUST gain `v2` functions on base V2 with tag version 2;
  `build::v2` MUST also set `ipc.unix_sockets` to the workspace; the v1
  presets MUST be unchanged.
- **FR-006**: A caged test MUST run the installed developer tools under V2
  and check their output, and MUST check what stays refused (US2).
- **FR-007**: The base docs MUST document V2 with the reason for each entry
  and each deliberate omission, and a "Running developer tools" section
  (persistent `TMPDIR`, `GIT_CONFIG_GLOBAL`/`HOME`, Xcode license, socket
  path length).
- **FR-008**: The lowering table MUST list `base-v2`; the example helper and
  crate docs MUST use V2.

### Key Entities

- **Base profile version 2**.
- **Version-2 presets**.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Under base V2 the child's per-user temporary directory MUST resolve to its private TMPDIR, and V2 MUST NOT allow com.apple.bsd.dirhelper or com.apple.system.opendirectoryd.membership.
  - Mitigates: `threat.shared-temp-poisoning` via `mitigation.no-dirhelper`
  - Given base V2 with the tmpdir grant, when the child asks getconf DARWIN_USER_TEMP_DIR and runs mktemp, then both are inside its private TMPDIR
- **SR-002** (P1): Base V2 MUST NOT let the child list the home directory, read home preferences or ~/.ssh, read Homebrew etc files other than OpenSSL's configuration, write system or Homebrew locations, or reach the network.
  - Mitigates: `threat.personal-data-in-base` via `mitigation.personal-checks`
  - Given base V2, when the child tries each of these, then each fails
- **SR-003** (P1): V1, V2 and every preset's profile MUST be pinned, and every base rule MUST carry at least one filter except V1's sysctl-read.
  - Mitigates: `threat.frozen-drift`, `threat.unfiltered-rule` via `mitigation.pins`
  - Given the policy crate tests, when they run, then the pinned contents match and no base rule is unfiltered
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Of the measured workloads, every one whose tool is installed
  runs under V2 (V1: 11 of 27 failed or could not run).
- **SC-002**: A warm shim call under V2 is within 2× of the uncaged time.
- **SC-003**: Zero additions grant user data beyond the encoding setting
  and home-directory metadata.
- **SC-004**: `just ci` passes.

## Assumptions

- Measured on macOS 26.6.2 with Xcode 27.2 selected and Homebrew under
  `/opt/homebrew`; CI images differ, so the program-set test skips tools
  that are not installed.
