# Feature Specification: A base profile that lets ordinary programs start

**Feature Branch**: `006-base-profile`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "006-base-profile: macOS curated base profile per release vs `system.sb`; Linux minimal mount/Landlock base."

## Context

A procage policy denies everything by default. On macOS that is so strict
that ordinary programs barely work. Measured on macOS 26.6.2:

- dyld aborts unless `/` can be read;
- `id` prints `501` instead of the user name;
- `date` shows UTC instead of local time;
- `sh` cannot find the shell it should run;
- `uname` and every Rust program fail on sysctl reads;
- nothing can open `/dev/null`.

Today every harness author would have to find these rules by trial and
error, as this project just did.

This feature adds a **base profile**: a curated, versioned and frozen set of
rules that lets ordinary programs start and run. It grants nothing in the
user's home directory or project trees, no network, and no secrets. A policy
opts in by naming the version (`Base::V1`). The Linux lowering of the same
version names the minimal system paths a Linux program needs.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Ordinary programs just work (Priority: P1)

A harness author writes a policy with the base profile and the project
directory, and spawns common tools: shells, coreutils, `sed`, `awk`, `perl`,
`tar`, `date`, `id`, `uname`, and Rust programs. They start, find the user's
name and local time, can use `/dev/null`, and touch only what the policy
grants.

**Why this priority**: Without it, procage is unusable for real workloads,
and every caller reinvents a fragile list.

**Independent Test**: Spawn each program of a fixed set with base V1 plus one
granted directory. Each exits successfully, with output that is correct (the
user name, not a number; local time, not UTC).

**Acceptance Scenarios**:

1. **Given** base V1, **When** `id -un` runs, **Then** it prints the user's
   name.
2. **Given** base V1, **When** `date +%Z` runs, **Then** it prints the local
   zone, the same as outside the cage.
3. **Given** base V1 and a granted working directory, **When** `sh`, `zsh` and
   `bash` run a command there, **Then** each succeeds.
4. **Given** base V1, **When** a child is spawned with its standard input and
   output on `/dev/null`, **Then** it runs.
5. **Given** base V1, **When** a Rust program starts, **Then** it runs without
   extra rules.

---

### User Story 2 - The base grants nothing the user cares about (Priority: P1)

A security reviewer checks what the base allows:

- reading system libraries, shared system data, `/private/etc`, the timezone
  database and a few devices;
- looking up a fixed list of system services (user lookup, notifications,
  system configuration, certificate trust, Rosetta);
- reading sysctls.

It allows no access to the user's home, project trees, temporary files or
other users' files, no network, no writes outside `/dev/null`, and no
process control beyond what the policy says.

**Why this priority**: A base profile that quietly opens the home directory
would undo the sandbox.

**Independent Test**: With base V1 alone, a child cannot list or stat the
home directory, read a file in the temp directory, write anywhere except
`/dev/null`, or connect to a loopback listener.

**Acceptance Scenarios**:

1. **Given** base V1 only, **When** the child lists `$HOME` or stats a file in
   it, **Then** it is refused.
2. **Given** base V1 only, **When** the child reads a file under the user's
   temporary directory, **Then** it is refused.
3. **Given** base V1 only, **When** the child creates a file in `/tmp`, **Then**
   it is refused.
4. **Given** base V1 only, **When** the child connects to a loopback
   listener, **Then** it is refused.

---

### User Story 3 - A terminal only when asked (Priority: P2)

With `Tty::Inherit`, the child uses the caller's terminal: it can read it,
write it, and query or set its modes. The terminal-injection deny of the
hard-deny tier still comes last. With `Tty::None` the base grants no
terminal device.

**Why this priority**: Interactive tools need their terminal. Granting
terminal devices to every child would widen the TIOCSTI surface (R-22).

**Independent Test**: With `Tty::None`, the profile names no terminal device.
With `Tty::Inherit`, it allows read, write and ioctl on `/dev/tty` and
`/dev/ttys*`, and the TIOCSTI deny is still the last tier.

**Acceptance Scenarios**:

1. **Given** base V1 with `Tty::None`, **When** the profile is lowered,
   **Then** it contains no `/dev/tty` rule.
2. **Given** base V1 with `Tty::Inherit`, **When** the profile is lowered,
   **Then** it allows the terminal devices before the hard-deny tier, and the
   TIOCSTI deny comes after them.

---

### Edge Cases

- **No base**: the policy default stays without a base, so an empty policy
  still allows nothing (feature 003's guarantee).
- **Frozen versions**: V1 never changes. A loosening needs a new version,
  because presets are versioned and frozen. A tightening is a fix and is stated in the docs.
- **Newer macOS**: a release may need more (macOS 27 aborts some
  deny-default programs). The base tests run on every macOS CI lane, so a
  regression shows up as a failing test, not a silent change.
- **Linux**: the Linux content of V1 is expressed in the plan now. Whether it
  is enough is shown when Linux spawning exists (008), and the lowering table
  says so.
- **Base plus raw rules**: the base's allows land in the allow block, like
  any other allow. Protect, hide and the hard-deny tier still win.
- **Programs outside the list**: Xcode-shimmed tools such as `/usr/bin/git`
  and `/usr/bin/python3` need developer-tool paths. They are out of V1.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The policy MUST be able to name a base profile version, and
  MUST default to none. Version 1 MUST be frozen: its lowered content for a
  given target never changes.
- **FR-002**: On macOS, base V1 MUST allow:
  - **System code**: reading `/` (the literal); read, exec and
    map-executable for `/usr/lib`, `/System`, `/bin`, `/sbin`, `/usr/bin`,
    `/usr/sbin` and `/usr/libexec`.
  - **System data**: reading `/usr/share`, `/private/etc`,
    `/private/var/db/timezone`, `/private/var/select` and
    `/Library/Preferences/Logging`, and the metadata of the root symlinks and
    directories (`/etc`, `/tmp`, `/var`, `/private`, `/private/var`, `/usr`,
    `/Library`).
  - **Devices**: reading and writing `/dev/null`, `/dev/zero` and
    `/dev/dtracehelper`; reading `/dev/random` and `/dev/urandom`; reading and
    writing under `/dev/fd`.
  - **Sysctls**: reading them.
  - **Mach services**: looking up `com.apple.system.opendirectoryd.libinfo`,
    `com.apple.system.notification_center`,
    `com.apple.SystemConfiguration.configd`, `com.apple.trustd`,
    `com.apple.trustd.agent` and `com.apple.oahd`.
  - **Shared memory**: reading the shared memory
    `apple.shm.notification_center`.
- **FR-003**: On macOS with `Tty::Inherit`, base V1 MUST also allow read,
  write and ioctl on `/dev/tty` and on `/dev/ttys` followed by digits. With
  any other terminal mode it MUST NOT name a terminal device.
- **FR-004**: On Linux, base V1 MUST add these Landlock rules:
  - read and exec for `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64` and `/lib32`;
  - read for `/etc`;
  - read and write for `/dev/null` and `/dev/zero`;
  - read for `/dev/random` and `/dev/urandom`;
  - with `Tty::Inherit`, read and write for `/dev/tty` and `/dev/pts`.
  Paths that are absent on a host are skipped by the spawn backend.
- **FR-005**: The base MUST NOT allow file access under `/Users`,
  `/private/var/folders`, `/private/tmp` or `/Volumes`; network; writes other
  than the devices listed; or process creation and signals beyond the
  policy's.
- **FR-006**: Base allows MUST be emitted in the allow block, before every
  protect, hide and hard-deny rule.
- **FR-007**: The lowering table MUST have a row for the base, and the data
  format MUST carry it.
- **FR-008**: A test MUST spawn each program of the verified set with base V1
  on the real kernel and check its output. Another test MUST check the
  refusals of User Story 2. Both run on every macOS CI lane.
- **FR-009**: The docs MUST list what the base allows, the programs it was
  verified with, the release it was measured on, and that `/usr/bin/git` and
  `/usr/bin/python3` (Xcode shims) are not covered.

### Key Entities

- **Base profile**: a named, frozen version (V1) with per-target content.
- **Verified program set**:
  - `id -un`, `whoami`, `date`, `uname -a`;
  - `sh`, `zsh` and `bash` with a command;
  - `cat`, `sort`, `sed`, `awk`, `xxd` on `/dev/urandom`;
  - `perl -e 1`, `tar --version`, `gzip -V`;
  - a Rust program.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Base V1 alone MUST NOT give a caged child access to the user's home, the user's temporary directory, /tmp writes or the network.
  - Mitigates: `threat.base-too-broad` via `mitigation.base-refusal-tests`
  - Given base V1 only, when the child lists or stats the home directory, then it is refused
  - Given base V1 only, when the child reads a temp-dir file, creates a /tmp file or connects to loopback, then each is refused
- **SR-002** (P2): The lowered content of base V1 MUST be pinned per target by a test, so any change fails until a new version is introduced.
  - Mitigates: `threat.base-drift` via `mitigation.frozen-snapshot`
  - Given base V1, when it is lowered for macOS and Linux, then the rules equal the pinned list
- **SR-003** (P1): Base allows MUST be emitted before every protect, hide and hard-deny rule.
  - Mitigates: `threat.base-overrides-deny` via `mitigation.base-in-allow-block`
  - Given base V1 plus a protect rule, when it is lowered for macOS, then every base allow precedes the protect deny and the hard-deny tier
- **SR-004** (P1): Terminal devices MUST be allowed only with Tty::Inherit, and the TIOCSTI deny MUST still come after them.
  - Mitigates: `threat.tty-surface` via `mitigation.tty-only-on-inherit`
  - Given base V1 with Tty::None, when lowered, then no /dev/tty rule appears
  - Given base V1 with Tty::Inherit, when lowered, then the terminal allows precede the TIOCSTI deny
- **SR-005** (P2): The base MUST allow only the listed query services and MUST NOT name any service the hard-deny tier denies.
  - Mitigates: `threat.service-handoff-via-base` via `mitigation.read-only-services`
  - Given the base service list and the hard-deny service list, when compared, then they are disjoint
- **SR-006** (P2): Every program of the verified set MUST run correctly under base V1 on the real kernel, on every macOS CI lane, and the docs MUST state the release measured and the programs not covered.
  - Mitigates: `threat.base-insufficient` via `mitigation.program-set-on-every-lane`
  - Given base V1 and a granted working directory, when each program of the set runs, then it exits 0 with correct output (user name, local zone)
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the verified programs exit successfully under base V1
  with correct output, on macOS 26.6.2.
- **SC-002**: 100% of the User Story 2 refusals hold under base V1.
- **SC-003**: An empty policy (no base) still lowers to a profile with no
  allow rule.
- **SC-004**: `just ci` stays green.

## Assumptions

- **Curated, not imported.** `system.sb` is Apple-private, changes
  between releases, and is opaque to review. A curated list can be explained
  and tested. It may need additions per release, and the CI lanes catch that.
- **Opt-in.** The base is opt-in in the IR, so the IR keeps "nothing without
  a source". Presets (007) will include it.
- **Sysctl reads are allowed broadly.** Programs read many sysctls (page
  size, CPU count, OS version). Reading them exposes system information,
  not user data.
- **macOS 27** cannot be measured here; the newest-macOS CI lane will.
- **Measured on macOS 26.6.2 (25G83), 2026-10-30.**

## Out of Scope

- Presets, secret and trust-handoff deny data (007).
- Developer-tool paths (Xcode, Homebrew).
- Network-related base rules: DNS goes with the network policy.
- Verifying the Linux content on a kernel (008).
