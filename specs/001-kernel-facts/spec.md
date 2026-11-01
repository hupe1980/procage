# Feature Specification: Kernel facts as regression tests

**Feature Branch**: `001-kernel-facts`

**Created**: 2026-10-29

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "001-kernel-facts — Workspace + tests/kernel_facts: every verified fact from the earlier macOS and Linux research becomes a regression test on real kernels. Closes the open kernel questions: path A layout (macOS lanes), compile-abort threshold (soft limit bisection), extension ordering, TIOCSTI; Linux probe skeleton; CI matrix (macOS + Linux lanes, outside-sandbox rule); justfile, deny, MSRV."

## Context

procage's design rests on behaviour that the research measured by hand on one
macOS build (26.6.2, 25G83) and one Linux kernel (7.0.12-linuxkit). Several of
those facts are undocumented, held by private interfaces, and could change in any
OS update. Before any backend is built on them, each verified fact must become an
automated check that runs a real child process on a real kernel. Then a broken
assumption shows up as a failing check and a broken backend is never shipped.

The "users" of this feature are procage's maintainers and its CI. The outcome
is a repository layout that later specs build on, plus a body of executable
evidence.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Re-verify every macOS kernel fact with one command (Priority: P1)

A maintainer on a Mac, outside any agent sandbox, runs one documented command.
Every verified macOS fact from the research (compile surface, path semantics,
nesting, limits, apply path A, inherited-fd bypass, sandbox extensions,
parameters, hard-deny forms) is re-checked against the running kernel. Each
fact passes or fails with its identifier and what was observed.

**Why this priority**: Backends 004–007 all depend on these facts. A drifted fact
found now costs a test change. Found later, it costs a redesign or a silent
security hole.

**Independent Test**: On macOS 26.6.2 outside a sandbox, run the fact suite. It
reports every macOS fact as passed and prints the OS build it ran on.

**Acceptance Scenarios**:

1. **Given** a Mac not inside a Seatbelt sandbox, **When** the maintainer runs
   the fact suite, **Then** each macOS fact in the catalog runs, reports pass or
   fail by identifier, and the run records the macOS version and build.
2. **Given** the suite is started from inside a Seatbelt sandbox (for example an
   agent harness), **When** an enforcement fact runs, **Then** it **fails** with
   a message naming the already-sandboxed condition and how to run outside it.
   It never skips or passes.
3. **Given** a fact whose observed behaviour differs from the recorded one,
   **When** the suite runs, **Then** that fact fails and shows expected and
   observed values.

---

### User Story 2 - Re-verify Linux kernel facts and detect the tier (Priority: P1)

A maintainer or CI lane on Linux runs the same command. A probe reports which
capabilities the host offers: Landlock ABI and errata, available seccomp
actions, unprivileged user namespaces, mount and proc behaviour, and the network
namespace. It classifies the host into tier T1, T2 or T3. The Linux facts then
run against the expectations for that tier.

**Why this priority**: Linux is first-class from 0.1.0. The tier model
is only as good as its probe, and the probe skeleton is what spec 008
grows.

**Independent Test**: In a container with default seccomp, the probe reports T2
and the T2 facts pass. With seccomp unconfined, the probe reports T1 (without
fresh /proc) and the T1 facts pass.

**Acceptance Scenarios**:

1. **Given** a Linux host that allows unprivileged user namespaces, **When** the
   suite runs, **Then** the probe reports T1 and the namespace, mount, Landlock
   and network facts pass.
2. **Given** a container under a default seccomp profile that refuses user
   namespaces, **When** the suite runs, **Then** the probe reports T2. It records
   that creating a user namespace was refused with EPERM. Facts that need T1
   report "not applicable on T2" with the reason. They do not report a pass.
3. **Given** a host with neither usable Landlock nor user namespaces, **When**
   the probe runs, **Then** it reports T3. It never reports a higher tier than
   it measured.

---

### User Story 3 - Close the open kernel questions with evidence (Priority: P2)

The maintainer needs answers to four open questions, each backed by a test that
keeps the answer true:

- **Path A layout**: is the path A bytecode-apply argument layout valid on every macOS lane?
- **Compile-abort threshold**: where between 5,000 and 20,000 rules does in-process compilation
  start to abort, and does rule shape matter?
- **Extension ordering**: can a sandbox extension token be consumed before the profile is
  applied, and are the check and consume calls free of user-space locking?
- **TIOCSTI**: can a process on macOS 26 inject keystrokes into its terminal
  (TIOCSTI)?

**Why this priority**: These answers set the design of spec 004 (soft limit,
child sequence) and spec 005 (tty default). They are not needed to build the
workspace itself.

**Independent Test**: Run the question probes. Each writes a dated finding
(answer, OS build, method). The matching regression fact then asserts that
answer.

**Acceptance Scenarios**:

1. **Given** the compile-abort bisection runs in a crash-isolated child, **When** it
   finishes, **Then** it reports the largest rule count that compiled and the
   smallest that aborted, for at least two rule shapes. The calling process
   never aborts.
2. **Given** a per-spawn extension token, **When** the child consumes it before
   applying the profile and then writes to the granted path, **Then** the
   outcome (allowed or denied) is recorded as the extension-ordering answer and asserted from
   then on.
3. **Given** a child with a terminal, **When** it attempts TIOCSTI, **Then** the
   outcome is recorded as the TIOCSTI answer and asserted.

---

### User Story 4 - A workspace and quality gates that later specs inherit (Priority: P2)

Later specs need a fixed layout: a portable, allocation-only policy crate with no
unsafe code, and a facade crate. They also need one local command that runs the
same gates as CI (format, lints, tests, docs, dependency policy, minimum Rust
version, portability of the policy crate). Each gate fails loudly.

**Why this priority**: Every later spec plugs into this. It is cheap to build, but
it is meaningful only once the facts it guards exist.

**Independent Test**: On a clean checkout, the single CI command passes. A
deliberate violation in any gate makes it fail: an `unsafe` block in the policy
crate, a disallowed dependency licence, or a use of a newer-than-MSRV API.

**Acceptance Scenarios**:

1. **Given** a clean checkout, **When** the maintainer runs the local CI command,
   **Then** formatting, lints, tests, docs with warnings denied, dependency
   policy, the MSRV build and the policy crate's portable build all pass.
2. **Given** the CI definition, **When** it is read, **Then** it declares macOS
   lanes (26 arm64, newest available image, x86_64 under Rosetta if offered) and
   Linux lanes (ubuntu-24.04 x64 and arm64 as shipped and with the userns
   restriction lifted, ubuntu-26.04, a debian:13 container). Each lane records
   its OS build or kernel and its tier.

---

### Edge Cases

- **Sandboxed runner**: the suite is started inside Claude Code's, Codex's or
  any other Seatbelt sandbox. Enforcement facts fail with a clear "already
  sandboxed" message; compile-only facts may still pass (compiling works inside
  a sandbox).
- **Missing private symbol**: a required libsandbox symbol is absent on a future
  macOS. Its fact fails as "symbol unavailable" by name. It does not crash the
  run, and the remaining facts still run.
- **Libsandbox abort**: a fact that triggers an abort inside libsandbox (the
  20k-rule case) runs in an isolated child. The suite records the abort as the
  expected outcome and keeps running.
- **A fact differs by OS release**: a fact holds on 26.6.2 but not on another
  lane. The fact fails on that lane and reports the build. Expectations are never
  loosened without a recorded decision.
- **Timing-sensitive facts** (apply under dyld contention): bounded trial counts
  and a per-trial timeout. A hang is a failure, not an endless run.
- **Linux in a container with masked /proc**: a PID namespace without a fresh
  /proc is reported as a real state (`fresh_proc` false). It is not an error.
- **Probe in a throwaway child**: a probe that crashes or is killed counts as
  "capability absent" and lowers the tier. It never raises it.
- **Non-admin or CI VM**: facts must not need root or admin. A fact that cannot
  be checked without privilege is out of scope here and listed as such.

## Requirements *(mandatory)*

### Functional Requirements

**Fact catalog and reporting**

- **FR-001**: The suite MUST hold a catalog of kernel facts. Each fact has a
  stable identifier (`KF-M##` for macOS, `KF-L##` for Linux), a one-line
  statement, the platform and tier it applies to, and the expected outcome.
  Identifiers are never renumbered or reused.
- **FR-002**: Every verified [V]/[VL] fact in the macOS and Linux research
  that describes kernel or libsandbox behaviour MUST appear in the catalog. The
  minimum set is listed in "Fact catalog (minimum)" below. A fact left out on
  purpose MUST be listed with the reason it was left out.
- **FR-003**: Each fact MUST be checked by starting a real child process on the
  running kernel and observing what happens: exit status, errno, data read or
  written, or the result of the sandbox self-check. Comparing generated profile
  text or filter bytes MUST NOT count as evidence of enforcement.
- **FR-004**: Each run MUST report, per fact, its identifier, pass, fail or "not
  applicable" with a reason, and the observed value when it fails. It MUST also
  report the OS version and build (macOS) or kernel release (Linux), and the
  date.
- **FR-005**: A fact that triggers an abort or a crash in the system library
  MUST run in an isolated child, so the test process survives.
- **FR-006**: Timing-dependent facts MUST use a fixed number of trials and a
  per-trial timeout. A timeout MUST count as a failure.

**Outside-sandbox rule**

- **FR-007**: Before any enforcement fact runs, the suite MUST detect whether
  the test process is already inside a Seatbelt sandbox. If it is, every
  enforcement fact MUST fail (not skip), and the message MUST name the condition
  and how to run outside the sandbox.
- **FR-008**: The project MUST document one command that runs the suite outside
  an agent sandbox.

**Linux probe skeleton**

- **FR-009**: A Linux probe MUST run in a throwaway child. It MUST measure, and
  never infer from the kernel version string:
  - the Landlock ABI version and errata;
  - the available seccomp actions, including user notification;
  - whether an unprivileged user namespace can be created and its uid/gid map
    written;
  - whether a tmpfs and a locked read-only bind can be mounted, and whether the
    read-only bind returns EROFS on write;
  - whether a fresh /proc can be mounted;
  - whether a new network namespace has only an inactive loopback.

  It MUST also read the AppArmor unprivileged-userns setting, for diagnostics
  only.
- **FR-010**: From those measurements the probe MUST classify the host:
  - **T1**: userns, mounts, Landlock and seccomp are all usable.
  - **T2**: Landlock ABI ≥ 4 and seccomp, without usable userns.
  - **T3**: anything less.

  A failed or crashed measurement MUST count as "absent".
- **FR-011**: Linux facts MUST state the tiers they apply to. On a lower tier
  they report "not applicable" with the measured reason. They never report a
  pass.

**Open questions**

- **FR-012**: The suite MUST determine, record and then assert:
  - **Path A layout**: path A apply works and is enforced, checked on each macOS lane;
  - **Compile-abort threshold**: the rule-count range where in-process compile aborts, found by
    bisection in an isolated child, for at least two rule shapes (inline
    literals, and grouped `require-any`);
  - **Extension ordering**: whether an extension can be consumed before apply, and what
    happens when the child then writes to the granted path;
  - **TIOCSTI**: whether TIOCSTI injects on the running macOS.
- **FR-013**: For the extension question's "syscalls only" part, the suite MUST record the
  evidence gathered: an inspection of the calls the functions make, or a probe.
  The answer MUST say if it is inferred rather than proven.

**Workspace and gates**

- **FR-014**: The repository MUST become a workspace with two crates:
  - a policy crate: portable, allocation-only (`no_std` + `alloc`), with unsafe
    code forbidden;
  - a facade crate: it keeps the published name and the 0.0.1 placeholder
    status, and gains no public API in this feature.
- **FR-015**: Unsafe code needed by the fact suite MUST be confined to one
  clearly named low-level module per OS in test-only code. Each unsafe block
  MUST carry a safety comment. Every other module MUST forbid unsafe code.
- **FR-016**: One local command MUST run all gates that CI runs:
  - format;
  - lints with warnings denied;
  - tests;
  - docs with warnings denied;
  - dependency licence and advisory policy;
  - an MSRV (1.99) build;
  - a portable `no_std` build of the policy crate.
- **FR-017**: The CI definition MUST declare the macOS and Linux lanes listed in
  User Story 4, scenario 2. Every lane runs the fact suite outside any agent
  sandbox and records its OS build or kernel and its tier. A lane whose image is
  unavailable is marked as allowed to be missing. It is never silently dropped.
- **FR-018**: Nothing published (source, README, rustdoc, tests, examples, CI)
  may cite a path under the private notes directory, `specs/` or `.specify/`. Fact identifiers
  and their statements live in the published tests themselves.
- **FR-019**: Building the fact suite MUST NOT need network access beyond normal
  dependency fetching. It MUST NOT need root or admin rights. A fact that needs
  privilege is out of scope.

### Fact catalog (minimum)

Statements are the recorded outcomes on macOS 26.6.2 (25G83) and Linux
7.0.12-linuxkit. Each becomes one fact.

| ID | Fact (expected outcome) |
|---|---|
| KF-M01 | The compile, apply, parameter, check, extension and bytecode-syscall symbols resolve at runtime by dynamic lookup |
| KF-M02 | A small profile compiles to bytecode (no builtin name) |
| KF-M03 | A compile error reports line and column; the error slot is not cleared on success |
| KF-M04 | An unset parameter makes the compile fail ("expected pattern, got boolean") |
| KF-M05 | After apply, the sandbox self-check reports 1 and stays 1 (irreversible) |
| KF-M06 | The sandbox is inherited across fork and exec |
| KF-M07 | A `literal` rule on `/etc/hosts` does not block reading it; the `/private/etc/hosts` spelling does |
| KF-M08 | `subpath "/tmp"` does not allow creating `/tmp/x`; `/private/tmp` does |
| KF-M09 | A second apply with a different profile fails with EPERM and its rules are not enforced; an identical profile returns 0 |
| KF-M10 | Compiling inside a sandbox works |
| KF-M11 | A sandboxed process cannot exec a setuid binary with elevated privileges |
| KF-M12 | `(allow process-exec (with no-sandbox))` compiles and the exec'd child runs unsandboxed (the escape procage must never emit) |
| KF-M13 | A specific IP address in a network filter fails to compile; only `*` and `localhost` are hosts |
| KF-M14 | Every hard-deny and network form in the research compiles under `(deny default (with message …))` |
| KF-M15 | `(param …)` is accepted by `subpath`, `literal`, `prefix`, `regex`, unix-socket `path-literal`, `global-name` and `string-append` |
| KF-M16 | An inline string literal of 1016 bytes compiles and one of 1024 bytes is rejected; a 4000-byte parameter value compiles |
| KF-M17 | 20,000 inline `(allow file-read* (literal "/private/tmp/dirNNNNNN/file"))` rules under `(deny default)` abort the compiling process with the jump-length assertion (isolated child). Re-measured 2026-10-29: the abort depends on rule shape, since 20,000 `allow default` deny rules on shorter paths fail cleanly instead |
| KF-M18 | Path A apply in a child forked from a parent with dyld-lock contention is enforced in every trial, with no hang |
| KF-M19 | A file descriptor opened by the parent and inherited by the child reads a path the profile denies; a fresh open is denied |
| KF-M20 | One compiled profile plus a per-spawn file extension grants exactly the issued path, and a second spawn with a different token gets the other path |
| KF-M21 | A `subpath "/Users"` deny is enforced through the firmlink |
| KF-M22 | The sandbox check is reliable for file-read-data/path and mach-lookup/global-name (the operations later used as an oracle) |
| KF-M23 | Path A argument layout is accepted and enforced on this lane |
| KF-M24 | Compile-abort threshold per rule shape lies in the recorded range |
| KF-M25 | Extension consumption before apply has the recorded outcome |
| KF-M26 | TIOCSTI has the recorded outcome |
| KF-M27 | A profile whose bytecode would exceed 65,535 bytes fails to compile with "data object length … exceeds maximum (65535)", without aborting (measured 2026-10-29: 10,000 deny-default allow rules) |
| KF-M28 | A single `require-any` group of 10,000 literals fails to compile with **no** error text, so a NULL result with an empty error slot is possible (measured 2026-10-29) |
| KF-L01 | The probe reports a Landlock ABI ≥ 1 and its errata on hosts with Landlock |
| KF-L02 | seccomp lists `user_notif` among available actions |
| KF-L03 | (T1) An unprivileged user namespace with self uid/gid map is created |
| KF-L04 | (T1) Writing through a read-only bind fails with EROFS |
| KF-L05 | (T1) A tmpfs over a directory hides its entries |
| KF-L06 | Landlock denies a write outside the allowed tree with EACCES |
| KF-L07 | (T1) A new network namespace has no interface up |
| KF-L08 | Under Landlock, `/dev/null` writes are denied until it is given a rule |
| KF-L09 | (T1) In a nested user namespace, remounting the read-only bind writable fails with EPERM, unmounting the tmpfs fails, and a non-recursive bind of the parent fails |
| KF-L10 | (T1) Under Landlock, a nested user namespace cannot write its uid map (EACCES) |
| KF-L11 | Mount topology changes are denied after Landlock restriction |
| KF-L12 | (T2 inside a container only; N/A elsewhere) creating a user namespace fails with EPERM while Landlock is available |
| KF-L13 | (container) mounting a fresh /proc in a PID namespace fails when /proc is masked; the probe reports `fresh_proc = false` |

Excluded on purpose (documented in the suite): figures about performance
(compile times, 0.64 ms namespace setup) are recorded as observations, not
assertions; Landlock audit and tracepoints need privilege (FR-019);
path C's no-deadlock result informs only the fallback path, which the chosen design (path A apply) does not use.

### Key Entities

- **Kernel fact**: identifier, statement, platform, tiers or OS range, expected
  outcome, last-verified date and build.
- **Probe result (Linux)**: Landlock ABI and errata, seccomp actions, userns
  usable, tmpfs/ro-bind usable, fresh /proc, netns, AppArmor setting, boot id,
  derived tier.
- **Question finding**: question id, answer, method, OS build, date, whether
  it is proven or inferred.
- **Lane**: OS image, architecture, configuration (e.g. userns restriction
  lifted), expected tier.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The fact suite MUST fail, never skip or pass, every enforcement fact when the test process is already inside a Seatbelt sandbox, and the failure message MUST name the condition and the outside-sandbox command.
  - Mitigates: `threat.sandboxed-runner-false-result` via `mitigation.outside-sandbox-precheck`
  - Given the suite is started under a Seatbelt profile (e.g. sandbox-exec or an agent harness), when an enforcement fact runs, then it fails with an already-sandboxed message naming the outside-sandbox command; no enforcement fact reports pass or skip
- **SR-002** (P1): Every enforcement fact MUST include a control run of the same action without the restriction that succeeds, and MUST match the specific expected errno, exit code or data, never just "the child failed".
  - Mitigates: `threat.false-pass-enforcement-fact` via `mitigation.positive-controls`
  - Given an enforcement fact whose target file is missing, when the fact runs, then the control run fails and the fact reports a setup failure, not a pass
  - Given a denied action that fails with an unexpected errno, when the fact runs, then the fact fails and reports expected and observed errno
- **SR-003** (P1): The TIOCSTI probe MUST operate only on a pseudo-terminal pair it creates, after detaching from any controlling terminal, and MUST NOT write a newline or command text.
  - Mitigates: `threat.tiocsti-injects-into-maintainer-terminal` via `mitigation.private-pty`
  - Given the maintainer runs the suite in an interactive terminal, when the TIOCSTI probe runs, then no character appears in, or is executed by, the maintainer's terminal; the observation is read back from the probe's own pty
- **SR-004** (P2): Facts MUST execute only absolute-path commands with constant arguments, never through a shell or with arguments derived from the environment, and any setuid exec MUST be non-interactive and time-bounded.
  - Mitigates: `threat.escape-fact-runs-unconfined-payload` via `mitigation.fixed-argv-no-shell`
  - Given the probe source, when it is reviewed or grepped, then no fact execs a shell or builds argv from environment variables
  - Given the setuid fact on a host where sudo would prompt, when it runs, then it completes within its timeout without prompting
- **SR-005** (P2): Facts MUST create and touch files only in their own freshly created 0700 temp directory (or under unique, exclusively created names where a fact needs /private/tmp itself), MUST NOT write under $HOME, and MUST remove what they create.
  - Mitigates: `threat.shared-tmp-races` via `mitigation.private-scratch-dirs`
  - Given a pre-existing symlink at a predictable /tmp name, when the /tmp facts run, then they neither follow it nor write through it
  - Given a full suite run, when it finishes, then no files created by the suite remain and nothing under $HOME changed
- **SR-006** (P1): Every fact that may abort inside a system library MUST run in a separate child process, and an abort MUST be recorded as an observation while the suite continues.
  - Mitigates: `threat.compile-abort-kills-harness` via `mitigation.crash-isolated-children`
  - Given the 20,000-rule fact, when libsandbox aborts, then the fact records the abort signal and every later fact still runs
- **SR-007** (P2): Timing-dependent facts MUST use fixed trial counts and per-child timeouts that kill the child and fail the fact; the compile-abort bisection MUST be opt-in and time-budgeted.
  - Mitigates: `threat.unbounded-fact-runtime` via `mitigation.bounded-trials`
  - Given a child that hangs, when its timeout expires, then it is killed and the fact fails with a timeout
  - Given the default test command, when it runs, then the compile-abort bisection does not run; the asserting fact checks only the recorded bracket edges
- **SR-008** (P2): Fact code MUST NOT run between fork and exec in the test runner process; each fact runs in a freshly exec'd probe binary, and fork-then-apply code exists only in that binary and issues syscalls only.
  - Mitigates: `threat.fork-in-multithreaded-harness` via `mitigation.exec-fresh-probe-binary`
  - Given the test harness source, when it is reviewed, then it contains no pre_exec closure or raw fork; children start through the standard process API
- **SR-009** (P1): All unsafe code MUST be confined to one test-only sys module per OS, with a SAFETY comment on every unsafe block; private symbols MUST be resolved by dynamic lookup and a missing symbol MUST fail its fact by name.
  - Mitigates: `threat.ffi-misdeclaration` via `mitigation.confined-audited-ffi`
  - Given the workspace, when lints run, then unsafe_code is forbidden in every module except the sys modules, and every unsafe block has a SAFETY comment
  - Given a symbol name that does not exist, when it is resolved, then the fact fails reporting the symbol as unavailable and the suite continues
- **SR-010** (P2): The CI workflow MUST pin every third-party action to a full commit SHA, set token permissions to read-only, use no secrets on fact lanes, and check out without persisted credentials.
  - Mitigates: `threat.unpinned-ci-actions` via `mitigation.pinned-least-privilege-ci`
  - Given the CI workflow file, when it is checked, then every uses reference has a 40-hex SHA, permissions is contents read, and no secrets reference appears
- **SR-011** (P2): The local CI command MUST run a dependency policy check (advisories, licence allowlist, crates.io-only sources, bans), and the lockfile MUST be part of the tree.
  - Mitigates: `threat.malicious-dependency` via `mitigation.dependency-policy`
  - Given a dependency with a disallowed licence or a git source, when the local CI command runs, then it fails at the dependency gate
- **SR-012** (P2): Every fact report and question finding MUST record OS version and build or kernel release, architecture, tier (Linux), and date; question findings MUST also record the method and whether the answer is proven or inferred.
  - Mitigates: `threat.unattributed-evidence` via `mitigation.attributed-reports`
  - Given any suite run, when the report is printed, then its header contains OS build or kernel, architecture, date and tier
- **SR-013** (P3): Local Linux fact runs MUST NOT use privileged containers or host networking, MUST run the facts as a non-root user, and MUST mount the host workspace read-only.
  - Mitigates: `threat.container-host-exposure` via `mitigation.unprivileged-container`
  - Given the documented container recipe, when it is inspected, then it has no --privileged, no host network, a read-only source mount and a non-root user
- **SR-014** (P3): Probes MUST report byte counts, errno values and exit codes only, never file contents or environment variable values.
  - Mitigates: `threat.secret-leak-in-reports` via `mitigation.report-redaction`
  - Given the inherited-fd fact reads a file, when it reports, then the report shows the byte count, not the contents
- **SR-015** (P3): The local CI command MUST fail when any published file mentions the private notes directory, specs/ or .specify/.
  - Mitigates: `threat.planning-path-leak` via `mitigation.planning-path-gate`
  - Given a source comment citing a private research note, when the local CI command runs, then the planning-path gate fails naming the file
- **SR-016** (P1): The Linux probe MUST derive the tier only from measurements taken in throwaway children, MUST treat a failed, crashed or timed-out measurement as absent, and MUST NOT consult the kernel version string for capabilities.
  - Mitigates: `threat.probe-overstates-tier` via `mitigation.measured-tier-floor`
  - Given a container with default seccomp, when the probe runs, then it reports T2 with user namespaces absent (EPERM)
  - Given a measurement child that crashes, when the probe derives the tier, then the capability counts as absent and the tier is not raised
- **SR-017** (P3): Sandbox extension tokens MUST be passed between steps only over a stdin pipe, MUST NOT appear in argv, environment or observations, and MUST grant only a 0700 scratch directory.
  - Mitigates: `threat.extension-token-exposure` via `mitigation.token-over-pipe`
  - Given the KF-M20 and KF-M25 steps run, when argv, env and the report are inspected, then no token string appears; the child reads it from stdin
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the facts in the minimum catalog have an automated check;
  0 are verified only by hand.
- **SC-002**: On the reference Mac (macOS 26.6.2, outside any sandbox), the full
  macOS fact suite passes with a single command in under 5 minutes.
- **SC-003**: In a local Linux container, the probe classifies the default
  configuration as T2 and the unconfined configuration as T1. Every applicable
  Linux fact passes in both.
- **SC-004**: Started from inside a Seatbelt sandbox, 100% of enforcement facts
  report failure and 0 report skip or pass.
- **SC-005**: The four open questions each have a dated, recorded answer and a
  fact that asserts it. The compile-abort answer narrows the 5,000–20,000 range to a
  bracket no wider than 10% of its lower bound.
- **SC-006**: The local CI command passes on a clean checkout. Each of three
  injected violations (unsafe in the policy crate, a dependency with a
  disallowed licence, a `std` use in the policy crate) makes it fail. The MSRV
  gate runs on every check. It cannot be mutation-tested while the current
  stable release equals the MSRV (1.99).
- **SC-007**: A search of the published tree finds 0 references to the local
  planning directories.

## Assumptions

- The reference Mac is macOS 26.6.2 (25G83), Apple silicon, not sandboxed.
  Docker Desktop (kernel 7.0.x linuxkit, arm64) stands in for Linux locally. Bare
  Ubuntu, Fedora and RHEL behaviour is confirmed only once CI lanes run.
- CI lanes are defined in this feature, but they run only once the repository is
  pushed. Pushing, and any commit, needs the user's authorization. Local runs are
  the acceptance evidence for this feature.
- The TIOCSTI question is closed here, although an earlier plan
  placed its canary in spec 004. Spec 004 can reuse the fact.
- The extension question's "syscalls only" answer may be inferred from inspecting the calls, since
  kernel tracing on macOS needs SIP changes or root (FR-019). The answer says so.
- The facade crate stays a name placeholder with no public API. The policy crate
  holds only a placeholder module for spec 003 to fill. Whether to publish the
  policy crate is decided in spec 019.
- Performance figures are recorded, not asserted, because CI hardware varies.
