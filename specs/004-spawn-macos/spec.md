# Feature Specification: Spawn a caged child on macOS

**Feature Branch**: `004-spawn-macos`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "004-spawn-macos: `macos::sys` (dlsym table), compile + in-memory cache + crash isolation, path A + probe, path B helper with integrity, status pipe, verify, `AlreadySandboxed`, extension grants."

## Context

procage can now write a policy once and lower it to a Seatbelt profile
(feature 003). Nothing yet applies that profile to a process. A harness
author on macOS still has to shell out to the deprecated `sandbox-exec`, or
copy private-interface code from another tool.

This feature makes procage spawn a child process in a cage on macOS:

- **Prepare in the parent.** The parent resolves the policy's paths to the
  spellings the kernel matches, lowers the policy, and compiles the profile
  once.
- **Apply in the child.** The forked child applies the compiled profile using
  system calls only, confirms that it is caged, and only then runs its target
  program.
- **Grants per spawn.** Per-spawn paths (a workspace, a scratch directory) are
  bound when spawning, without recompiling.
- **Fail closed.** Every step that cannot be done is a typed error, never a
  child that runs uncaged.

This is the first feature whose claims are about enforcement. Every claim it
makes is backed by a test that runs a real caged child on this Mac's kernel
and observes the outcome.

Readers are harness authors on macOS (two consumer harnesses are the first
users), procage's maintainers and its CI.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a program in a cage that holds (Priority: P1)

A harness author builds a policy, prepares it once, and spawns a program
with it. In the child:

- files the policy grants can be used with the granted access;
- every other file access is refused by the kernel with "operation not
  permitted";
- the network is reachable only as the policy says.

If the cage cannot be applied or confirmed in the child, the program never
starts, and the author gets an error naming the failed step.

**Why this priority**: This is the product. A sandbox library that cannot
apply a sandbox, or that might run the target uncaged, has no value.

**Independent Test**: Spawn real programs (`cat`, `touch`, `nc`) with
policies granting a scratch directory. The kernel refuses access outside it,
allows access inside it, and refuses network access unless granted.

**Acceptance Scenarios**:

1. **Given** a policy that grants read access to one directory, **When**
   `cat` is spawned on a file inside it and on a file outside it, **Then**
   the first succeeds and the second fails with "operation not permitted".
2. **Given** a policy that grants write access to a directory and protects a
   subdirectory, **When** the child creates files in both, **Then** creation
   succeeds in the directory and is refused in the protected subdirectory.
3. **Given** a policy with no network, **When** the child connects to a TCP
   listener on loopback, **Then** the connection is refused. With loopback
   access for that port, it succeeds.
4. **Given** a cage that fails to apply or to confirm itself in the child,
   **When** the author spawns, **Then** spawning returns an error naming the
   failed step, and the target program is never executed.
5. **Given** a parent with several threads busy loading libraries, **When**
   it spawns many caged children in a row, **Then** every child is caged and
   none hangs.

---

### User Story 2 - Paths mean what the author wrote (Priority: P1)

The author writes `/tmp/work` or `/etc/hosts`, as people do. On macOS these
are symlinked spellings (`/private/tmp`, `/private/etc`). The kernel matches
real paths, so a rule written with the symlinked spelling silently does
nothing (escape class R-02). Before lowering, procage resolves every path to
the real spelling the kernel matches, in the firmlink-visible form. It
records each rewrite, so the author can see it.

**Why this priority**: A rule that silently does nothing is the most common
macOS sandbox bug. Prior tools shipped it, and this project's kernel facts
show it (KF-M07, KF-M08, KF-M21).

**Independent Test**: With a policy written as `/tmp/...`, a child can write
where the author meant and nowhere else. The prepared cage lists the rewrite
from `/tmp/...` to `/private/tmp/...`.

**Acceptance Scenarios**:

1. **Given** a policy granting write access to `/tmp/<dir>`, **When** the
   child creates a file there through the `/tmp` spelling, **Then** it
   succeeds, and the cage records the rewrite to `/private/tmp/<dir>`.
2. **Given** a path that does not exist yet below an existing directory,
   **When** the cage is prepared, **Then** the existing part is resolved and
   the rest is kept unchanged.
3. **Given** a glob whose fixed leading part is a symlinked spelling, **When**
   the cage is prepared, **Then** that part is resolved, and any glob
   characters in the resolved name are taken literally.

---

### User Story 3 - Compile once, bind paths per spawn (Priority: P2)

A harness spawns hundreds of commands with the same policy, each with its own
scratch directory. The profile is compiled once, when the cage is prepared.
Each spawn binds the policy's named grants to concrete paths for that spawn
only. A grant bound for one spawn gives nothing to another.

**Why this priority**: Compiling costs milliseconds to seconds. Per-spawn
paths written into the profile would force a compile for every spawn.

**Independent Test**: With one prepared cage, spawn twice, binding the grant
to directory A and then to directory B. Each child can write only to its own
directory. Preparing the same policy again reuses the compiled profile.

**Acceptance Scenarios**:

1. **Given** a policy with a write grant `scratch`, **When** spawn 1 binds it
   to A and spawn 2 binds it to B, **Then** child 1 can write to A but not B,
   and child 2 to B but not A.
2. **Given** a grant the policy declares but the spawn does not bind, **When**
   the child accesses any path through it, **Then** access is refused.
3. **Given** a binding for a grant name the policy does not declare, **When**
   spawning, **Then** spawning fails with a typed error.
4. **Given** the same policy prepared twice in one process, **When** the
   second cage is prepared, **Then** the profile is not compiled again.

---

### User Story 4 - Never nest silently, never run weaker (Priority: P2)

A harness that already runs inside a Seatbelt sandbox (for example inside an
AI agent's sandbox) asks procage to spawn. A second profile would either fail
or be silently ignored by the kernel (KF-M09). procage detects this first
and returns "already sandboxed". Other conditions fail with a typed error
before any child runs:

- private libsandbox interfaces are missing;
- the in-child apply method does not work on this OS release;
- the profile is over its size limit;
- the policy holds constructs macOS cannot express;
- a policy setting this release cannot apply yet.

**Why this priority**: These are the "silently weaker" failure modes that
constitution principle I forbids.

**Independent Test**: Spawn from inside a caged child and get "already
sandboxed". Prepare oversized and unsupported policies and get their typed
errors. Check that the first-use probe of the apply method passes on this
release.

**Acceptance Scenarios**:

1. **Given** a process that is itself caged, **When** it asks procage to
   spawn, **Then** it gets "already sandboxed" and no child is started.
2. **Given** a policy over the rule limit, **When** the cage is prepared,
   **Then** preparation fails with "limit exceeded", and nothing is compiled
   in-process.
3. **Given** a policy that asks for a new pseudo-terminal, **When** the cage
   is prepared, **Then** preparation fails with "unsupported in this
   release", naming the setting.
4. **Given** the first spawn in a process, **When** procage probes the
   in-child apply method, **Then** the probe applies a profile in a
   throwaway child, confirms that the child is caged and that a canary
   access is denied, and caches the result for the process.

---

### Edge Cases

- The child's own target program must be executable under the policy. If
  it is not, the exec is refused by the cage and spawning reports a
  permission error. It never falls back to an uncaged run.
- Environment: the child receives exactly the environment the policy
  states. With the default allowlist it receives an empty environment, plus
  variables the caller sets explicitly on the command.
- Terminal: with the default `Tty::None`, the child starts a new session and
  has no controlling terminal. `Tty::Inherit` keeps the caller's terminal.
  `Tty::NewPty` is refused in this release.
- Resource limits in the policy are set in the child before the cage is
  applied. The core-dump size is 0 by default.
- An inherited file descriptor still bypasses path rules (KF-M19). Closing
  them is the hygiene feature's job (005). This feature does not claim fd
  hygiene and documents the gap.
- A grant path that does not exist cannot be bound (the kernel needs an
  existing file to issue the token): spawning fails with a typed error.
- Profile parameters (long paths) are passed at compile time; the cache key
  includes them.
- Other threads may fork at the same moment. Nothing the child does between
  fork and exec takes a lock or allocates memory.

## Requirements *(mandatory)*

### Functional Requirements

**Private interfaces**

- **FR-001**: procage MUST resolve the private libsandbox symbols and
  `__mac_syscall` by dynamic lookup, once per process, before any child is
  forked. A missing symbol MUST give a typed "unsupported" error naming the
  symbol and the OS build. It MUST never cause a load failure or a crash.
- **FR-002**: Unsafe code MUST be confined to one system-interface module.
  Every unsafe block MUST state why it is sound.

**Preparing a cage**

- **FR-003**: Preparing a cage MUST:
  - resolve every policy path to its real spelling in firmlink-visible form;
  - record each rewrite;
  - lower the policy for macOS (feature 003);
  - compile the profile in the parent.
  Lowering errors (gaps, invalid policy, limits) MUST be returned unchanged.
- **FR-004**: Path resolution MUST:
  - resolve the longest existing leading part of each path, and keep the
    remainder byte-exact;
  - resolve only the fixed leading part of a glob before its first
    wildcard component, and treat glob characters in the resolved part as
    literal;
  - map a path under the data volume (`/System/Volumes/Data/...`) to its
    visible spelling when both name the same file.
- **FR-005**: Compiled profiles MUST be cached in memory for the life of the
  process, keyed by the exact profile text and its parameters. Compiled
  bytecode MUST never be read from disk.
- **FR-006**: A profile with more rules than the in-process compile limit
  (default 2,000, configurable) MUST NOT be compiled in-process. Preparation
  MUST fail with "limit exceeded". Compiling in a separate helper process is
  out of scope.
- **FR-007**: Policy settings this release cannot apply MUST fail
  preparation with a typed "unsupported in this release" error naming the
  setting. The first such setting is `Tty::NewPty`.

**Spawning**

- **FR-008**: Before forking, spawning MUST detect whether the calling
  process is already sandboxed. If it is, spawning MUST return "already
  sandboxed" without forking.
- **FR-009**: Before the first spawn in a process, procage MUST probe the
  in-child apply method:
  - apply a fixed profile in a throwaway child;
  - require that the child reports itself caged;
  - require that a canary file access is denied;
  - cache the result for the process.
  A failed probe MUST make every spawn fail with "unsupported", naming the
  apply method and the OS build. The fallback through a helper process is
  out of scope.
- **FR-010**: Between fork and exec, the child MUST run only system calls,
  on data prepared by the parent. That means no memory allocation, no
  locks, no dynamic symbol lookup. In order, it MUST:
  1. start a new session (unless `Tty::Inherit`);
  2. set the policy's resource limits;
  3. apply the compiled profile;
  4. confirm it is sandboxed;
  5. consume this spawn's grant tokens.
  If any step fails, the child MUST exit without executing the target, and
  spawning MUST return an error naming the step and the OS error.
- **FR-011**: The child's environment MUST be exactly what the policy's
  environment setting yields:
  - an allowlist keeps only the named variables from the caller's
    environment;
  - passthrough keeps everything except the denied names;
  - variables the caller sets explicitly on the command are kept.
- **FR-012**: Grants MUST be bound per spawn by name to an existing path.
  procage MUST:
  - resolve the path like any policy path;
  - issue a token of class `procage.<name>` in the parent;
  - have the child consume it after applying the profile.
  Binding an undeclared grant name, or a path that does not exist, MUST
  fail with a typed error. An unbound grant MUST give no access.
- **FR-013**: One prepared cage MUST be usable for any number of spawns, from
  any thread.

**Evidence and documentation**

- **FR-014**: Every enforcement claim this feature's documentation makes MUST
  have an integration test that spawns a real caged child on this Mac's
  kernel and observes the outcome. When the test process is itself
  sandboxed, these tests MUST fail, never skip.
- **FR-015**: The plan MUST list the full call sequence the child runs
  between fork and exec. A test MUST spawn at least 100 caged children from
  a parent with at least four threads busy loading libraries, and observe
  that every child is caged and none hangs.
- **FR-016**: The crate documentation and the threat model's release status
  MUST say what this development version does on macOS, and what it does
  not do yet:
  - no fd hygiene;
  - no lifetime control of descendants;
  - no base profile;
  - no Linux.
  It MUST NOT claim more than the tests show. Escape-class statuses MUST stay
  as they are until the escape suite provides canaries.

### Key Entities

- **Cage**: a prepared policy. It holds the compiled profile, the grant
  classes, the path rewrites and the hygiene settings, and is reusable
  across spawns.
- **Path rewrite**: the original spelling and the resolved spelling of a
  policy path.
- **Grant binding**: grant name → existing path, for one spawn.
- **Apply method probe**: the cached result of testing the in-child apply
  method on this OS build.
- **Spawn error**: a typed reason why no caged child runs. One of:
  - unsupported (symbol, apply method, setting);
  - already sandboxed;
  - lowering error;
  - compile error;
  - limit exceeded;
  - grant error;
  - apply failure (step and OS error);
  - an I/O error from spawning.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The child MUST NOT execute its target unless applying the profile, confirming the sandbox and consuming its tokens all succeeded; spawning MUST return an error naming the failed step and OS error; spawning MUST be refused when the apply-method probe has not shown a caged child with a denied canary.
  - Mitigates: `threat.uncaged-run` via `mitigation.fail-closed-sequence`
  - Given a cage and a child whose apply step is made to fail, when spawn runs, then it returns an error naming the step and the target never runs
  - Given the first spawn of the process, when the probe runs, then it reports the apply method usable only after a throwaway child is caged and its canary access is denied
  - Given a policy granting one directory, when the child reads outside it, then the kernel refuses with EPERM
- **SR-002** (P1): Spawning from an already-sandboxed process MUST return AlreadySandboxed without forking a target.
  - Mitigates: `threat.silent-nesting` via `mitigation.nesting-check`
  - Given a process that is itself a caged child, when it asks procage to spawn, then it gets AlreadySandboxed and no grandchild runs
- **SR-003** (P1): Private libsandbox symbols MUST be resolved at runtime before any fork, and a missing symbol MUST yield Unsupported naming it; unsafe code MUST be confined to macos::sys with a SAFETY comment on every block.
  - Mitigates: `threat.ffi-memory-error`, `threat.symbol-removal` via `mitigation.dlsym-table`
  - Given a symbol name that does not exist, when the resolver looks it up, then it returns Unsupported naming the symbol and OS build
  - Given the root crate, when lints run, then unsafe code outside macos::sys fails the build and every unsafe block has a SAFETY comment
- **SR-004** (P1): Between fork and exec the child MUST only issue system calls on parent-prepared data; at least 100 caged children spawned from a parent with four threads under dyld contention MUST all be caged with none hanging.
  - Mitigates: `threat.fork-deadlock` via `mitigation.syscalls-only-child`
  - Given four threads looping dlopen/dlsym/dlclose, when 100 caged children are spawned, then all deny their canary access and none exceeds a 10 s timeout
- **SR-005** (P1): Every policy path MUST be resolved to its real, firmlink-visible spelling before lowering (longest existing prefix, remainder byte-exact, glob prefix escaped), with each rewrite recorded.
  - Mitigates: `threat.noncanonical-path` via `mitigation.canonicaliser`
  - Given a policy granting write to /tmp/<dir>, when the child creates a file via /tmp, then it succeeds and the cage records the rewrite to /private/tmp/<dir>
  - Given a path not yet existing below /tmp, when the cage is prepared, then the existing prefix is resolved and the remainder kept
  - Given a glob under /tmp whose resolved prefix contains a glob character, when the cage is prepared, then the character is escaped and matched literally
- **SR-006** (P1): A grant token MUST be issued per spawn, of class procage.<name>, for a resolved existing path, and MUST unlock only that grant for that spawn; undeclared grant names and missing paths MUST be typed errors; an unbound grant MUST give no access.
  - Mitigates: `threat.grant-leak` via `mitigation.per-spawn-tokens`
  - Given one cage with a write grant, bound to A then to B, when two children write to A and B, then each succeeds only in its own directory
  - Given an unbound grant, when the child writes through it, then access is refused
  - Given a binding for an undeclared name or a missing path, when spawn runs, then it fails with a typed grant error
- **SR-007** (P2): Compiled profiles MUST be cached only in memory, keyed by the exact profile text and parameters.
  - Mitigates: `threat.cache-confusion` via `mitigation.exact-memory-cache`
  - Given the same policy prepared twice, when the second cage is prepared, then no compile happens
  - Given two policies differing in one rule, when both are prepared, then two compiles happen
- **SR-008** (P2): A profile over the in-process compile limit MUST be refused with LimitExceeded before libsandbox is called.
  - Mitigates: `threat.compile-abort` via `mitigation.compile-limit`
  - Given a policy over the configured limit, when the cage is prepared, then it fails with LimitExceeded and the compile counter is unchanged
- **SR-009** (P1): The child's environment MUST be exactly the policy's allowlist (or passthrough minus denied names) of the caller's environment plus variables set explicitly on the command.
  - Mitigates: `threat.env-secret-leak` via `mitigation.env-from-policy`
  - Given the caller has SECRET_TOKEN and PATH set and the policy allowlists PATH, when the child prints its environment, then it shows PATH and not SECRET_TOKEN
  - Given passthrough denying SECRET_TOKEN, when the child prints its environment, then SECRET_TOKEN is absent and other variables are present
- **SR-010** (P1): With Tty::None the child MUST start a new session without a controlling terminal; Tty::NewPty MUST be refused with Unsupported until implemented.
  - Mitigates: `threat.terminal-injection` via `mitigation.new-session`
  - Given Tty::None, when the child queries its session and opens /dev/tty, then it leads its own session and has no controlling terminal
  - Given Tty::NewPty, when the cage is prepared, then it fails with Unsupported naming the setting
- **SR-011** (P2): Crate docs and the threat-model release status MUST state what this development version enforces on macOS (each claim backed by a caged-child test) and what it does not (fd hygiene, descendant lifetime, base profile, Linux); escape-class statuses MUST stay unchanged until escape-suite canaries exist.
  - Mitigates: `threat.overclaimed-enforcement` via `mitigation.honest-status`
  - Given the crate docs, README and threat model, when they are reviewed, then every enforcement sentence maps to a test in tests/spawn_macos.rs and the inherited-fd gap is stated
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: For every enforcement acceptance scenario of User Stories 1–4,
  a test spawns a real caged child and observes the stated outcome. All of
  them pass on macOS 26.6.2 outside any sandbox.
- **SC-002**: 100 of 100 children spawned under thread contention are caged
  (their denied access fails), and 0 hang beyond a 10-second timeout.
- **SC-003**: Preparing a cached policy a second time performs 0 compiles.
- **SC-004**: Each typed failure (missing grant, undeclared grant, nested
  sandbox, limit, unsupported setting) is observed by a test. In 0 cases the
  target program runs after a failed step.
- **SC-005**: A spawn with a prepared cage adds no more than 5 ms of median
  latency over an uncaged spawn of the same program on the development Mac.
  This is measured and recorded, not gated.
- **SC-006**: All existing gates (`just ci`) stay green, and the published
  package docs build.

## Assumptions

- **Path A only.** The in-child apply uses the measured `__mac_syscall`
  path. The helper process (path B, crash-isolated compile above the
  limit, helper integrity, whose design is still open) becomes its own later
  feature. Until then, its absence is a typed error, as the design allows.
- **Minimal hygiene now, full hygiene in 005.** This feature applies the
  hygiene settings the policy already carries and that need no new design:
  environment, resource limits, and a new session for `Tty::None`. It
  refuses `Tty::NewPty`. Closing inherited fds, process-group lifetime and
  kill-on-drop stay in feature 005. The docs state the gap rather than
  ignoring the setting.
- **No base profile yet.** A deny-default policy must grant what the
  program needs to start. Measured on 26.6.2, that is:
  - exec of the binary;
  - read and map-executable of `/usr/lib` and `/System`;
  - read of the literal `/`.
  The curated base profile is feature 006. Tests use a minimal base of
  their own.
- **Step reporting.** The failed step and OS error travel from the child to
  the parent as one encoded number through the standard library's own error
  channel. The value is set by a system call in the child, not by writing to
  a pipe of procage's own. The plan records this choice against the design's
  status pipe.
- **Custom extension classes work.** A token of class `procage.<name>`
  unlocks exactly the rule naming that class, and not another class
  (measured on 26.6.2, 2026-10-30).
- **Version.** Adding a public API to the root crate requires a version
  bump for the semver gate: the package version becomes 0.0.2. This is not
  a release; releases stay with feature 019 and the user's authorization.
- **Companion crate.** `procage` depends on `procage-policy`. Packaging needs
  both to be publishable, so `procage-policy` becomes a crate that will be
  published together with `procage`. Reserving its name on crates.io is a
  user action.

## Out of Scope

- Path B, the helper process, and helper integrity (a later row).
- Closing inherited fds, process groups, kill-on-drop, pseudo-terminals
  (005).
- The base profile (006), data-driven hard-deny content and presets (007).
- Linux spawning (008), violation monitoring (010), receipts (011).
- Changing any escape-class status in the threat model (009).
