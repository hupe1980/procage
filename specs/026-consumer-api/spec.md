# Feature Specification: Consumer API before the freeze

**Feature Branch**: `026-consumer-api` (planning directory; commits land on `main`)

**Created**: 2026-10-31

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "026-consumer-api: Pre-freeze API changes from consumer feedback: environment decision that cannot leak, a portable backend surface, keeping a caged child in the caller's group or a self-confine-then-exec entry for helpers, Unix sockets under trees, the \"read everything except\" case and approximations."

## Context

A consumer harness that adopted procage reported nine findings about
procage's API. Three of them are about the shape of the API a consumer
writes against, and are cheap to change only before 0.1.0 freezes it:

- **Environment**: the consumer built the child's environment itself, called
  `Command::env_clear()` and set the variables it wanted, with a
  passthrough policy. std offers no getter for `env_clear`, so procage did
  not see it and rebuilt the environment from the caller's: every secret in
  the consumer's environment reached the caged command. procage's docs now say
  so, but the API still lets the mistake happen silently.
- **Portable surface**: `procage::macos` and `procage::linux` have the same shape, but a
  consumer must alias one module per system and write `cfg` blocks around
  the options.
- **Spawn-time masks**: reading the whole file system on Linux tier T1 reaches the
  paths of the `secrets` and `trust-handoff` classes. procage masks the
  ones that exist at spawn, which is an approximation the caller must
  accept construct by construct; the consumer had to learn the construct
  names from the error.

Research for this spec found that std's alternate `Debug` output of a
`Command` reports whether `env_clear` was called (a `clear: true,` line).
That makes it possible for procage to honour `env_clear` instead of
ignoring it, as long as it checks that the format still says so.

The row's two other items are features of their own and move to their own
rows: a self-confine-then-exec entry point for helper processes (a
blocker for the consumer, new feature 029-exec-entry, next) and Unix sockets
under trees (feature 028-linux-gaps, which also gets the portable variant).

## Clarifications

### Session 2026-10-31

- Q: How should the environment decision become impossible to get wrong:
  refuse passthrough when the command sets variables, or honour
  `env_clear`? → A: Honour `env_clear`. Refusing would break the documented
  "an explicit variable wins under passthrough" behaviour that procage's own
  tests and harnesses rely on. When the command called `env_clear`, no
  variable of the caller reaches the child under any policy, only those set
  on the command. procage checks once per process that it can observe the
  call; if it cannot, passthrough policies fail to spawn with an error
  instead of passing the caller's environment.
- Q: Does honouring `env_clear` change allowlist policies? → A: Yes, the same
  way: after `env_clear`, allowlisted caller variables are not passed
  either. If the call cannot be observed, an allowlist still passes only the
  variables the policy names (no error), because the policy author chose
  them.
- Q: What is the portable surface? → A: A module `procage::native` that is
  `procage::macos` on macOS and `procage::linux` on Linux, plus the
  guarantee, checked by a test that compiles on both systems, that the
  common subset (`Cage::new`, `Cage::with_options`,
  `CageOptions::default().with_lower(..)`, `Cage::spawn`,
  `Cage::spawn_with_fds`, `Grants::new().bind(..)`, `Child::kill_all`,
  `Child::detach`, `Child::dropped_env`, `Child::tmpdir`, `SpawnError`'s
  `Display`) has the same signatures. No trait object: the types stay
  concrete.
- Q: How does a caller accept the spawn-time masks without naming each
  construct? → A: One named option, `LowerOptions::accept_spawn_masks()`,
  that accepts exactly the data-driven class approximations (`secrets`,
  `trust-handoff`, `persistence`). Each accepted approximation is still
  recorded in the plan's degradations.
- Q: The helper entry point and Unix sockets under trees? → A: Out of this
  feature (features 029 and 028).

## User Scenarios & Testing *(mandatory)*

### User Story 1 - `env_clear` keeps the caller's environment out (Priority: P1)

A harness builds the environment for a caged command itself: it calls
`env_clear()` and sets exactly the variables it wants, whatever the
policy's environment setting. The child sees exactly those variables.

**Why this priority**: The mistake leaked every secret of the consumer's
environment.

**Independent Test**: With a secret in the caller's environment, a
passthrough policy and `env_clear()` plus one variable on the command,
the caged child's environment contains that variable and not the secret.

**Acceptance Scenarios**:

1. **Given** a passthrough policy and a caller environment with a secret,
   **When** the command calls `env_clear()` and sets `A=1`, **Then** the
   child sees `A=1` (and `TMPDIR` when procage provides one) and no other
   caller variable.
2. **Given** an allowlist policy naming `PATH`, **When** the command calls
   `env_clear()`, **Then** the child does not get the caller's `PATH`.
3. **Given** a passthrough policy without `env_clear`, **When** the command
   sets `A=1`, **Then** the child gets the caller's variables (minus the
   default denylist) plus `A=1`, as before.
4. **Given** a std whose `Command` formatting no longer reports
   `env_clear`, **When** a passthrough policy spawns, **Then** the spawn
   fails with an error that says why, and nothing runs.

---

### User Story 2 - One code path for both systems (Priority: P2)

A consumer writes `use procage::native::{Cage, CageOptions, Grants};` once
and the same code builds on macOS and Linux.

**Why this priority**: Consumers otherwise duplicate code per system.

**Independent Test**: A test that uses only `procage::native` compiles and
runs a caged command on macOS and on Linux T1/T2.

**Acceptance Scenarios**:

1. **Given** code that uses only the common subset through
   `procage::native`, **When** it is built on macOS and on Linux, **Then**
   it compiles without `cfg` and runs a caged command on both.

---

### User Story 3 - Reading everything except secrets on Linux (Priority: P3)

A caller that reads the whole file system on Linux T1 accepts the
spawn-time masks with one option and gets a cage; the degradations list
what was accepted.

**Why this priority**: A papercut that cost a round trip through an error
message.

**Independent Test**: A policy reading `/` lowers for T1 with
`accept_spawn_masks()` and fails without it; the plan's degradations name
the accepted classes.

**Acceptance Scenarios**:

1. **Given** a policy that reads `/` on T1, **When** it is lowered without
   options, **Then** it fails naming the class constructs; **When** with
   `accept_spawn_masks()`, **Then** it lowers and its degradations name
   them.
2. **Given** `accept_spawn_masks()`, **When** a policy has another
   approximation (for example a glob rule), **Then** that one is still
   refused.

### Edge Cases

- `env_clear()` followed by `env_remove("X")`: removals of nothing are
  harmless; the child gets only the variables set.
- `env_clear()` with no variables set: the child's environment is empty
  apart from what procage adds (`TMPDIR` with the `tmpdir` grant).
- The format check is per process and cached; it costs one formatting of a
  probe command.
- A command whose arguments or variable values contain the text
  `clear: true,`: the check must not be fooled (values are quoted on one
  line).
- On a T2 host, `accept_spawn_masks()` changes nothing: those classes are a
  gap there, not an approximation.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: When the command passed to a spawn has had `env_clear` called,
  the child's environment MUST consist only of the variables set on the
  command, plus procage's own additions (`TMPDIR` for the `tmpdir` grant),
  under every environment policy, on both systems.
- **FR-002**: procage MUST check, once per process, that it can observe
  `env_clear` on a probe command (positive and negative case). If the check
  fails, spawning with a passthrough policy MUST fail with a typed error
  before forking; allowlist policies keep working.
- **FR-003**: The observation MUST NOT be fooled by argument or variable
  values, and MUST NOT allocate or run code in the child.
- **FR-004**: Without `env_clear`, the environment decision MUST stay as it
  is (passthrough with denylist, explicit variables win, allowlist as
  written).
- **FR-005**: procage MUST provide `procage::native`, which is the backend
  module of the system it is built for.
- **FR-006**: A test MUST compile and run on macOS and Linux using only
  `procage::native` and the common subset named in the clarifications.
- **FR-007**: `LowerOptions` MUST offer `accept_spawn_masks()`, accepting
  exactly the `secrets`, `trust-handoff` and `persistence` approximations;
  accepted approximations MUST remain in the plan's degradations.
- **FR-008**: The crate docs MUST describe the `native` module, the
  environment rules including `env_clear`, and the "read everything except"
  case on Linux.
- **FR-009**: The consumer's findings on the environment, the portable
  surface and the spawn-time masks MUST be answered; the helper entry point
  and Unix sockets under trees MUST have features of their own.

### Key Entities

- **Environment decision**: the caller's environment, the policy, the
  command's explicit variables and whether the command cleared its
  environment, giving the child's variables and the dropped names.
- **Native module**: an alias of the current system's backend.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): When a command called env_clear, no variable of the caller MUST reach the child under passthrough or allowlist policies, on macOS and Linux T1 and T2.
  - Mitigates: `threat.env-clear-ignored` via `mitigation.honour-env-clear`
  - Given a secret in the caller's environment and a passthrough policy, when the command calls env_clear and sets A=1, then the child's environment holds A and no caller variable
  - Given an allowlist naming PATH, when the command calls env_clear, then the child does not get the caller's PATH
- **SR-002** (P1): If procage cannot observe env_clear, a passthrough spawn MUST fail before forking with a typed error.
  - Mitigates: `threat.env-observer-unreliable` via `mitigation.checked-observer`
  - Given an observer whose self-check fails, when a passthrough policy spawns, then the spawn fails with the typed error and no child runs
- **SR-003** (P1): The observer MUST NOT report a clear because of argument or variable values that contain its marker text, and MUST report clear exactly when env_clear was called.
  - Mitigates: `threat.env-observer-unreliable` via `mitigation.checked-observer`
  - Given commands with and without env_clear whose arguments and values contain the marker text, when they are observed, then only the cleared ones are reported as cleared
- **SR-004** (P2): Code using only procage::native and the common subset MUST compile and run a caged command on macOS and Linux.
  - Mitigates: `threat.native-drift` via `mitigation.portable-test`
  - Given the portable test, when it runs on macOS, T1 and T2, then it passes without cfg in its body
- **SR-005** (P2): accept_spawn_masks MUST accept exactly the secrets, trust-handoff and persistence approximations, and they MUST appear in the plan's degradations.
  - Mitigates: `threat.overbroad-acceptance` via `mitigation.exact-acceptance`
  - Given a policy reading / on T1, when lowered with accept_spawn_masks, then it lowers and its degradations name the classes
  - Given a policy with a glob rule on Linux, when lowered with accept_spawn_masks, then it is still refused
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A secret in the caller's environment never reaches a child
  whose command called `env_clear`, under passthrough and allowlist, on
  macOS, Linux T1 and T2 (100% of the tests).
- **SC-002**: The portable test compiles with zero `cfg` attributes in its
  body and passes on all three.
- **SC-003**: Existing environment tests pass unchanged.
- **SC-004**: `just ci` passes.

## Assumptions

- std 1.99's alternate `Debug` for `Command` prints `clear: true,` on its
  own line when the environment was cleared (measured in the std source).
  This is not a stable interface; the per-process check turns a change into
  a refused passthrough spawn.
- The consumer's code is not changed by this feature.
