# Feature Specification: Data-driven hard denies and frozen presets

**Feature Branch**: `007-hard-deny-and-presets`

**Created**: 2026-10-30

**Status**: Shipped in 0.1.0 (2026-11-01)

**Input**: User description: "007-hard-deny-and-presets: Hard-deny tier (both OSes), secrets/trust-handoff data files, `minimal`, `build`, `agent_workspace`, `agent_readonly` as frozen `V1`, waivers overridable by name."

## Context

The hard-deny tier is emitted last in every policy. Today it holds only the
classes with fixed content, such as the fcntl trick, privilege, service
handoff and process access (feature 003). Several known escapes still come
through a policy that grants a broad tree:

- **Secrets in the home directory.** SSH keys, cloud and registry
  credentials, keychains, browser profiles and mail.
- **Trust handoff (R-07).** The sandbox writes a file that an unsandboxed
  tool later runs or reads as configuration: git hooks and config, shell rc
  files, editor and agent configuration, binaries on `PATH`.
- **Persistence (R-23).** Launch agents and login items run later, outside
  any run.

This feature adds these as data-driven hard-deny classes. They are emitted
last, so even an explicit allow cannot override them. The only way around
one is to waive the class by name, which is recorded.

It also ships the four **presets** the design names, each as a frozen
version 1: `minimal`, `build`, `agent_workspace` and `agent_readonly`. With a
preset, a harness author starts from a reviewed policy instead of a blank
page.

For the first time, the hard-deny tier is shown on the kernel: caged
children try to read secrets, write git hooks and plant launch agents.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Secrets stay unreadable even inside a granted tree (Priority: P1)

A harness grants read access to the user's home directory, for example so a
tool can read its configuration. The child still cannot read SSH keys, cloud
credentials, the GnuPG keyring, keychains, browser profiles or mail, however
the path is spelled. Waiving the `secrets` class, by name, is the only way
to allow it.

**Why this priority**: These are the most valuable assets on a developer
machine. Broad home grants are common in agent harnesses.

**Independent Test**: With read access to `$HOME`, the child can list
`$HOME`, but listing `~/.ssh` or `~/.aws` is refused, also when spelled
`~/.SSH`. With `secrets` waived, listing `~/.ssh` works.

**Acceptance Scenarios**:

1. **Given** read access to `$HOME`, **When** the child lists `~/.ssh`,
   `~/.aws` or `~/.gnupg`, **Then** each is refused, and listing `$HOME`
   succeeds.
2. **Given** the same, **When** the child lists `~/.SSH`, **Then** it is
   refused.
3. **Given** `secrets` waived, **When** the child lists `~/.ssh`, **Then** it
   succeeds, and the plan lists the waiver.

---

### User Story 2 - The sandbox cannot leave work for an unsandboxed tool (Priority: P1)

A coding agent has write access to its workspace. It cannot write any of
these:

- inside a repository: `.git/hooks`, `.git/config`, `.gitmodules`;
- shell startup files: `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`,
  `.profile`, `.envrc`;
- tool configuration: `.gitconfig`, `.npmrc`, `.cargo/config.toml`, `.mcp.json`;
- editor and agent directories: `.vscode`, `.idea`, `.claude`, `.codex`,
  `.cursor`;
- `PATH` locations in the home: `~/.cargo/bin`, `~/.local/bin`.

It can still write ordinary files and the rest of `.git` (objects, refs,
index), so git keeps working. It cannot plant launch agents or login items.

**Why this priority**: The sandbox can hold perfectly and still lose, if an
unsandboxed tool later runs what the sandbox wrote (R-07, the Beltdown and
GitPwned reports). Persistence outlives every run (R-23).

**Independent Test**: In a writable workspace with a `.git` directory, the
child:
- cannot create `.git/hooks/pre-commit`, write `.git/config`, create `.zshrc`
  or create `.vscode/settings.json`;
- can create `src/main.rs` and `.git/objects/x`;
- cannot create a file in `~/Library/LaunchAgents`, even when the policy
  grants that directory write access.

**Acceptance Scenarios**:

1. **Given** write access to a workspace with `.git/`, **When** the child
   creates `.git/hooks/pre-commit`, **Then** it is refused, and
   `.git/objects/x` succeeds.
2. **Given** the same, **When** the child creates `.zshrc`, `.envrc` or
   `.vscode/settings.json` in the workspace, **Then** each is refused.
3. **Given** a policy that grants write access to `~/Library/LaunchAgents`,
   **When** the child creates a file there, **Then** it is refused.
4. **Given** `trust-handoff` waived, **When** the child creates
   `.git/hooks/pre-commit`, **Then** it succeeds.

---

### User Story 3 - Start from a reviewed preset (Priority: P2)

A harness author picks a preset and names the workspace: `minimal`,
`build(workspace)`, `agent_workspace(workspace)` or
`agent_readonly(workspace)`. The result is an ordinary policy they can
inspect and extend. Each preset is version 1 and frozen; it never loosens.

**Why this priority**: Most callers want the same few shapes. Presets carry
the base profile, the hard-deny tier and sensible hygiene, so callers do not
need to know every rule.

**Independent Test**: Each preset is pinned by a test. In a caged run:
- `agent_workspace` writes in the workspace but not in `.git/hooks`, reads
  no secrets, and has no network;
- `agent_readonly` cannot write the workspace;
- `build` can run programs it builds in the workspace;
- `minimal` runs `echo` and nothing touches the home directory.

**Acceptance Scenarios**:

1. **Given** `agent_workspace(W)`, **When** the child writes `W/src/x`,
   `W/.git/hooks/x` and `~/.ssh/x`, **Then** only `W/src/x` succeeds.
2. **Given** `agent_readonly(W)`, **When** the child writes `W/x`, **Then** it
   is refused, and reading `W` succeeds.
3. **Given** `build(W)`, **When** the child executes a script it wrote to `W`,
   **Then** it runs.
4. **Given** any preset, **When** it is lowered, **Then** its content equals
   the pinned version 1.

---

### Edge Cases

- **Waivers**: each new class can be waived only by its name, and the plan
  lists every waiver (as in 003).
- **Explicit grants**: an explicit grant of `~/.ssh` stays denied unless
  `secrets` is waived. The hard-deny tier wins by design.
- **Case**: on case-insensitive APFS the kernel matches path rules
  case-insensitively, also when a new file is created (measured). The
  patterns are case-folded anyway, as a second guard.
- **Linux**: the Linux backend does not exist yet. These classes are not
  expressible in a Linux plan today: Landlock cannot deny inside a granted
  tree, and T1 masking happens at spawn. The lowering table states this, and
  the Linux spawn feature (008) must implement them before it ships.
- **Rename around the pattern**: moving `.git` aside, editing it and moving
  it back is blocked, because `.git` cannot be removed or renamed (FR-003a).
- **Git**: git keeps working. Objects, refs, the index and the working tree
  stay writable; only hooks, config and `.gitmodules` are protected.
- **Frozen presets**: a preset version that needs more access gets a new
  version. Version 1 never changes. A tightening is a fix, stated in the
  docs.

## Requirements *(mandatory)*

### Functional Requirements

**Hard-deny classes**

- **FR-001**: The hard-deny tier MUST gain three classes, each waivable only
  by name:
  - `secrets`: read and write denied;
  - `trust-handoff`: write denied;
  - `persistence`: write denied.
- **FR-002**: `secrets` (macOS) MUST cover, in every home under `/Users`:
  - `.ssh`, `.aws`, `.gnupg`, `.netrc`, `.docker/config.json`, `.kube`;
  - `.config/gh`, `.config/gcloud`, `.git-credentials`, `.pypirc`,
    `.cargo/credentials.toml`;
  - `Library/Keychains`, `Library/Cookies`, `Library/Mail`,
    `Library/Messages`, `Library/Safari`;
  - the browser profiles under `Library/Application Support` (Google
    Chrome, Firefox, BraveSoftware, Microsoft Edge).
- **FR-003**: `trust-handoff` (macOS) MUST cover these, in any directory:
  - `.git/hooks`, `.git/config`, `.gitmodules`;
  - `.bashrc`, `.bash_profile`, `.zshrc`, `.zprofile`, `.zshenv`, `.profile`,
    `.envrc`;
  - `.gitconfig`, `.npmrc`, `.cargo/config.toml`, `.cargo/config`, `.mcp.json`;
  - the directories `.vscode`, `.idea`, `.claude`, `.codex`, `.cursor`.

  It MUST also cover, in every home under `/Users`: `.cargo/bin`,
  `.local/bin` and `.ssh/config`.
- **FR-003a**: `trust-handoff` MUST also deny removing or renaming any
  `.git` directory. Otherwise the child could move `.git` aside, write hooks
  there, and move it back. Creating `.git` stays allowed. `git init` and
  `git clone` write hooks and config, so they need the class waived, and the
  docs say so.
- **FR-004**: `persistence` (macOS) MUST cover, in every home:
  `Library/LaunchAgents`, `Library/LaunchDaemons` and
  `Library/Application Support/com.apple.backgroundtaskmanagementagent`. It
  MUST also cover `/Library/LaunchAgents` and `/Library/LaunchDaemons`.
- **FR-005**: The patterns MUST be fixed, case-folded globs compiled
  through the existing glob and escaper path. The lists are part of the
  version (they are frozen like presets, and a change is a documented
  version bump of the tier).
- **FR-006**: On Linux, the lowering table MUST mark the three classes as not
  yet expressible. The Linux spawn feature (008) MUST carry the
  requirement to implement them.

**Presets**

- **FR-007**: The policy crate MUST provide these presets, each returning a
  policy tagged with the preset name and version:
  - `minimal::v1()`: base V1, nothing else;
  - `agent_readonly::v1(workspace)`: base V1, read of the workspace, the
    `tmpdir` grant, fork, signals to self and children, no network;
  - `agent_workspace::v1(workspace)`: as `agent_readonly`, with write and
    exec on the workspace;
  - `build::v1(workspace)`: as `agent_workspace`, with loopback network.

  In all of them the environment is an allowlist of `PATH`, `HOME`, `USER`,
  `LANG`, `LC_ALL`, `TERM` and `TMPDIR`, and the full hard-deny tier applies.
- **FR-008**: Each preset's content MUST be pinned by a test. The policy MUST
  record its preset name and version in its data form, for receipts.

**Evidence and docs**

- **FR-009**: Each user-story acceptance scenario MUST be a caged test on the
  kernel. The new classes' rules MUST compile.
- **FR-010**: The docs MUST list each class's patterns and each preset's
  content, state that Linux enforcement of the data classes is pending
  (008), and keep the escape-class statuses unchanged.

### Key Entities

- **Data-driven hard-deny class**: a name, an access to deny, a frozen
  pattern list per OS.
- **Preset**: a name and version, plus a function from a workspace to a
  policy.
- **Pattern**: an absolute glob, case-folded when lowered.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): With a read grant on the home directory, the listed secret paths MUST stay unreadable to the child unless the secrets class is waived by name.
  - Mitigates: `threat.secret-read-in-granted-tree` via `mitigation.secrets-class`
  - Given read access to HOME, when the child lists ~/.ssh, ~/.aws and ~/.gnupg, then each is refused and listing HOME succeeds
  - Given secrets waived, when the child lists ~/.ssh, then it succeeds and the plan lists the waiver
- **SR-002** (P1): With write access to a workspace, the child MUST NOT create or modify git hooks, git config, .gitmodules, shell rc files, editor or agent config directories or tool config files, while git objects, refs and the index stay writable; waiving trust-handoff by name allows them.
  - Mitigates: `threat.git-broken`, `threat.persistence-plant`, `threat.trust-handoff-write` via `mitigation.handoff-and-persistence-classes`
  - Given write access to a workspace with .git, when the child creates .git/hooks/pre-commit, .zshrc, .envrc and .vscode/settings.json, then each is refused and .git/objects/x succeeds
  - Given trust-handoff waived, when the child creates .git/hooks/pre-commit, then it succeeds
- **SR-003** (P1): The child MUST NOT create files in launch-agent or login-item locations, even when the policy grants write access there.
  - Mitigates: `threat.git-broken`, `threat.persistence-plant`, `threat.trust-handoff-write` via `mitigation.handoff-and-persistence-classes`
  - Given write access to ~/Library/LaunchAgents, when the child creates a file there, then it is refused and nothing is created
- **SR-004** (P1): Data-class patterns MUST deny case variants of the listed names.
  - Mitigates: `threat.case-variant-bypass` via `mitigation.case-folded-patterns`
  - Given read access to HOME, when the child lists ~/.SSH, then it is refused
  - Given a writable workspace with .git, when the child creates .GIT/HOOKS/x or .ZSHRC, then each is refused
- **SR-005** (P2): The class lists and every preset V1 MUST be pinned by tests.
  - Mitigates: `threat.list-or-preset-drift` via `mitigation.pinned-lists-and-presets`
  - Given each preset and class, when it is lowered or serialised, then it equals the pinned content
- **SR-006** (P2): The lowering table and docs MUST state that Linux enforcement of the data classes is pending, and the Linux spawn spec (008) MUST carry it.
  - Mitigates: `threat.linux-silently-weaker` via `mitigation.linux-pending-explicit`
  - Given the lowering table and the 008 spec, when reviewed, then the Linux cells say pending and 008 lists the requirement
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: 100% of the acceptance scenarios pass on macOS 26.6.2, outside
  any sandbox.
- **SC-002**: 0 secret paths are readable with a `$HOME` read grant unless
  `secrets` is waived.
- **SC-003**: Git operations that do not touch hooks or config (writing
  objects, refs, the index, the working tree) succeed in the workspace.
- **SC-004**: `just ci` stays green.

## Assumptions

- **Linux pending.** Linux enforcement of the data classes needs mount masks
  in T1 and cannot be exact in T2. Both belong to 008; the lowering table
  and the 008 spec say so.
- **No home in the IR.** Patterns cover every home under `/Users` instead of the caller's home,
  so the IR needs no home field and every user's secrets are covered.
- **`launchctl submit`**: the Mach service names are unverified, so
  the persistence class covers files only. This question stays open.
- **Own files**: procage's own files join the tier with the helper (021).
- **Measured on macOS 26.6.2 (25G83), 2026-10-30.** Seatbelt matches path
  rules case-insensitively on case-insensitive APFS, for existing files and
  for new names.

## Out of Scope

- Linux enforcement (008), the helper's own files (021), mach-based
  persistence (`launchctl submit`), and pseudo-terminals (022).
