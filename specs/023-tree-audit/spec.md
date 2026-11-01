# Feature Specification: Audit of the writable trees, before and after a run

**Feature Branch**: `023-tree-audit` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: Two escape classes procage cannot fully prevent with path rules. (1) A hard link created before the run gives a protected or hidden file a second name inside a writable tree (R-08, open). (2) Trust handoff: the child writes a file that an unsandboxed program later runs or follows — git config and hooks, editor and agent settings, a symbolic link the host follows. The most frequent 2026 agent-sandbox escapes were of this class, including files that did not exist when the sandbox started (CVE-2026-25725, CVE-2026-39861).

## Context

procage denies writes to the known trust-handoff paths in every policy. On
macOS the rules hold for paths that do not exist yet. On Linux tier T1 they
are mounts over files found at spawn, so a file created later is not covered
(an approximation the caller accepts by name); on T2 Landlock cannot deny a
path inside an allowed tree at all. And no path rule can stop the *host* from
following a symbolic link or a nested `.git` the child created.

Prevention has limits; **detection** does not. An audit of the writable trees:

- **before** the run, lists hard links (link count above one) that alias a
  protected or hidden file, so the cage can refuse or report them;
- **after** the run, lists files of the trust-handoff classes that were
  created or changed, and symbolic links or repository metadata created in
  the writable trees, so the harness can review them before anything outside
  the sandbox uses them.

## Clarifications

### Session 2026-11-01

- Q: Refuse or report a pre-existing hard link? → A: The caller chooses per
  cage: refuse (spawn fails with the links found) or report (the audit lists
  them); the default is refuse when the policy protects or hides files, since
  the link defeats exactly those rules.
- Q: How deep does the post-run audit look? → A: Only the writable trees, only
  for the frozen trust-handoff patterns plus new symbolic links and new
  repository metadata directories; bounded by a walk limit like the Linux
  spawn snapshot, with a typed "incomplete" result past it.
- Q: Does the audit undo changes? → A: No. It reports; restoring or
  quarantining is the harness's decision.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A hard link cannot alias a protected file (Priority: P1)

A workspace contains `notes` hard-linked to the protected `.git/config`. The
cage refuses to start (or reports the link, if the caller chose to).

**Why this priority**: it closes an open escape class with a canary.

**Independent Test**: The R-08 canary (today ignored as open) passes on both
systems: the link is refused before the child runs.

**Acceptance Scenarios**:

1. **Given** a hard link inside a writable tree to a protected file, **When**
   the cage spawns with refuse, **Then** the spawn fails naming both paths.
2. **Given** report mode, **Then** the child runs and the audit lists the link.
3. **Given** a hard link to a hidden file, **Then** the same.

---

### User Story 2 - The harness sees what the run left behind (Priority: P1)

After a run, the harness gets a list: `.vscode/settings.json` created,
`.git/hooks/pre-commit` changed (if the class was waived), a symbolic link
`build -> ~/.ssh` created, a nested `.git` directory created.

**Independent Test**: A caged child creates each kind of artefact on each
backend and tier (with the relevant classes waived where the cage would
otherwise deny them); the post-run audit lists each exactly once.

**Acceptance Scenarios**:

1. **Given** Linux T1 and a trust-handoff file that did not exist at spawn,
   **When** the child creates it, **Then** the audit lists it as created.
2. **Given** a symbolic link created in a writable tree, **Then** the audit
   lists the link and its target.
3. **Given** a run that touched nothing of these kinds, **Then** the audit is
   empty and complete.

---

### User Story 3 - The receipt carries the audit (Priority: P3)

**Acceptance Scenarios**:

1. **Given** receipts (spec 011), **Then** the audit summary is part of the
   run's receipt.

### Edge Cases

- Very large trees: the walk limit returns "incomplete" with how far it got;
  never a silent partial list.
- Files changed by another process during the run: listed (the audit cannot
  tell writers apart); documented.
- Hard links across file systems are impossible; only same-device trees are
  checked for links.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: Before spawning, procage MUST find, in every writable tree, files
  with more than one link whose inode equals that of a protected or hidden
  file, and MUST refuse the spawn or report them as the caller chose.
- **FR-002**: After a run ends, procage MUST be able to list, in the writable
  trees: trust-handoff files created or modified during the run; symbolic
  links created; repository metadata directories created.
- **FR-003**: Both audits MUST be bounded by a walk limit and return a typed
  incomplete result past it.
- **FR-004**: The audits MUST run in the parent, never in the child between
  fork and exec, and MUST NOT follow symbolic links while walking.
- **FR-005**: The R-08 canaries MUST pass on both systems, and the threat
  model MUST move R-08 to mitigated (refuse) or detected (report), and record
  detection for R-07.
- **FR-006**: The audit result MUST be serialisable and included in the
  receipt when receipts exist.

### Key Entities

- **Link finding**: alias path, protected path, inode, refuse/report.
- **Handoff finding**: path, kind (created, modified, link, repository
  metadata), class, link target where applicable.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): Before spawning, procage MUST find every file in a writable tree whose device and inode equal those of a protected or hidden file, and in refuse mode the spawn MUST fail before the child runs, naming both paths.
  - Mitigates: `threat.alias-missed` via `mitigation.inode-match`
  - Given a file in a writable tree hard-linked to a protected .git/config, when the cage spawns in refuse mode, on macOS, Linux T1 and T2, then the spawn fails naming the alias and the protected path, and the target never runs
  - Given a hard link to a hidden file, when the cage spawns in refuse mode, then the spawn fails the same way
  - Given a writable tree with hard links only between unprotected files, when the cage spawns, then it runs and the audit has no link finding
- **SR-002** (P1): Refuse MUST be the default whenever the policy protects or hides files; report mode MUST be chosen by the caller by name, and the mode and every link finding MUST be in the audit result and in the receipt when receipts exist.
  - Mitigates: `threat.report-mode-silent` via `mitigation.refuse-default`
  - Given a policy that protects files and no audit option set, when a cage with an aliasing hard link spawns, then the spawn is refused
  - Given report mode chosen by the caller, when the same cage spawns, then the child runs, and the audit result and the receipt record report mode and list the link
- **SR-003** (P1): The post-run audit MUST list each trust-handoff file created or modified, each symbolic link created (with its target) and each repository metadata directory created in the writable trees exactly once, and MUST detect a change by inode, size and status-change time, never by modification time alone.
  - Mitigates: `threat.mtime-reset` via `mitigation.ctime-snapshot`
  - Given a waived trust-handoff class and an existing .git/hooks/pre-commit, when the child rewrites it with the same size and resets its modification time, then the audit lists it as modified
  - Given Linux T1 and a .vscode/settings.json that did not exist at spawn, when the child creates it, then the audit lists it as created
  - Given a child that creates a symbolic link build pointing to the home directory and a nested .git directory, when the audit runs, then it lists the link with its target and the repository metadata, each once
  - Given a run that touched nothing of these kinds, when the audit runs, then it is empty and complete
- **SR-004** (P1): Both audits MUST stop at a walk limit and MUST return a typed incomplete result, with how far they got, past the limit or when any entry cannot be read; an incomplete result MUST NOT be presentable as an empty list.
  - Mitigates: `threat.silent-partial` via `mitigation.typed-incomplete`
  - Given a child that creates more files than the walk limit, when the post-run audit runs, then it returns incomplete with the count reached, within the time bound of SC-003 scaled to the limit
  - Given a child that makes a directory in the tree unreadable, when either audit runs, then the result is incomplete and names the directory
- **SR-005** (P1): Audit walks MUST NOT follow symbolic links or cross to another device, and MUST read link targets without resolving them.
  - Mitigates: `threat.walk-follows-link` via `mitigation.nofollow-walk`
  - Given a child that creates a link loop pointing to its own directory and a link out pointing to the home directory, when the post-run audit runs, then it terminates, lists both links with their targets, and lists nothing from the home directory
  - Given a protected file reachable only through a symbolic link in a writable tree, when the pre-run audit runs, then the link is not traversed and no file outside the tree is examined through it
- **SR-006** (P2): The post-run audit MUST run only after the run is over (child reaped, every process of the run gone); before that it MUST return incomplete with that reason.
  - Mitigates: `threat.audit-too-early` via `mitigation.after-run-only`
  - Given a detached run whose descendant still runs, when the harness asks for the post-run audit, then it is incomplete because the run has not ended
  - Given a run with Lifetime::Run whose descendant writes a hook after the child exits, when the run ends and the audit runs, then the descendant is gone and the hook is listed
- **SR-007** (P2): Findings MUST keep paths and link targets as exact bytes; their serialised form MUST round-trip them and their display MUST escape control characters.
  - Mitigates: `threat.finding-injection` via `mitigation.byte-paths`
  - Given a created file whose name holds a newline, an escape character and invalid UTF-8, when the finding is serialised, read back and displayed, then the bytes are equal and the display shows the characters escaped
- **SR-008** (P3): Both audits MUST run in the parent, never between fork and exec in the child.
  - Mitigates: `threat.audit-in-child` via `mitigation.parent-only`
  - Given a multithreaded parent spawning many cages with both audits on, when the spawn tests run, then no spawn deadlocks and the child-side call sequence is unchanged
- **SR-009** (P2): The threat model MUST change R-08's status only with non-ignored canaries on every lane, MUST record R-07 as detected by the post-run audit and still a harness responsibility, and the docs MUST NOT present an empty audit as proof that the trees are safe.
  - Mitigates: `threat.status-overclaim` via `mitigation.measured-status`
  - Given THREAT_MODEL, the crate docs and the site, when they describe R-07, R-08 and the audit, then R-08 names its canaries per lane, R-07 says the harness still reviews the trees, and no text calls an empty audit proof
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: R-08 has non-ignored canaries on every lane.
- **SC-002**: Every artefact kind of User Story 2 is detected on every
  backend and tier.
- **SC-003**: Pre-run audit adds under 10 ms for a tree of 10,000 files on the
  reference machine; the post-run audit under 50 ms.

## Assumptions

- Modification times and inode identity are sufficient to detect a change
  during a run; the plan records the snapshot taken at spawn.

## Out of Scope

- Restoring or quarantining changed files.
- Changes outside the writable trees (the cage denies those).
