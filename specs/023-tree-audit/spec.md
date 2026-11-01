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

### Session 2026-11-01 (after threat modelling)

- Q: How do subpath and glob protect/hide rules become the set of files to
  check? → A: By their own side, not by walking the workspace: an alias
  shows on the protected file itself as a link count above one. procage
  examines the literal targets, the files under protect and hide subpaths
  and the existing files of the secrets, trust-handoff and persistence
  classes, up to a walk limit, and refuses (or reports) any regular file
  with more than one name. Glob rules are expanded by walking their fixed
  prefix under the same limit. Past the limit the audit is incomplete,
  which the result and the receipt say; it is not a refusal.
- Q: Readable trees too? → A: Yes, by the same rule: the check is on the
  protected or hidden file, so it does not matter where the other name
  lies, readable or writable.
- Q: Hard links made during the run? → A: Not possible, so not listed: on
  macOS Seatbelt refuses to link a file the child cannot write (measured on
  26.6.2), on Linux Landlock never grants linking across directories and a
  protected path on tier T1 is a separate mount. The canaries assert it.
- Q: Cost? → A: The link check examines only the protected, hidden and
  class files, so it is on by default (refuse). The post-run handoff audit
  walks the writable trees, so it is opt-in.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A hard link cannot alias a protected file (Priority: P1)

A workspace contains `notes` hard-linked to the protected `.git/config`. The
cage refuses to start (or reports the link, if the caller chose to).

**Why this priority**: it closes an open escape class with a canary.

**Independent Test**: The R-08 canary (today ignored as open) passes on both
systems: the link is refused before the child runs.

**Acceptance Scenarios**:

1. **Given** a hard link inside a writable tree to a protected file, **When**
   the cage spawns with refuse, **Then** the spawn fails naming the protected
   file and its link count (the other name may lie anywhere).
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

- **FR-001**: Before spawning, procage MUST find every protected, hidden or
  class file (secrets, trust handoff, persistence) that has more than one
  name (a regular file with a link count above one), and MUST refuse the
  spawn naming each such file, or report them, as the caller chose; refuse
  is the default.
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

- **SR-001** (P1): Before every spawn, procage MUST examine, in the parent, every literal protect and hide target, every file under protect and hide subpaths and under the fixed prefix of protect and hide globs, and the existing files of the secrets, trust-handoff and persistence classes in every home; a regular file with a link count above one MUST be a link finding unless every one of its names was found among the targets and, for a file found in a hidden target, every name lies in a hidden target. Globs are matched exactly for *, ? and **; a glob with classes or alternatives is matched conservatively and its matches never count as accounted names. Cache directories inside class paths and the large application data and privacy-guarded folders named in the threat model are not examined. In Refuse mode a finding MUST fail the spawn with SpawnError::HardLinks.
  - Mitigates: `threat.alias-missed` via `mitigation.inode-match`
  - Given a file in a writable tree hard-linked to a protected .git/config, when the cage spawns with Refuse on macOS, Linux T1 and T2, then the spawn fails with HardLinks naming .git/config and its link count, and the target never runs
  - Given a hidden file whose second name lies in a readable-only tree, and a secrets class file whose second name lies outside every granted tree, when the cage spawns with Refuse, then the spawn fails naming both files
  - Given a protect or hide glob, a file it matches with a second name outside the glob, and a multi-link file under the glob's prefix that the glob does not match, when the link check runs, then the matched file is a finding and the unmatched one is not
  - Given hard links only between unprotected files in a writable tree, when the cage spawns, then it runs and the audit has no link finding
- **SR-002** (P1): LinkAudit::Refuse MUST be the default for every cage; Report and Off MUST take effect only when the caller names them, and the mode and every link finding MUST be in the audit result and in the receipt when receipts exist.
  - Mitigates: `threat.report-mode-silent` via `mitigation.refuse-default`
  - Given CageOptions with no link audit option, when a cage whose protected file has a second name spawns, then the spawn is refused with HardLinks
  - Given with_link_audit(Report), when the same cage spawns, then the child runs, and the audit result and the receipt record Report and list the file
  - Given with_link_audit(Off), when the same cage spawns, then the child runs and the audit result and the receipt record Off, never an empty complete link check
- **SR-003** (P1): The post-run audit MUST list each trust-handoff file created or modified, each symbolic link created (with its target) and each repository metadata directory created in the writable trees exactly once, and MUST detect a change by inode, size and status-change time, never by modification time alone.
  - Mitigates: `threat.mtime-reset` via `mitigation.ctime-snapshot`
  - Given a waived trust-handoff class and an existing .git/hooks/pre-commit, when the child rewrites it with the same size and resets its modification time, then the audit lists it as modified
  - Given Linux T1 and a .vscode/settings.json that did not exist at spawn, when the child creates it, then the audit lists it as created
  - Given a child that creates a symbolic link build pointing to the home directory and a nested .git directory, when the audit runs, then it lists the link with its target and the repository metadata, each once
  - Given a run that touched nothing of these kinds, when the audit runs, then it is empty and complete
- **SR-004** (P1): Both audits MUST stop at the walk limit and MUST mark their result incomplete, with the entries visited, past the limit or when any entry cannot be read; an incomplete link check MUST NOT refuse the spawn, and an incomplete result MUST NOT be presentable as an empty complete one, in the audit result or in the receipt.
  - Mitigates: `threat.silent-partial` via `mitigation.typed-incomplete`
  - Given a protect subpath with more files than a small walk limit, when the cage spawns with Refuse, then the child runs, links_complete is false with the visited count, and the receipt says the audit is incomplete
  - Given a child that creates more files than the walk limit, when the post-run audit runs, then handoff_complete is false with the count reached, within the time bound of SC-003 scaled to the limit
  - Given a child that makes a directory in a tree unreadable, when either audit runs, then the result is incomplete
- **SR-005** (P1): Audit walks MUST NOT follow symbolic links or cross to another device, and MUST read link targets without resolving them.
  - Mitigates: `threat.walk-follows-link` via `mitigation.nofollow-walk`
  - Given a child that creates a link loop pointing to its own directory and a link out pointing to the home directory, when the post-run audit runs, then it terminates, lists both links with their targets, and lists nothing from the home directory
  - Given a protect subpath containing a symbolic link to a directory outside it, when the pre-run link check runs, then the link is not traversed and no file outside the subpath is examined through it
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
- **SR-010** (P2): The link check MUST run in the parent on every spawn as the last step before the fork, re-examining the Targets each time, and MUST NOT reuse a result from an earlier spawn.
  - Mitigates: `threat.check-spawn-race` via `mitigation.check-last`
  - Given a cage that spawned cleanly once, when a second name is given to its protected file and the same cage spawns again, then the second spawn is refused
  - Given a protect subpath, when an aliased file is created under it after the cage was built and the cage spawns, then the spawn is refused naming that file
- **SR-011** (P1): A literal protect or hide target that is a symbolic link MUST be a link finding, so that Refuse fails the spawn, without the check following the link.
  - Mitigates: `threat.target-replaced-by-link` via `mitigation.target-link-finding`
  - Given a protected .git/config replaced by a symbolic link to a file with a second name, when the cage spawns with Refuse on macOS, Linux T1 and T2, then the spawn fails naming .git/config
- **SR-012** (P2): Every lane MUST have a non-ignored canary in which a caged child tries to hard link a protected and a hidden file into a writable tree and the kernel refuses it.
  - Mitigates: `threat.in-run-link` via `mitigation.in-run-canary`
  - Given the escape suites on macOS, Linux T1 and T2, when the child calls link on a protected and on a hidden file, then both calls fail and no second name exists after the run
- **SR-013** (P2): The receipt audit summary MUST hold only counts, mode and completeness unless the receipt includes the policy; finding paths MUST NOT appear otherwise.
  - Mitigates: `threat.receipt-paths-leak` via `mitigation.receipt-counts`
  - Given a Report run with a link finding and a handoff finding, when the receipt is built without the policy, then it holds the counts, the mode and completeness, and no finding path bytes
  - Given the same run, when the receipt is built with the policy, then the finding paths are present
- **SR-014** (P2): Both walks MUST honour the walk limit (default 200,000 on both systems); the handoff audit MUST NOT walk unless with_handoff_audit is set; the link check MUST stay within SC-003.
  - Mitigates: `threat.audit-cost` via `mitigation.bounded-cost`
  - Given a cage without with_handoff_audit, when it spawns and the run ends, then no snapshot is taken and the audit has no handoff part
  - Given the default policy and a 10,000-file workspace on the reference machine, when the link check runs, then it adds under 10 ms to the spawn
- **SR-015** (P3): SpawnError::HardLinks MUST name every refused file with its link count, and its message MUST say that removing the extra name, or choosing Report or Off by name, lets the spawn proceed.
  - Mitigates: `threat.benign-links-block` via `mitigation.actionable-refusal`
  - Given two protected files with second names, when the spawn is refused, then the error lists both files with their link counts and the message names the remedies
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: R-08 has non-ignored canaries on every lane.
- **SC-002**: Every artefact kind of User Story 2 is detected on every
  backend and tier.
- **SC-003**: The default link check adds under 10 ms to a spawn whose protected
  and hidden trees and class files hold 10,000 entries on the reference
  machine; the opt-in post-run audit takes under 50 ms for a writable tree of
  10,000 files.

## Assumptions

- Modification times and inode identity are sufficient to detect a change
  during a run; the plan records the snapshot taken at spawn.

## Out of Scope

- Restoring or quarantining changed files.
- Changes outside the writable trees (the cage denies those).
