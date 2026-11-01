# Feature Specification: Published threat model and escape-class contract

**Feature Branch**: `002-threat-model`

**Created**: 2026-10-30

**Status**: Draft

**Input**: User description: "002-threat-model: Publish procage's threat model as part of the published crate (README section plus a rustdoc page). It states adversary, assets, trusted components, in-scope and out-of-scope classes, sandbox strength versus microVMs, private-interface dependencies (libsandbox symbols, Linux tiers) and non-goals. The escape-class list (R-02…R-12, R-21…R-26, R-28…R-30) is published with stable ids, each with a disposition (mitigated / detected / harness-side) and a status that is honest about the current release: no class may be marked mitigated without a named kernel test as evidence. The list is the contract the escape suite (spec 009) must satisfy: a gate checks the catalog's structure, id stability and evidence rule. The README and crate docs must stop claiming enforcement the release does not ship. Published files never cite local planning paths."

## Context

procage's threat model exists only in local, unpublished planning notes. A
person deciding whether to put procage between an AI agent and their machine
cannot see what it defends against, what it trusts, or where it stops. The
published README and crate docs also describe macOS enforcement ("it applies
Seatbelt profiles") that the current release (0.0.1, a name reservation with
no API) does not ship. That breaks the project rule that no enforcement claim
is published without a kernel test behind it.

This feature publishes the threat model with the crate, and with it the
**escape-class catalog**: the named ways a caged process could escape or leak,
each with a stable id, an intended disposition and its honest status in the
current release. The catalog is also the contract for the later escape suite
(one canary per class), so a mechanical gate keeps it well-formed, keeps ids
stable, and refuses any "mitigated" claim that does not name its evidence.

Readers are adopters (harness and tool authors), security reviewers,
procage's maintainers and its CI.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Evaluate procage's security boundary before adopting it (Priority: P1)

An adopter opens the repository or the crate's documentation page and finds
one threat model. It states the adversary procage assumes, the assets it
protects, what it trusts, which classes are in and out of scope, how strong an
OS sandbox is compared with a microVM, which undocumented OS interfaces it
depends on, and its non-goals. A status line says plainly what the current
release enforces (nothing yet).

**Why this priority**: Adopters choosing an isolation tier for untrusted or
LLM-driven code must know the boundary before they rely on it. A missing or
inflated threat model leads to misplaced trust, which is the worst failure for
a security library.

**Independent Test**: Read the README and the crate's documentation page as
an outsider. Each topic in FR-002 is answered on the page, and the release
status says that this release enforces nothing.

**Acceptance Scenarios**:

1. **Given** the repository front page, **When** an adopter looks for the
   security boundary, **Then** a threat-model section summarises adversary,
   scope and strength and links to the full threat model.
2. **Given** the crate's documentation page, **When** an adopter opens it,
   **Then** the full threat model is reachable in one step from the crate root,
   with the same content as the repository copy.
3. **Given** the current release, **When** the adopter reads its status,
   **Then** it states that this release contains no sandboxing API and
   enforces nothing; no sentence describes enforcement in the present tense.

---

### User Story 2 - Read and rely on the escape-class catalog (Priority: P1)

A security reviewer or a harness author reads the escape-class catalog. Each
row names one escape or leak class with a stable id, a one-line description,
the platforms it concerns, the intended disposition (procage mitigates it,
procage detects it, or the harness owns it), the status in the current release,
and the evidence that backs that status. Where the kernel-facts suite has
observed the underlying OS behaviour (for example that an inherited file
descriptor bypasses path rules), the row names that observation.

**Why this priority**: The catalog is what makes the threat model checkable:
each class later gets a canary in the escape suite, and downstream projects
can cite class ids in their own audits.

**Independent Test**: Read the catalog. It contains exactly the classes R-02…R-12,
R-21…R-26 and R-28…R-30, each fully filled in; every status is `planned` or
`documented` in this release; every cited kernel observation exists in the
kernel-facts suite.

**Acceptance Scenarios**:

1. **Given** the catalog, **When** a reviewer looks up a class by id, **Then**
   the row shows description, platforms, disposition, current status and
   evidence.
2. **Given** a class whose disposition is harness-side, **When** a reviewer
   reads it, **Then** the row says what procage provides and what the harness
   must do itself.
3. **Given** a class whose OS behaviour the kernel-facts suite observes,
   **When** a reviewer reads it, **Then** the row names the kernel fact by id
   and the OS release it was measured on.

---

### User Story 3 - The gate keeps the catalog honest (Priority: P1)

A maintainer edits the threat model, or a later feature changes a class's
status. The quality gate run by `just ci` and CI fails if the catalog is
malformed, if a previously published id disappears or is renumbered, if a
status is `mitigated` or `detected` without naming evidence that exists in the
repository, or if a cited kernel fact does not exist. The README or crate docs
fail the gate if they stop linking to the threat model.

**Why this priority**: The constitution forbids unbacked enforcement claims.
Without a mechanical check the catalog drifts the moment the first backend
lands.

**Independent Test**: Inject each kind of defect (drop a row, mark a class
mitigated with no evidence, cite a non-existent test or kernel fact, break the
row format) and run the gate. Each injection fails with a message naming the
id and the rule; the clean tree passes.

**Acceptance Scenarios**:

1. **Given** a catalog row marked `mitigated` with an empty evidence field,
   **When** the gate runs, **Then** it fails naming that id and the evidence
   rule.
2. **Given** a published id removed from the catalog, **When** the gate runs,
   **Then** it fails naming the missing id (ids are retired, never removed).
3. **Given** evidence naming a test that does not exist in the repository,
   **When** the gate runs, **Then** it fails naming the id and the reference.
4. **Given** an unmodified tree, **When** the gate runs, **Then** it passes.

---

### User Story 4 - Report a vulnerability privately (Priority: P3)

Someone who finds an escape reads the repository's security policy. It says
how to report privately, what is in scope (pointing to the threat model), and
that pre-release versions enforce nothing.

**Why this priority**: A published threat model invites reports; without a
private channel they arrive as public issues. It is low priority because no
release enforces anything yet.

**Independent Test**: Open the security policy from the repository root; it
names a private reporting route and links the threat model.

**Acceptance Scenarios**:

1. **Given** the repository, **When** a reporter looks for how to disclose an
   escape, **Then** a security policy names a private route and refers to the
   threat model for scope.

---

### Edge Cases

- A class concerns only one OS (R-05 fcntl on macOS, R-28 io_uring on Linux):
  the row names that platform; the other OS is not implied.
- A class is mitigated on one Linux tier and only a typed gap on another (R-30):
  the row's disposition and notes say so, without a blanket "mitigated".
- A class's attack is observed to be *blocked by the kernel itself* rather than
  by procage (R-29, nested user namespaces against locked mounts): the evidence
  names the kernel observation, and the status still says what procage does.
- A class is retired later (the code removes the risk for good): the row stays
  with status `retired` and its id is never reused.
- The README is the crates.io landing page and may be truncated by readers:
  its summary stands on its own and links the full model.
- The crate documentation page is built where the repository's other files are
  absent: the threat model must ship inside the published package.
- Risks that are not escape classes (private-symbol removal, profile size
  limits, nested use inside an agent sandbox, a lower Linux tier) are described
  in the dependencies section, not in the catalog.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The project MUST publish exactly one threat-model document. It
  is shown on the repository, included in the published crate package, and
  rendered as a page reachable from the crate root documentation. All three
  views come from the same single source.
- **FR-002**: The threat model MUST state, each under its own heading:
  - the adversary: adaptive, same-uid code in the child that can fork, exec,
    and use whatever the policy grants;
  - the assets: secrets, files outside the grants, the host session,
    persistence locations, other runs and the caller's own state;
  - what is trusted: the parent process and its policy, the kernel, the OS
    sandbox libraries;
  - what is in scope: misconfiguration escapes, the known escape classes,
    leaks through inherited state, persistence and outliving the run;
  - what is out of scope: kernel, XPC, TCC and LSM bugs, side channels,
    denial of service beyond procage's resource limits, and trust handoff
    beyond the shipped presets;
  - the strength of an OS sandbox compared with a microVM, with guidance on
    when to choose a microVM;
  - the dependency on undocumented OS interfaces;
  - the non-goals.
- **FR-003**: The threat model MUST include a release-status statement that
  names the release and what it enforces. For 0.0.x it states that no
  sandboxing API exists and nothing is enforced.
- **FR-004**: The dependency section MUST say:
  - that macOS support relies on undocumented libsandbox symbols, which are
    resolved at run time; their absence is an "unsupported" error, never a
    silent fallback;
  - that Linux capability is probed into tiers and a tier procage cannot use is
    an error, never a best-effort weakening;
  - that procage refuses to run inside another Seatbelt sandbox rather than
    nesting silently;
  - that profile size is bounded.

  These are stated as design commitments of upcoming releases, not as shipped
  behaviour.
- **FR-005**: The threat model MUST contain the escape-class catalog. It has
  one row per class, R-02…R-12, R-21…R-26 and R-28…R-30 (20 classes), and the
  following fields:
  - id;
  - short name;
  - one-line description;
  - platforms (macOS, Linux or both);
  - disposition (`mitigate`, `detect` or `harness`);
  - status in this release (`planned`, `mitigated`, `detected`, `documented`
    or `retired`);
  - evidence;
  - observed-on (the kernel facts that confirm the underlying OS behaviour, if
    any).
- **FR-006**: Ids MUST be stable. A published id is never removed, renumbered
  or reused; a class that no longer applies keeps its row with status
  `retired`. The catalog explains that numbering gaps exist because ids are
  shared with other, non-escape risks.
- **FR-007**: A status of `mitigated` or `detected` MUST name, as evidence, at
  least one test in the repository that runs a caged child on a real kernel.
  In this release no class has that status. A status of `planned` or
  `documented` makes no enforcement claim, and its evidence field may be empty.
- **FR-008**: Every kernel fact cited under observed-on MUST exist in the
  kernel-facts suite, and the catalog MUST state the OS release the
  observations were recorded on.
- **FR-009**: A harness-side class (`harness` disposition) MUST say what
  procage provides and what remains the caller's responsibility.
- **FR-010**: A quality gate, run by `just ci` and by CI, MUST fail when any of
  the following holds:
  - a catalog row is missing or malformed;
  - a field value is outside its allowed set;
  - a previously published id is absent;
  - an id is duplicated;
  - FR-007 or FR-008 is violated;
  - the README or the crate root documentation no longer links to the threat
    model.

  Each failure names the id or file and the rule.
- **FR-011**: The README and crate root documentation MUST describe procage's
  intended behaviour as intended or planned. They MUST NOT state enforcement
  in the present tense while the release ships no sandboxing API. The README
  MUST include a short threat-model summary (adversary, scope, strength) that
  links to the full document.
- **FR-012**: The published package description MUST name both target platforms
  and the development status, without claiming enforcement.
- **FR-013**: The repository MUST contain a security policy. It names a private
  vulnerability reporting route, refers to the threat model for scope, and
  states which versions are supported.
- **FR-014**: No published file added or changed by this feature may cite the
  local planning directories. The existing planning-path gate MUST cover the
  new files.
- **FR-015**: The catalog MUST be machine-readable by the later escape suite.
  Its rows have a fixed, documented format that a test can parse without
  ambiguity, so that the suite can require one canary per non-retired
  `mitigate` or `detect` class.

### Key Entities

- **Threat model document**: the single published source; sections per FR-002,
  the release status, the dependency section and the escape-class catalog.
- **Escape class**: id (`R-NN`), name, description, platforms, disposition,
  status, evidence, observed-on, notes.
- **Evidence reference**: a pointer to a test in the repository that runs a
  caged child (required for `mitigated` and `detected`).
- **Kernel observation**: a kernel-fact id from the existing kernel-facts suite
  plus the OS release it was recorded on.
- **Published-id baseline**: the set of ids published so far, which the gate
  checks against so that no id silently disappears.
- **Security policy**: the reporting route, scope and supported versions.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The catalog gate MUST fail when a row has status mitigated or detected and its evidence is empty or names a test that does not exist in the repository, and the README and crate docs MUST NOT state enforcement in the present tense while no sandboxing API ships.
  - Mitigates: `threat.overclaimed-enforcement` via `mitigation.evidence-gate`
  - Given a row marked mitigated with empty evidence, when the gate runs, then it fails naming the id and the evidence rule
  - Given a row marked detected whose evidence names a non-existent test, when the gate runs, then it fails naming the id and the unresolved reference
  - Given the README and crate docs of a release with no sandboxing API, when they are reviewed, then no sentence describes enforcement in the present tense
- **SR-002** (P1): Evidence for mitigated or detected MUST resolve to a test function in an integration-test location that runs a caged child; references into library source or unit tests MUST fail the gate.
  - Mitigates: `threat.evidence-not-a-caged-test` via `mitigation.evidence-location-rule`
  - Given evidence pointing at a unit test inside the library source, when the gate runs, then it fails naming the id and the location rule
- **SR-003** (P1): The gate MUST fail when any id in the published-id baseline is absent from the catalog or an id appears twice.
  - Mitigates: `threat.silent-id-removal` via `mitigation.published-id-baseline`
  - Given the R-22 row deleted, when the gate runs, then it fails naming R-22 as missing
  - Given a second row with id R-10, when the gate runs, then it fails naming R-10 as duplicated
- **SR-004** (P1): The gate MUST reject, not skip, any row in the catalog section that does not parse into every field with an allowed value, and MUST fail when the parsed row count differs from the baseline count.
  - Mitigates: `threat.malformed-row-skipped` via `mitigation.strict-row-parser`
  - Given a row with status "done", when the gate runs, then it fails naming the id, the field and the allowed values
  - Given a row with a missing column, when the gate runs, then it fails naming the line instead of ignoring the row
- **SR-005** (P2): The gate MUST fail when an observed-on entry names a kernel fact absent from the kernel-facts catalog.
  - Mitigates: `threat.dangling-kernel-observation` via `mitigation.kernel-fact-resolution`
  - Given a row citing KF-M99, when the gate runs, then it fails naming the id and KF-M99
- **SR-006** (P1): The threat model MUST come from one source file that the crate package includes, and the crate documentation MUST build from the packaged crate alone with warnings as errors.
  - Mitigates: `threat.divergent-or-missing-published-copy` via `mitigation.single-source-embedding`
  - Given the packaged crate, when its file list is inspected, then it contains the threat-model file
  - Given the unpacked package, when its docs are built with warnings denied, then the build succeeds and the threat-model page is present
- **SR-007** (P1): The gate MUST fail when a required threat-model heading (adversary, assets, trusted, in scope, out of scope, strength, dependencies, non-goals, release status, escape classes) is missing or the release-status section does not name the crate's current version.
  - Mitigates: `threat.missing-scope-section` via `mitigation.required-sections-check`
  - Given the out-of-scope heading removed, when the gate runs, then it fails naming the missing heading
  - Given a release-status section naming 0.0.0 while the crate is 0.0.1, when the gate runs, then it fails naming both versions
- **SR-008** (P2): The planning-path gate MUST scan the threat-model document and the security policy, and the published files MUST NOT contain internal planning content (open user actions, unpublished decisions).
  - Mitigates: `threat.planning-content-leak` via `mitigation.planning-gate-coverage`
  - Given a planning path injected into the threat-model document, when the planning-path gate runs, then it fails naming the file
  - Given the finished document, when it is reviewed, then it contains no open user action or unpublished decision from the planning notes
- **SR-009** (P2): The repository MUST contain a security policy that names a private reporting route, asks reporters not to file escapes as public issues, and refers to the threat model for scope.
  - Mitigates: `threat.public-escape-report` via `mitigation.private-reporting-policy`
  - Given the repository root, when a reporter opens the security policy, then it names a private route, asks for no public issue and links the threat model
- **SR-010** (P3): Catalog rows MUST describe classes at the level of a one-line description with public sources and MUST NOT include exploit steps, payloads or proofs of concept.
  - Mitigates: `threat.catalog-as-exploit-guide` via `mitigation.class-level-descriptions`
  - Given the published catalog, when it is reviewed, then no row contains commands, payloads or exploit steps
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: An outsider finds every topic of FR-002 in the threat model, and
  reaches it in at most one link from both the repository front page and the
  crate documentation root.
- **SC-002**: The catalog lists all 20 escape classes. 100% of rows are fully
  filled in, and 0 rows claim `mitigated` or `detected` in this release.
- **SC-003**: Each of the six defect kinds in FR-010 is caught by the gate when
  injected (6 of 6), and the clean tree passes.
- **SC-004**: The README and crate docs contain no present-tense enforcement
  claim, as checked by review against FR-011.
- **SC-005**: The packaged crate contains the threat model, and the crate
  documentation builds from the package alone with warnings treated as errors.
- **SC-006**: Every cited kernel observation (100%) resolves to a fact in the
  kernel-facts suite.

## Assumptions

- **Ids kept as `R-NN`.** The published catalog keeps the risk numbers already
  used across the design. Renumbering would break the link to the escape
  suite and to decisions. The numbering gaps (R-01, R-13…R-20, R-27) are
  explained in the document (FR-006).
- **One source, two renderings.** The document lives at the repository root and
  is embedded into the crate docs, rather than being maintained twice.
- **Kernel facts are observations, not mitigations.** A kernel fact shows how
  the OS behaves (that the attack works, or that the kernel blocks it). It
  never makes a class `mitigated`; only a procage test that cages a child does.
- **Security policy route**: GitHub private vulnerability reporting for the
  repository. Enabling it in the repository settings is a maintainer action
  outside this feature.
- **Supported versions**: none enforce anything before 0.1.0; the policy says
  so.
- The threat-model content follows the design's current threat model (revision
  2, 2026-10-27) and the risk register. This feature publishes it and does not
  change the security design.
- Linux and macOS facts cited were recorded on macOS 26.6.2 (25G83) and Linux
  7.0.14-linuxkit (Docker Desktop, aarch64), 2026-10-29.

## Out of Scope

- Implementing any mitigation or canary (specs 003–009).
- Changing the security design, disposition or scope of any class beyond
  publishing it.
- A separate documentation website.
- Enabling repository settings (private vulnerability reporting), pushing or
  publishing a release.
