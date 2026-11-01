# Feature Specification: Public design records

**Feature Branch**: `037-public-design-records` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: User description: "Make the specs public; only the private notes stay private. Rewrite specs and .specify so they read well in public: no links to private notes, no naming of the consumer project." Also a showcase of the ThreatSpec extension for Spec Kit.

## Context

Every procage change was specified with Spec Kit and threat-modelled with
the ThreatSpec extension: a spec, a plan, tasks, research with measurements,
a machine-readable threat model with security requirements, and the
verification that closed them. These records are the strongest evidence that
procage's claims are earned, and they are git-ignored today.

They are not ready to publish as they are: they point into private notes
(decision ids, research files, the planning list), name the consumer project that
drove several changes, and carry local paths of the machine they were
written on. A record that points nowhere, or names a private project, reads
as half a story.

## Clarifications

### Session 2026-11-01

- Q: What becomes public? → A: `specs/` (procage's rows) and `.specify/`
  (Spec Kit configuration, templates, the constitution, the ThreatSpec
  extension), except caches. The private notes, `.claude/` and `CLAUDE.md` stay
  private.
- Q: How are references to private notes handled? → A: Each record stands
  alone: the reason a decision note gave is written into the record where
  it matters; ids of private notes (decisions, questions, feedback items,
  planning items) are removed.
- Q: How is the consumer project named? → A: Not at all. Its feedback reads
  as "a consumer harness reported …". Its own rows live with it.
- Q: Are the records rewritten into current truth? → A: No. They are
  records of each change as made, kept accurate as history; a README says
  so and points to the authoritative documents (README, threat model, site).
- Q: How does it stay clean? → A: The planning-paths gate checks the public
  records for private references, consumer names and local paths.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A reviewer follows the reasoning (Priority: P1)

A security reviewer opens `specs/`, reads why a feature exists, its threat
model and how each security requirement was verified, without hitting a
reference to something they cannot open.

**Independent Test**: the gate finds no reference to private notes, no
consumer name and no local path in `specs/` or `.specify/`.

**Acceptance Scenarios**:

1. **Given** any record, **When** it gives a reason, **Then** the reason is
   in the record (no pointer to a private note).
2. **Given** a row driven by consumer feedback, **Then** it describes the
   need ("a consumer harness reported …") without naming the consumer.

---

### User Story 2 - A visitor finds and understands them (Priority: P2)

A visitor on GitHub or the site learns that procage is specified and
threat-modelled in the open, and how (Spec Kit plus ThreatSpec).

**Acceptance Scenarios**:

1. **Given** the README and the site, **Then** each links to `specs/` once,
   as design records.
2. **Given** `specs/README.md`, **Then** it explains what a record holds, that
   records are history, how ThreatSpec turns threats into tested
   requirements, and where the authoritative documents are.

---

### User Story 3 - It stays clean (Priority: P1)

A later change that adds a private reference fails `just ci`.

**Acceptance Scenarios**:

1. **Given** a record that mentions a decision id or a local path, **When**
   `just ci` runs, **Then** the planning-paths gate fails and names it.

### Edge Cases

- A threat model's `sources` hashes change when its spec is rewritten: the
  models are re-merged and re-rendered so `check` stays clean.
- Row 001's threat model is about keeping planning private: its wording is
  updated to the new rule, not deleted.
- Generated caches (`.specify/extensions/.cache/`) stay ignored.

## Requirements *(mandatory)*

- **FR-001**: `specs/` and `.specify/` (except caches) MUST be tracked;
  the private notes, `.claude/` and `CLAUDE.md` MUST stay ignored.
- **FR-002**: No public record MUST reference private notes (their
  directory, decision, question and feedback ids, research files, planning
  items), name a consumer project, or contain a local path or e-mail address.
- **FR-003**: Each record MUST keep its substance (requirements,
  measurements, threat models, verification), with reasons written in.
- **FR-004**: The constitution MUST state the new rule: public design
  records, private notes; the published product (crates, site, README)
  never depends on planning files.
- **FR-005**: `specs/README.md` MUST explain the records and ThreatSpec; the
  README and the site MUST link to it.
- **FR-006**: The planning-paths gate MUST check FR-002 on `specs/` and
  `.specify/` and keep checking that crates never cite planning paths.
- **FR-007**: Every public threat model MUST pass `threatspec check` after
  the rewrite.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): No public record MUST contain a reference to private notes, a consumer project's name, a local path, an e-mail address or a secret.
  - Mitigates: `threat.private-leak` via `mitigation.rewrite-and-scan`
  - Given specs/ and .specify/, when scanned for private-note directories and ids, research notes, planning references, consumer names, home-directory paths, e-mail and token patterns, then nothing is found
- **SR-002** (P2): specs/README.md MUST state that records describe each change as made and name the authoritative documents.
  - Mitigates: `threat.stale-claims` via `mitigation.history-readme`
  - Given specs/README.md, when read, then it says records are history and links the README, the threat model and the site
- **SR-003** (P1): just ci MUST fail when a public record contains a forbidden pattern.
  - Mitigates: `threat.gate-drift` via `mitigation.gate`
  - Given a planted decision id in a record, when just planning-paths runs, then it fails and names the file
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: The gate reports zero private references across all public
  records, and fails on a planted one.
- **SC-002**: Every public row's threat model checks clean.
- **SC-003**: `just ci` and `just site` pass.

## Assumptions

- Rewriting is editorial: no requirement, measurement or verdict changes.
