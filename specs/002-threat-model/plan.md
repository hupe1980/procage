# Implementation Plan: Published threat model and escape-class contract

**Branch**: `002-threat-model` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/002-threat-model/spec.md`

## Summary

Add one published document, `THREAT_MODEL.md`, at the repository root. It is:

- included in the `procage` package;
- rendered on docs.rs as a docs-only module, `procage::threat_model`, through
  `#![doc = include_str!("../THREAT_MODEL.md")]`;
- summarised in a new README section that links to it.

The document holds the ten required sections and the escape-class catalog:
20 rows in a fixed Markdown table, plus a "Harness responsibilities"
subsection for the harness-side classes.

A std-only integration test of the root crate, `tests/threat_model.rs`, is
the catalog gate. It parses the catalog strictly and checks:

- the published-id baseline;
- the allowed values, and that disposition and status agree;
- the evidence location rule (and that the referenced test exists);
- that every cited kernel fact exists in the kernel-facts catalog;
- the required headings, and that the release status names the current
  version;
- that the README and crate docs link to the threat model.

Each check is a pure function over strings. Unit tests feed it mutated copies
of the real document, so every defect kind is injected and caught on every
run.

Further changes:

- A new `package-docs` recipe in `just ci` packages the crate and builds its
  docs from the unpacked package, with warnings denied.
- The README, crate docs and package description stop describing enforcement
  in the present tense.
- `SECURITY.md` names GitHub private vulnerability reporting.
- The planning-path gate also scans the new root documents.

## Technical Context

**Language/Version**: Rust, edition 2024, MSRV 1.99

**Primary Dependencies**: none new. The gate uses std only, with no dev-dependencies.

**Storage**: Repository files: `THREAT_MODEL.md`, `SECURITY.md`, README, `src/lib.rs`, `src/threat_model.rs`

**Testing**: `cargo test --workspace` runs `tests/threat_model.rs`: the gate over the real files, plus injection unit tests over mutated copies. A just recipe packages the crate and builds its docs.

**Target Platform**: any host OS; the gate is pure text processing. docs.rs renders the module.

**Project Type**: Library documentation and a quality gate

**Performance Goals**: the gate adds < 1 s to `cargo test`

**Constraints**:

- No published file cites the planning directories.
- Relative links inside `THREAT_MODEL.md` must work both on GitHub and in rustdoc, so it uses only absolute repository URLs or none.
- rustdoc runs with `-D warnings`, so table text must not create broken intra-doc links: no bare `[x]` patterns.

**Scale/Scope**: 1 document (10 sections, 20 catalog rows), 1 security policy, 1 docs module, 1 gate test file, 2 just recipe changes, README and lib.rs rewrites

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan complies | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | The gate fails on any unparsable row and never skips one (SR-004). The dependency section states the fail-closed design (`Unsupported`, tier errors, `AlreadySandboxed`) as a commitment of upcoming releases | gate unit tests | — |
| II. Types over strings | Not applicable to documents. The gate parses fields into enums (disposition, status, platform) rather than comparing free text | gate code | — |
| III. Kernel is the oracle | No procage enforcement claim is published: every class is `planned` or `documented`. A `mitigated`/`detected` status requires evidence in a caged-child integration test (SR-001, SR-002). Claims about OS behaviour cite kernel facts with OS release and date (SR-005) | gate; kernel-facts catalog | Kernel facts on Linux distros are only verified locally (Docker) until CI runs |
| IV. Syscalls only / unsafe in sys | No unsafe code; the docs module is empty apart from its documentation | `unsafe_code = forbid` | — |
| V. Hygiene by default | Stated in the threat model as the in-scope inherited-state classes (R-21…R-26), status planned | catalog | Implemented in spec 005 |
| VI. Private interfaces, honestly | This feature delivers the public statement of the libsandbox dependency, Linux probing, the threat model and the non-goals (required headings, SR-007) | gate heading check | — |
| VII. A library, not a harness | Adds one public, documentation-only module (`threat_model`), which is a minor change for semver-checks. No global state, no dependency | `just semver`, `just deny` | The module becomes API surface; see Complexity Tracking |

**Workflow rules**:

- One spec (002).
- Local planning stays local: the planning-path gate is extended to the new files (SR-008).
- The decision is recorded: public escape-class ids, and `THREAT_MODEL.md` as the source of truth.
- No commits without authorization.

**Gate result (pre-research)**: PASS. **Post-design re-check**: PASS. The
design adds no code outside a test file and an empty docs module. Every
catalog status is non-claiming.

## Project Structure

### Documentation (this feature)

```text
specs/002-threat-model/
├── plan.md
├── research.md          # R1–R9 decisions
├── data-model.md        # catalog row, enums, consistency rules
├── quickstart.md        # validation scenarios incl. injected defects
├── contracts/
│   ├── catalog-format.md   # the table format the escape suite will parse
│   └── gate.md             # gate rules, messages, recipes
├── threat-model.yaml    # ThreatSpec (+ threat-model.md, security/)
└── tasks.md
```

### Source Code (repository root)

```text
THREAT_MODEL.md            # NEW: single source (sections + catalog + harness responsibilities)
SECURITY.md                # NEW: private reporting route, scope, supported versions
README.md                  # rewritten intro (planned, not present tense) + "Threat model" summary section
Cargo.toml                 # package: description, include += /THREAT_MODEL.md, categories
src/lib.rs                 # crate docs: honest status, link to `threat_model`; `pub mod threat_model;`
src/threat_model.rs        # NEW: #![doc = include_str!("../THREAT_MODEL.md")], no items
tests/threat_model.rs      # NEW: catalog gate (root-crate integration test, std only)
justfile                   # planning-paths covers THREAT_MODEL.md and SECURITY.md; new `package-docs` gate in `ci`
```

**Structure Decision**: the gate is an integration test of the root crate,
so it runs under the existing `test` gate and in every CI lane without a new
crate. It reads the files relative to `CARGO_MANIFEST_DIR`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| A public, documentation-only module `procage::threat_model` (new API surface) | FR-001 needs a page reachable from the crate root on docs.rs, rendered from the single source | Putting the document into the crate-root docs would bury the API overview under a long page. A `#[doc(hidden)]` module would not be reachable. A link to GitHub only would fail "ships inside the package" (FR-001) and would not version with the crate |
