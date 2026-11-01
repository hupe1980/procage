---

description: "Task list for 002-threat-model"
---

# Tasks: Published threat model and escape-class contract

**Input**: Design documents from `specs/002-threat-model/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/, quickstart.md

**Tests**: Requested by the spec (SC-003 requires each defect kind to be injected and caught), so the gate's injection tests are tasks.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependencies)
- **[Story]**: US1 evaluate the boundary, US2 catalog, US3 gate, US4 security policy
- `[SR-###]` tags sit on the first line of each security task

---

## Phase 1: Setup

- [X] T001 Create `src/threat_model.rs` containing only `#![doc = include_str!("../THREAT_MODEL.md")]`, add `pub mod threat_model;` to `src/lib.rs`, and add `"/THREAT_MODEL.md"` to the `include` list in `Cargo.toml` [SR-006]
- [X] T002 [P] Create a `THREAT_MODEL.md` skeleton at the repository root with the ten `## ` headings in the order from research R7 (Release status … Escape classes) and an empty catalog table header from `contracts/catalog-format.md`. It must build with `cargo doc` [SR-007]

**Checkpoint**: `cargo doc -p procage --no-deps` renders an (empty) `threat_model` page.

---

## Phase 2: Foundational (gate skeleton)

- [X] T003 Create `tests/threat_model.rs` (std only) with the types from data-model.md: `Platforms`, `Disposition`, `Status`, `EvidenceRef`, `EscapeClass`, `Rule`, `Violation`, plus `Display` printing `threat-model gate: <rule>: <subject>: <detail>`. Add file loading relative to `env!("CARGO_MANIFEST_DIR")` and a `#[test] fn gate()` that prints every violation and fails if there is any [SR-004]
- [X] T004 Implement `parse_catalog(doc) -> (Vec<EscapeClass>, Vec<Violation>)` in `tests/threat_model.rs`. It finds `## Escape classes` and the first table, requires the exact header, and needs exactly 8 cells per row. It parses the enums, `—` as an empty list and `, ` lists. Every malformed row is a `row-format` or `value` violation, never skipped [SR-004]

**Checkpoint**: the gate runs, and fails on the skeleton because the baseline ids are missing.

---

## Phase 3: User Story 1: evaluate the security boundary (Priority: P1) 🎯 MVP

**Goal**: an outsider finds adversary, assets, trust, scope, strength, dependencies, non-goals and the release status in one document, reachable from the README and the crate docs.

**Independent Test**: read the README and `cargo doc` output. Every FR-002 topic is present, and the release status says this release enforces nothing.

- [X] T005 [US1] Write the prose sections of `THREAT_MODEL.md`. Base them on the design threat model, with no planning paths and no internal content: [SR-008]
  - Release status: `procage 0.0.1`, no sandboxing API, nothing enforced; the statuses below describe the design.
  - Adversary.
  - Assets.
  - Trusted.
  - In scope.
  - Out of scope, including trust handoff beyond the shipped presets.
  - Strength: an OS sandbox versus a microVM, and when to choose a microVM.
  - Dependencies on undocumented interfaces: libsandbox symbols resolved at run time → unsupported error; Linux tiers probed, a lower tier is an error, never best-effort; refusing to nest in another Seatbelt sandbox; bounded profile size. All stated as commitments of upcoming releases.
  - Non-goals.
- [X] T006 [US1] Rewrite the crate docs in `src/lib.rs`: what procage is *for* (planned), an explicit status (0.0.x, no API, enforces nothing) and an intra-doc link to [`threat_model`]. Remove the present-tense "it applies Seatbelt profiles" [SR-001]
- [X] T007 [P] [US1] Rewrite the `README.md` intro in the same honest tense. Add a `## Threat model` section summarising adversary, scope and strength in five lines or fewer, with a link to `THREAT_MODEL.md` [SR-001]
- [X] T008 [P] [US1] Update the package `description` in `Cargo.toml` to name macOS and Linux and the under-development status without claiming enforcement. Add the category `os::linux-apis`
- [X] T009 [US1] Implement the `heading` (required headings in order), `release-status` (`procage {CARGO_PKG_VERSION}` inside Release status) and `link` (README → `THREAT_MODEL.md`; `src/lib.rs` has `pub mod threat_model;` and a doc link to `threat_model`) checks in `tests/threat_model.rs` [SR-007]

**Checkpoint**: US1 passes its independent test; the heading, release and link checks pass.

---

## Phase 4: User Story 2: the escape-class catalog (Priority: P1)

**Goal**: 20 fully filled rows with honest statuses, kernel observations and the harness responsibilities.

**Independent Test**: the catalog lists exactly the baseline ids. Every status is `planned` or `documented`, and every observed-on id exists.

- [X] T010 [US2] Fill the catalog table in `THREAT_MODEL.md` with the 20 rows R-02…R-12, R-21…R-26 and R-28…R-30. Each row has a class-level one-line description (no exploit steps or payloads), platforms, a disposition per research R3, status `planned` (mitigate/detect) or `documented` (harness), evidence `—`, and observed-on per research R6. Above the table, state the recording releases and date, and explain the numbering gaps [SR-010]
- [X] T011 [US2] Write `### Harness responsibilities` in `THREAT_MODEL.md`: one `- **R-NN**` entry per harness row (at least R-07), saying what procage will provide and what the caller must do
- [X] T012 [US2] Add `const PUBLISHED` (the 20 ids, append-only, with a comment saying so) and the checks `baseline-missing`, `baseline-unknown`, `duplicate-id`, `disposition-status` and `harness-note` in `tests/threat_model.rs` [SR-003]
- [X] T013 [US2] Implement the `kernel-fact` check in `tests/threat_model.rs`. It collects the `id: "KF-…"` literals from `tests/kernel_facts/tests/kernel_facts.rs` and resolves each observed-on id against them [SR-005]

**Checkpoint**: the gate passes on the real document.

---

## Phase 5: User Story 3: the gate keeps the catalog honest (Priority: P1)

**Goal**: every defect kind is caught with a message naming the id and the rule; the clean tree passes.

**Independent Test**: `cargo test -p procage --test threat_model` runs the injection tests; all pass.

- [X] T014 [US3] Implement `evidence-required` (status mitigated/detected with an empty evidence list), `evidence-location` (the ref must start with `tests/`, must not be under `tests/kernel_facts/`, must end with `.rs` and have the form `path::fn`) and `evidence-missing` (the file exists and contains `fn <name>`) in `tests/threat_model.rs` [SR-001] [SR-002]
- [X] T015 [US3] Add injection unit tests in `tests/threat_model.rs`. Each test applies one mutation to the real `THREAT_MODEL.md` text (or to README/lib.rs) and asserts that exactly the expected rule fires, naming the expected subject [SR-001] [SR-002] [SR-003] [SR-004] [SR-005] [SR-007]
  - delete the R-22 row → baseline-missing R-22;
  - duplicate the R-10 row → duplicate-id R-10;
  - add an R-99 row → baseline-unknown R-99;
  - a row with 7 cells → row-format;
  - status `done` → value;
  - `harness` + `planned` → disposition-status;
  - R-10 `mitigated` with `—` → evidence-required;
  - R-10 `mitigated` with evidence `src/lib.rs::x` → evidence-location;
  - R-10 `mitigated` with evidence `tests/kernel_facts/tests/kernel_facts.rs::main` → evidence-location;
  - R-10 `mitigated` with evidence `tests/threat_model.rs::no_such_fn` → evidence-missing;
  - observed-on `KF-M99` → kernel-fact;
  - remove `## Out of scope` → heading;
  - Release status naming `procage 0.0.0` → release-status;
  - remove the R-07 harness entry → harness-note;
  - README without the link → link.
- [X] T016 [US3] Add a positive test in `tests/threat_model.rs`: R-10 `mitigated` with evidence naming an existing test function in `tests/threat_model.rs` passes every rule. This shows that the evidence rule accepts valid evidence [SR-001]

**Checkpoint**: 15 injections caught, 1 positive case accepted, real tree clean.

---

## Phase 6: User Story 4: report a vulnerability privately (Priority: P3)

- [X] T017 [US4] Create `SECURITY.md`. It names GitHub private vulnerability reporting (`https://github.com/hupe1980/procage/security/advisories/new`) and asks reporters not to open public issues for escapes. It refers to `THREAT_MODEL.md` for scope, and states supported versions: 0.0.x has no sandboxing API, and security fixes start with the first release that enforces [SR-009]

---

## Phase 7: Polish and cross-cutting

- [X] T018 Add `THREAT_MODEL.md` and `SECURITY.md` to the `paths` array of the `planning-paths` recipe in `justfile`. Verify that an injected `specs/` reference in `SECURITY.md` fails the recipe [SR-008]
- [X] T019 Add a `package-docs` recipe to `justfile` and to `ci`. It checks that `cargo package --list -p procage --allow-dirty` lists `THREAT_MODEL.md`, packages with `--no-verify`, unpacks into `mktemp -d` outside the workspace, and runs `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` there [SR-006]
- [X] T020 Review pass over `README.md`, `src/lib.rs`, `THREAT_MODEL.md` and `SECURITY.md`. Confirm: no present-tense enforcement claim (SR-001 scenario 3); no open user action, token reference or unpublished decision (SR-008); no exploit steps in any row (SR-010). Record the result in `quickstart.md` [SR-001] [SR-008] [SR-010]
- [X] T021 Run `just ci`; record the outcomes of quickstart scenarios 1–8 in `specs/002-threat-model/quickstart.md`
- [X] T022 Record the decision: published escape-class ids are `R-NN`; `THREAT_MODEL.md` is the public source of the escape classes; status values and the evidence rule.

---

## Dependencies & Execution Order

- Setup (T001–T002) → Foundational (T003–T004) → US1 (T005–T009) and US2 (T010–T013). US2 needs T004's parser. US3 (T014–T016) needs US2's rows to mutate. US4 (T017) is independent and can follow Setup.
- Polish: T018 after T017; T019 after T001; T020 to T022 last.

## Parallel Opportunities

- T002 ∥ T001; T007 ∥ T008 ∥ T006 (different files); T017 at any time after Setup.

## Implementation Strategy

MVP is US1: an honest README, crate docs and a threat model with the required sections. US2 and US3 make it a checkable contract. US4 and the polish tasks complete the feature. Everything lands as one change; nothing is committed without authorization.

---

## Phase 8: Convergence

- [X] T023 Add an injection test in `tests/threat_model.rs` that removes the doc link to `threat_model` from `src/lib.rs` and asserts that only a `link` violation naming `src/lib.rs` fires, per FR-010 (partial)
