# Research: 002-threat-model

No NEEDS CLARIFICATION remained in the spec. These are the design decisions.

## R1 Single source and rendering

- **Decision**: `THREAT_MODEL.md` at the repository root is the source.
  `src/threat_model.rs` contains only `#![doc = include_str!("../THREAT_MODEL.md")]`,
  and the package `include` adds `/THREAT_MODEL.md`.
- **Rationale**: GitHub renders the root file and docs.rs renders the module,
  both from the same bytes. `include_str!` fails the build if the package lacks
  the file, so a missing copy cannot ship silently (SR-006).
- **Alternatives**: duplicating the text into rustdoc (it drifts); a docs
  site (out of scope); crate-root docs (too long for the landing page).

## R2 Catalog as a Markdown table

- **Decision**: one table under `## Escape classes`, with eight columns in a
  fixed order: `Id | Class | Description | Platforms | Disposition | Status |
  Evidence | Observed on`. Empty fields hold an em dash `—`. Multiple values
  are separated by `, `. Harness-side notes go in a `### Harness
  responsibilities` list keyed by id (`- **R-07** …`).
- **Rationale**: it reads well on GitHub and docs.rs, and a few lines of std
  code parse it without ambiguity: it has no pipes inside cells and no nested
  markup in the enum columns. FR-015.
- **Alternatives**: a TOML/YAML data file plus generated Markdown (two
  sources, needs a generator and a dependency); a Rust `const` table (API
  surface, harder to read for reviewers).

## R3 Values and consistency

- Platforms ∈ {`macOS`, `Linux`, `macOS, Linux`}.
- Disposition ∈ {`mitigate`, `detect`, `harness`}.
- Status ∈ {`planned`, `mitigated`, `detected`, `documented`, `retired`}.
- Allowed pairs: `mitigate` → {planned, mitigated, retired}; `detect` →
  {planned, detected, retired}; `harness` → {documented, retired}.
- **Rationale**: a harness-side class cannot be "mitigated by procage", and a
  mitigate class cannot become `detected` silently. Changing a disposition is
  a visible design change.

## R4 Evidence location rule

- **Decision**: an evidence entry is `<repo-relative path>::<fn name>`. The
  path must start with `tests/`, must not be under `tests/kernel_facts/`, and
  must end in `.rs`. The file must exist and contain `fn <name>`.
- **Rationale**: library unit tests (`src/`) cannot cage a child the way a
  canary does. Kernel facts observe the OS, and do not test procage's
  mitigation (spec assumption). Integration tests are where caged-child
  canaries live (specs 005, 009). Checking for `fn <name>` catches typos and
  renames (SR-001, SR-002). Whether the test really cages a child stays a
  review item. It is recorded as the residual risk of
  threat.evidence-not-a-caged-test.
- **Alternatives**: requiring a marker attribute such as `#[caged]` (no such
  machinery exists before spec 009; revisit there).

## R5 Published-id baseline

- **Decision**: a `const PUBLISHED: &[&str]` in `tests/threat_model.rs` holds
  the 20 ids and is append-only. The gate fails when the catalog is missing a
  baseline id, has a duplicate, or has an id that is not in the baseline. The
  last case forces a new class to be added to the baseline in the same change.
- **Rationale**: no git history is needed, and the review diff of the const
  shows any removal.

## R6 Kernel-fact resolution

- **Decision**: the gate reads `tests/kernel_facts/tests/kernel_facts.rs` and
  collects every `id: "KF-…"` literal. Each observed-on id must be in that set.
  The catalog states the recording release in one sentence above the table
  (macOS 26.6.2 (25G83), Linux 7.0.14-linuxkit, 2026-10-29).
- **Observed-on mapping** (from the kernel-facts catalog):

  | Class | Kernel facts | What they show |
  |---|---|---|
  | R-02 | KF-M07, KF-M08 | a non-canonical literal or subpath rule does not match |
  | R-11 | KF-M12 | `(with no-sandbox)` runs the exec'd child unsandboxed |
  | R-12 | KF-M21 | a `/Users` subpath deny is enforced through the firmlink (the visible spelling works) |
  | R-21 | KF-M19 | an fd inherited from before apply reads a denied file |
  | R-22 | KF-M26 | TIOCSTI injects into the own controlling terminal, sandboxed or not |
  | R-29 | KF-L09, KF-L10 | a nested user namespace cannot undo locked mounts or write its uid_map under Landlock |

## R7 Required headings and release status

- **Decision**: the gate requires these `## ` headings, verbatim and in order:
  1. Release status
  2. Adversary
  3. Assets
  4. Trusted
  5. In scope
  6. Out of scope
  7. Strength
  8. Dependencies on undocumented interfaces
  9. Non-goals
  10. Escape classes

  The Release status section must contain `procage <CARGO_PKG_VERSION>`.
- **Rationale**: SR-007. Putting the release status first means that a reader
  who stops early still learns that nothing is enforced.

## R8 Link checks and honesty review

- **Decision**: the README must contain a link to `THREAT_MODEL.md`. `src/lib.rs`
  must contain an intra-doc link to `threat_model` and the line
  `pub mod threat_model;`. Present-tense enforcement wording is a review item
  (SR-001 scenario 3) and is not pattern-matched, because a phrase list would
  give false confidence.
- **README link on crates.io**: crates.io rewrites relative README links
  against `repository`, so `THREAT_MODEL.md` resolves there as well.

## R9 Package docs check and security policy

- **Package docs**: `just package-docs` runs `cargo package --allow-dirty
  --no-verify -p procage`, unpacks the `.crate` into a fresh `mktemp -d`
  directory outside the workspace, and runs `cargo doc --no-deps` there with
  `RUSTDOCFLAGS=-D warnings`. It also checks that `THREAT_MODEL.md` is listed
  by `cargo package --list`. The directory outside the workspace avoids the
  "package believes it is in a workspace" error.
- **Security policy**: GitHub private vulnerability reporting
  (`https://github.com/hupe1980/procage/security/advisories/new`), no email
  address. The supported-versions table covers 0.0.x: there is no sandboxing
  API, so security fixes are not applicable. Enabling the feature in the
  repository settings is a maintainer action.
