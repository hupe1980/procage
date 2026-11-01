# Quickstart: validate 002-threat-model

Prerequisites: the toolchain from 001 (`just`, cargo-deny, cargo-semver-checks,
the 1.99.0 toolchain, the thumbv7em target).

## Scenarios

1. **Gate on the clean tree**: run `cargo test -p procage --test threat_model`.
   Expected: pass, 20 classes parsed, 0 violations.
2. **Injected defects, automated**: the same command runs the injection unit
   tests. Expected: one mutation per rule, each caught by exactly its rule
   (SC-003).
3. **Injected defects, by hand** (each followed by `git diff`-free restore):
   - delete the R-22 row → `baseline-missing: R-22`;
   - set R-10 to `mitigated` with `—` → `evidence-required: R-10`;
   - set R-10's evidence to `src/lib.rs::x` → `evidence-location`;
   - cite `KF-M99` → `kernel-fact`;
   - remove `## Out of scope` → `heading`.
4. **Package and docs**: run `just package-docs`. Expected: `THREAT_MODEL.md`
   is in the file list, and the docs build from the unpacked package with
   warnings denied.
5. **Rendered page**: run `cargo doc -p procage --no-deps --open`. Expected:
   the crate root links to `threat_model`, and the page shows the sections and
   the catalog table.
6. **Planning paths**: append `see specs/x` to `SECURITY.md`, run `just
   planning-paths` (expected: fail), then revert.
7. **Full gates**: `just ci` passes.
8. **Review** (SR-001 scenario 3, SR-008, SR-010): the README and crate docs
   contain no present-tense enforcement sentence. The document contains no
   open user action or unpublished decision. No row contains exploit steps.

## Recorded outcomes (2026-10-29 UTC, macOS 26.6.2 25G83 arm64)

1. Gate on the clean tree: pass, 20 rows, 0 violations.
2. Injection unit tests: 16 of 16 defect kinds caught by exactly their rule (16th, the crate-docs link, added by convergence T023),
   and the positive evidence case is accepted (18 tests pass).
3. Real-file injections, each restored byte for byte afterwards:
   - deleting the R-22 row with `sed` left a blank line inside the table, so
     the gate reported the stranded rows as `row-format` and R-22…R-30 as
     `baseline-missing`. That is strict, not skipped (SR-004);
   - R-10 `mitigated` with `—` → `evidence-required: R-10`;
   - KF-M19 → KF-M99 → `kernel-fact: R-21 KF-M99`;
   - `## Out of scope` removed → `heading: Out of scope`.
4. `just package-docs`: pass. Removing `/THREAT_MODEL.md` from `include` fails
   with "THREAT_MODEL.md is not in the package".
5. The rendered page (`target/doc/procage/threat_model/index.html`) exists in
   the package build. The crate root links to it.
6. `see specs/x` appended to SECURITY.md → `planning-paths` fails; reverted.
7. `just ci`: all 10 gates pass (macOS facts 28/28 in 140.9 s; semver: the new
   docs module is additive).
8. Review: the README and crate docs use "is designed to" / "is meant to" and
   state that 0.0.1 enforces nothing. The dependencies section, the
   disposition definitions and the out-of-scope DoS line were changed from the
   present to the future tense during review. A performance sentence ("starts
   in well under a few milliseconds", not measured for procage) was replaced
   by a qualitative comparison with VMs. No planning paths, open user actions,
   tokens or internal names. No exploit steps in rows (R-11 and R-22 name the
   class without syntax or ioctl).
