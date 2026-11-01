# Implementation Plan: Portable policy IR and its lowering to each backend

**Branch**: `003-policy-ir` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/003-policy-ir/spec.md`

## Summary

Turn the placeholder `procage-policy` crate into the portable policy layer.
It stays `no_std` + `alloc`, with no `unsafe`, and is still unpublished.

- **Value types**: `AbsPath` (exact bytes, lexically checked), `Glob` (an
  explicit pattern compiled to an anchored, escaped SBPL regex), and
  validated identifiers.
- **Intent layer**: `Policy`, as data, with deny as the default effect.
- **Backend layers**: a typed `seatbelt::Layer` with a closed list of 112
  operations, each measured to compile on 26.6.2. A modifier is
  unrepresentable. There is also a `linux::Layer`.
- **One escaper**: `sbpl::quote`, with a parameter fallback above 1016 bytes.
- **`lower(policy, target, options)`**: produces a `SeatbeltPlan` (profile
  text in fixed precedence blocks, parameters, grant classes) or a
  `LinuxPlan` (namespaces, mounts, Landlock rights per ABI, seccomp denies by
  name, network mode). Otherwise it returns the complete list of typed
  `CapabilityGap`s. Approximations need `allow_degrade(construct)` and are
  recorded.
- **Limits guard**: a configurable rule limit, with only the exact
  adjacent-merge rewrite.
- **Hard-deny tier**: nine fixed classes, emitted last, waivable by name.
- **Lowering table**: `src/lowering.md` is both the rustdoc of `lower` and
  the fixture of a test that checks every construct × target × ABI.
- **Data format**: optional, behind `serde`. It is versioned, refuses unknown
  fields and validates every value.
- **Assurance**:
  - generated-input property tests (10,000 cases each);
  - four cargo-fuzz targets;
  - a libsandbox compile test in the kernel-facts crate, which shows only
    well-formedness.

## Technical Context

**Language/Version**: Rust, edition 2024, MSRV 1.99 (stable 1.99.1 installed)

**Primary Dependencies**:
- `serde` 1, optional, `default-features = false`, with `derive` and `alloc`.
- Dev-dependency: `serde_json` 1.
- Fuzz package: `libfuzzer-sys` 0.4, outside the workspace.
- No other dependency.

**Storage**: none (pure functions)

**Testing**:
- `cargo test -p procage-policy --all-features`: unit tests plus integration
  tests in `crates/procage-policy/tests/` for paths, escaping, lowering_table,
  precedence, limits, format and gaps.
- `cargo test -p procage-kernel-facts --test policy_compiles` (macOS).
- `just fuzz-all` (nightly).

**Target Platform**: any; `no_std` build checked for `thumbv7em-none-eabihf`. The compile test needs macOS.

**Project Type**: library crate inside the existing workspace

**Performance Goals**:
- lowering a 2,000-rule policy takes < 50 ms in a debug build;
- the property tests finish in < 30 s in total.

**Constraints**:
- no `unsafe`, no `std`, no planning paths in published files;
- deterministic output;
- no enforcement claims in docs.

**Scale/Scope**: ~9 source modules, ~7 test files, 4 fuzz targets, 1 kernel-facts test file, justfile and CI changes.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | How this plan complies | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | <ul><li>Every construct a target cannot express is a typed `CapabilityGap`, collected completely.</li><li>Approximations need `allow_degrade` by name and are recorded.</li><li>A tier or ABI below the minimum is a `TargetError`, never a substitute.</li><li>Relative paths are errors. Control characters and non-UTF-8 values on macOS are `Unrepresentable` gaps.</li><li>The limits guard only rewrites exactly.</li><li>`(with no-sandbox)` is unrepresentable.</li></ul> | lowering_table, gaps, limits, escaping tests; fuzz | Enforcement of each plan is unverified until 004/008/009 |
| II. Types over strings | <ul><li>Two-layer IR.</li><li>`AbsPath`, `Glob` and validated names are distinct types, and a glob is never inferred.</li><li>One escaper; parameters for long values.</li><li>Byte-exact paths; deny by default.</li><li>The hard-deny tier is emitted last and waivable only by class name.</li></ul> | property tests, fuzz targets, libsandbox compile test | Regex matching semantics (libMatch) are measured as compiling only |
| III. Kernel is the oracle | <ul><li>No enforcement claim is made. Docs say what lowering produces.</li><li>The compile test is labelled a well-formedness check (SR-011).</li><li>Measurements carry their date and OS build (research.md).</li><li>The threat model's statuses are unchanged.</li></ul> | review; THREAT_MODEL gate unchanged | — |
| IV. Syscalls only / unsafe in sys | `procage-policy` has no `unsafe` (`forbid`). The compile test reuses the kernel-facts `sys` binding and adds no unsafe code | lints | — |
| V. Hygiene by default | Env, limits and tty are carried into both plans unchanged, with safe defaults: an empty env allowlist, `core = 0`, `Tty::None` | data-model defaults test | Applied in spec 005 |
| VI. Private interfaces, honestly | The closed operation list is measured on 26.6.2 and re-checked by the compile test on every macOS run. Landlock ABI and tier are inputs, never inferred | policy_compiles | Newer macOS lanes run in CI after a push |
| VII. A library, not a harness | <ul><li>No global state, no runtime.</li><li>`serde` and `unstable-operations` are opt-in features.</li><li>`no_std` + `alloc`, MSRV 1.99, edition 2024.</li><li>The crate stays unpublished, so there is no semver surface yet.</li></ul> | `just no-std` (with and without serde), `just msrv`, `just deny` | — |

**Workflow rules**:

- One spec (003).
- Local planning stays local: planning-paths already scans `crates/`.
- The decisions are recorded: `Exec::{Granted, Any, Never}` replaces
  `Paths[..]`; `Network::None` on Linux denies `socket()` outright; the closed
  operation list of 112 measured names; the hard-deny classes of this feature.
- No commits without authorization.

**Gate result (pre-research)**: PASS. **Post-design re-check**: PASS. The
research made two Linux mappings stricter than the earlier Linux research (fail closed),
and nothing weaker.

## Project Structure

### Documentation (this feature)

```text
specs/003-policy-ir/
├── plan.md
├── research.md          # R1–R12 (measured on 26.6.2, 2026-10-30)
├── data-model.md
├── quickstart.md
├── contracts/
│   ├── public-api.md
│   ├── lowering-table.md
│   └── data-format.md
├── threat-model.yaml    # ThreatSpec (+ threat-model.md, security/)
└── tasks.md
```

### Source Code (repository root)

```text
Cargo.toml                                  # workspace: exclude fuzz package
crates/procage-policy/
├── Cargo.toml                              # features serde, unstable-operations; dev-dep serde_json
├── src/
│   ├── lib.rs                              # crate docs (what it produces, no enforcement claim), re-exports
│   ├── path.rs                             # AbsPath, PathError
│   ├── glob.rs                             # Glob, GlobError, to_sbpl_regex
│   ├── name.rs                             # GrantName, Tag, Name, OperationName, Port, NameError
│   ├── policy.rs                           # intent layer, HardDenyClass, PolicyError, validate()
│   ├── seatbelt.rs                         # Operation (112 + Other), Filter, Rule, Layer
│   ├── linux.rs                            # Layer, Syscall, LinuxPlan types, Landlock rights per ABI
│   ├── sbpl.rs                             # quote, INLINE_LIMIT, Rule rendering, merge_adjacent, profile writer
│   ├── lower/
│   │   ├── mod.rs                          # lower(), Target, Tier, LowerOptions, Construct, Outcome, gaps, Plan
│   │   ├── macos.rs                        # Seatbelt lowering + hard-deny SBPL
│   │   └── linux.rs                        # Linux lowering + hard-deny seccomp
│   ├── lowering.md                         # the lowering table (rustdoc of `lower` + test fixture)
│   └── format.rs                           # serde representations (feature serde)
├── tests/
│   ├── common/mod.rs                       # xorshift generator, reference policies, SBPL string decoder, reference evaluator
│   ├── paths.rs  escaping.rs  lowering_table.rs  precedence.rs  limits.rs  gaps.rs  format.rs
└── fuzz/                                   # cargo-fuzz package (own workspace): quote, glob, format, lower
tests/kernel_facts/
├── Cargo.toml                              # dev-dependency procage-policy
└── tests/policy_compiles.rs                # macOS: every reference profile + 112 operations compile
justfile                                    # no-std also with serde; fuzz, fuzz-all
.github/workflows/ci.yml                    # nightly fuzz smoke job
```

**Structure Decision**: everything except the compile test goes in
`procage-policy`. The compile test lives in the kernel-facts crate, which
already owns the only libsandbox binding outside the future `macos::sys`.

## Complexity Tracking

| Item | Why needed | Simpler alternative rejected because |
|---|---|---|
| Lowering table parsed from rustdoc | One source for users and tests (SR-006) | A Rust const table would drift from the docs |
| Test-only reference evaluator | Proves the guard never broadens (SR-008) | Comparing SBPL strings proves nothing about meaning |
| Separate fuzz workspace | cargo-fuzz needs nightly and libfuzzer-sys | Putting it in the workspace would break `cargo deny`/MSRV/stable gates |
