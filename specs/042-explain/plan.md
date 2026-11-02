# Implementation Plan: Explain and diff, checked against the kernel

**Branch**: `042-explain` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

- `procage_policy::explain`: an `Explainer` built from a policy, a target
  and the lowering options answers `(operation, canonical path)` questions
  for file read, file write and exec, with the deciding rule, any
  spawn-time caveat and a verified remedy. Other operations answer
  `NotModelled`.
- `procage_policy::explain::diff`: the entries one policy's plan has and the
  other's lacks, per target, each with the operations, the path set, the
  deciding rule kind and a direction; every other differing plan field is
  listed as a changed setting.
- macOS: the evaluator walks the emitted SBPL rules in profile order (last
  match wins), kept with their origin before reasons are stripped and rules
  merged. Path filters (`literal`, `subpath`, `regex`, `path-ancestors`),
  grant extensions and `file-mode` are evaluated; a rule with any other
  filter on a modelled operation makes the answer `NotModelled`.
- Linux: the plan's Landlock rules (path-beneath union; a right the ruleset
  does not handle is allowed), T1 mounts, the data-driven classes with the
  context's homes, and the T2 piecewise hides. Spawn-time covers carry a
  caveat.
- `procage::{macos,linux}::Cage::explain` resolves the path and grants, adds
  the homes (Linux) and asks the cage's explainer.
- `crates/procage/tests/oracle.rs`: per lane, every preset (v1–v3) and a
  rule-kinds policy; more than 1,000 generated read/write questions answered
  by one caged child, and exec questions answered by caged spawns; any
  disagreement or unresolved question fails, naming it.
- Docs: `explain.md` on the site (the proven operations per target, what an
  answer holds, relay guidance), crate docs, README feature line,
  CHANGELOG.

## Technical Context

**Language/Version**: Rust 1.99 (MSRV), edition 2024

**Primary Dependencies**: none new (the SBPL regex subset is matched by a
small Thompson NFA in the policy crate)

**Storage**: N/A

**Testing**: unit tests in `procage-policy` (regex, canonical form, rule
kinds, remedy, diff soundness over generated pairs); `oracle.rs` on the
macOS lanes and both Linux lanes

**Target Platform**: macOS (Seatbelt), Linux T1 and T2

**Project Type**: library

**Performance Goals**: under 1 ms per question in release on the reference
machine (Apple M4 Pro); diff is O(n log n) in the plan's rules

**Constraints**: the evaluator is `no_std` + `alloc`, no `unsafe`, no system
calls (FR-003); no new dependency

**Scale/Scope**: three operations, three targets, 12 frozen presets

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I Fail closed | Unmodelled operations and unevaluable filters answer `NotModelled`; a remedy is offered only after re-lowering confirms it flips the question | PASS |
| II Types over strings | Typed `Op`, `Decider`, `PathSet`, `Change`; question paths are bytes, never patterns | PASS |
| III Kernel is the oracle | The oracle asks caged children on every lane; AlreadySandboxed fails | PASS |
| IV Syscalls between fork and exec | No change to the spawn sequence; the oracle child is a test-binary mode | PASS |
| V Hygiene | No change | PASS |
| VI Docs follow tests | The proven-operations list is compared with the oracle's coverage by a test | PASS |
| VII Dependencies | None added | PASS |

Re-check after design: unchanged, PASS.

## Project Structure

### Documentation (this feature)

```text
specs/042-explain/
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/explain-api.md
└── tasks.md
```

### Source Code

```text
crates/procage-policy/src/
├── explain/mod.rs      # Op, Question, Context, Answer, Explainer
├── explain/macos.rs    # SBPL evaluation
├── explain/linux.rs    # Landlock, mounts, classes
├── explain/diff.rs     # diff and PathSet
├── explain/regex.rs    # the SBPL regex subset
└── lower/macos.rs      # emits tagged rules (shared with explain)
crates/procage/src/{macos,linux}/mod.rs   # Cage::explain
crates/procage/tests/oracle.rs
site/content/docs/explain.md
```

**Structure Decision**: the evaluator lives in the policy crate next to the
lowering it mirrors; only path resolution and grant binding live in
`procage`.

## Complexity Tracking

None.
