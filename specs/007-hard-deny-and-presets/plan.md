# Implementation Plan: Data-driven hard denies and frozen presets

**Branch**: committed on `main` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

## Summary

This feature has two parts:

- **Hard-deny classes**: three new classes (secrets, trust handoff,
  persistence) with frozen, case-folded pattern lists, emitted in the
  hard-deny block on macOS and pending on Linux (008).
- **Presets**: four frozen presets V1, carrying their name and version in the
  policy.

Evidence:
- caged tests for reading secrets, git hooks, rc files, editor config,
  `mv .git`, launch agents, the waivers and each preset;
- pinned fixtures in the policy crate.

## Technical Context

**Language**: Rust 2024. **Dependencies**: none new. `procage-policy` stays `no_std`.

## Constitution Check

| Principle | Compliance | Gap |
|---|---|---|
| I. Fail closed | The classes are last and waivable only by name; the Linux status is stated explicitly | Linux enforcement is in 008 |
| II. Types | Patterns are typed globs; one escaper; folding is a pure transform | — |
| III. Kernel is the oracle | Every claim has a caged test on 26.6.2 | macOS 27 pending (user update) |
| VII. Library | Presets are versioned and frozen; waivers overridable by name | — |

**Gate**: PASS.

## Project Structure

```text
crates/procage-policy/src/{presets.rs (NEW), policy.rs, glob.rs, format.rs, lower/{mod,macos}.rs, lowering.md, lib.rs}
crates/procage-policy/tests/{presets.rs (NEW), fixtures/presets/*.sb (NEW), common/mod.rs}
tests/spawn_macos.rs
THREAT_MODEL.md, README.md, src/macos/mod.rs
```
