# Implementation Plan: Base V3 and quiet records

**Branch**: `036-base-v3` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **Policy crate**: `Base::V3`; `sbpl::Rule::quiet` rendered as
  `(with no-report)` (never combined with a reason message); `base::macos_v3_quiet(tty)`
  (logd, diagnosticd, dirhelper, membership lookups; dtracehelper ioctl;
  `/dev/tty` read/write; a granted `/dev/tty` wins by order, not by leaving
  the rule out); the macOS lowering emits a
  quiet block first (before allow), then V2's allows; Linux lowers V3 as V2;
  presets `v3` for all four; fixtures `*-v3.sb`.
- **procage**: `Violation::repeats`; `Record::push` merges equal entries
  (both backends); `Display` appends `(×N)`.
- **Tests**: policy (strip = V2 for every reference policy, quiet list vs
  hard-deny/data-class targets, v3 fixtures, V1/V2 unchanged); macOS caged
  (quiet probes absent, targets still refused, `Tty::Inherit` /dev/tty,
  LaunchServices merged with a count, the command set succeeds and shrinks
  ≥ 95 %); Linux merge (both tiers); KF-M30; escape suite with presets v3.
- **Docs**: base table (V3), site presets/macOS/violations pages, README.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | V3 adds only denies; strip-equals-V2 test; V1/V2 frozen | PASS |
| II. Types | `Base::V3`, `Rule::quiet`, `Violation::repeats` | PASS |
| III. Kernel oracle | KF-M30; caged tests for every story | PASS |
| IV–VI | No child-side change; no new private interface (SBPL modifier only, pinned by KF-M30) | PASS |
| VII. Presets frozen | V3 and presets v3 are new versions; nothing loosened | PASS |

## Project Structure

```text
crates/procage-policy/src/{policy.rs, base.rs, sbpl.rs, lower/macos.rs, lower/linux.rs, presets.rs, lowering.md}
crates/procage-policy/tests/{base.rs, presets.rs, fixtures/presets/*-v3.sb}
crates/procage/src/violation.rs
crates/procage/tests/{spawn_macos.rs, spawn_linux.rs, escape_macos.rs}
crates/procage-kernel-facts (KF-M30)
README.md, site/content/docs/{presets,macos,violations}.md, crates/procage/src/lib.rs
```

## Complexity Tracking

None.
