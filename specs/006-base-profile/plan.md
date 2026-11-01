# Implementation Plan: A base profile that lets ordinary programs start

**Branch**: committed on `main` | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

## Summary

This feature adds `Base::V1` to the policy IR, opt-in and frozen, with
content in `procage-policy/src/base.rs`:

- **macOS**: curated SBPL rules (system code and data, devices, sysctl reads,
  five query services, notifyd shared memory), plus terminal devices with
  `Tty::Inherit`.
- **Linux**: Landlock rules for system paths, with optional ones skipped when
  absent.

The base is lowered into the allow block. It gets a lowering-table row and a
data-format field, and tests:

- pinned-content tests in the policy crate;
- caged tests in `procage` (the program set, the refusals, a child with
  `/dev/null` stdio).

The docs list the content, the verified programs and the release.

## Technical Context

**Language**: Rust 2024, MSRV 1.99. **Dependencies**: none new.

**Testing**:
- `crates/procage-policy/tests/base.rs`;
- `tests/spawn_macos.rs` (`base_*`);
- `tests/kernel_facts/tests/policy_compiles.rs`, which picks up the new
  reference policy automatically.

**Constraints**: `procage-policy` stays `no_std`; the base is constant data.

## Constitution Check

| Principle | Compliance | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | The base is opt-in; nothing is allowed without a source | `every_allow_has_a_source` (003) still passes, with the base as a named source | — |
| II. Types | Constant paths go through the escaper; a typed filter for shared memory | compile test | — |
| III. Kernel is the oracle | The program set and the refusals run on the kernel; measured release recorded | `spawn_macos` | macOS 27 is untested |
| IV/VI | n/a | | |
| V. Hygiene | The terminal device is allowed only with `Inherit` | `base.rs` tests | — |
| VII. Library | Versioned and frozen; opt-in | pinned test | — |

**Gate**: PASS.

## Project Structure

```text
crates/procage-policy/src/{base.rs (NEW), policy.rs, sbpl.rs, linux.rs, format.rs, lower/{mod,macos,linux}.rs, lowering.md, lib.rs}
crates/procage-policy/tests/{base.rs (NEW), common/mod.rs}
tests/spawn_macos.rs
src/macos/mod.rs, src/lib.rs, THREAT_MODEL.md, README.md
```
