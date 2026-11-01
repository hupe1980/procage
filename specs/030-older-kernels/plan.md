# Implementation Plan: Older Linux kernels

**Branch**: `030-older-kernels` (local planning; commits on `main`) |
**Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

Four changes, one per user story (R1–R5 in [research.md](research.md)):

1. **Truncation guard** (US1): the Linux lowering adds three seccomp denies
   when the ABI is below 3, on both tiers: `truncate` (`EPERM`), `open` and
   `openat` when `O_TRUNC` is set and the access mode is neither `O_WRONLY`
   nor `O_RDWR` (`EPERM`, new `Condition::TruncWithoutWrite { flags_arg }`),
   `openat2` (`ENOSYS`). The seccomp compiler gains `BPF_ALU|BPF_AND|BPF_K`
   and the numbers of `truncate`, `open` (x86_64 only), `openat`, `openat2`.
2. **T2 from ABI 1** (US2): `Tier::T2.min_landlock_abi()` becomes 1; the
   probe and the docs follow.
3. **`Signals::SameUser`** (US3): new policy value and construct
   `signals-same-user`, exact everywhere. Linux: no signal scope and no
   signal denies. macOS: `(allow signal)` with no target filter; the
   `hd-process-access` deny of `signal (target others)` still follows (hard
   deny wins).
4. **ABI cap** (US4): `CageOptions::landlock_abi: Option<u8>` with
   `with_landlock_abi(abi)`; `Cage::with_options` uses
   `min(kernel, cap, BACKEND_MAX_ABI)` for the tier check, lowering and
   enforcement; `Cage::landlock_abi()` reports it.

Docs: a "Kernels" section in the Linux module docs (per-ABI table, the
guard, `SameUser`, the cap), the lowering table (`signals-same-user`, T2's
minimum, the guard), THREAT_MODEL (R-31, the tier text), the README's Linux
line. Kernel fact KF-L14 records the truncation behaviour; the escape suite
adds `r31_*` canaries.

## Technical Context

**Language/Version**: Rust 1.99, edition 2024. **Dependencies**: none new.
**Testing**: `tests/spawn_linux.rs` and `tests/escape_linux.rs` on Docker
T1 and T2 with capped ABIs; policy-crate fixtures; seccomp unit tests (BPF
interpreter); KF-L14 in the kernel-facts suite; `just ci` on macOS (macOS
lowering and a caged `SameUser` test). **Constraints**: child code unchanged
(syscalls only, the plan is built in the parent); `unsafe` only in `sys`.
**Scope**: ~150 lines code, ~300 lines tests, docs.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | The guard refuses more, never less; `SelfAndChildren` stays a gap below ABI 6; the cap can only lower the ABI and the plan is lowered for it | PASS |
| II. Types | `Signals::SameUser`, `Construct::SignalsSameUser`, `Condition::TruncWithoutWrite`, `CageOptions::landlock_abi: Option<u8>` | PASS |
| III. Kernel oracle | Caged tests per capped ABI on T1 and T2 with a negative control; KF-L14 observes the kernel behaviour; the cap is a faithful stand-in (Landlock enforces only handled rights), stated as an assumption | PASS |
| IV. Syscalls only | Nothing new in the child; the filter is built in the parent | PASS |
| V. Hygiene | Unchanged | PASS |
| VI. Private interfaces | None | PASS |
| VII. Library | No global state; the cap is per cage | PASS |

## Project Structure

```text
crates/procage-policy/src/policy.rs        # Signals::SameUser
crates/procage-policy/src/lower/mod.rs     # Construct::SignalsSameUser, Tier::T2 minimum
crates/procage-policy/src/lower/linux.rs   # guard below ABI 3, SameUser
crates/procage-policy/src/lower/macos.rs   # SameUser
crates/procage-policy/src/linux.rs         # syscalls, Condition::TruncWithoutWrite, O_* constants
crates/procage-policy/src/lowering.md      # rows, T2 minimum, guard
crates/procage-policy/tests/*              # fixtures (lowering table, gaps, format)
src/linux/seccomp.rs                       # AND, numbers, condition
src/linux/mod.rs                           # cap, landlock_abi(), Kernels docs
src/linux/probe.rs                         # (minimums via Tier)
tests/spawn_linux.rs, tests/escape_linux.rs, tests/spawn_macos.rs
tests/kernel_facts/tests/kernel_facts.rs   # KF-L14
tests/threat_model.rs, THREAT_MODEL.md     # R-31
README.md
```

## Complexity Tracking

None.
