# Implementation Plan: Fitting a policy to the host

**Branch**: `032-fit` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- `crates/procage-policy/src/lower/fit.rs` (re-exported at the crate root):
  `Relaxation` (non-exhaustive enum), `Relax` (builder: `leave_out_protect`,
  `leave_out_hide`, `waive`, `no_unix_sockets`, `signals_same_user`,
  `no_loopback`), `Relax::apply(&mut Policy, &[CapabilityGap])`
  (all-or-nothing), `Lift { tier1, landlock_abi }`, `lift(policy, gap,
  options, max_abi)` by re-lowering, `Relaxed { gap, relaxation, lift }`
  with `Display`. Lives in `lower/` to reuse `subject_of`.
- `Cage::fit(policy, options, relax) -> Result<(Cage, Vec<Relaxed>),
  SpawnError>` in `src/linux/mod.rs` and `src/macos/mod.rs`: at most four
  rounds of `with_options` → `apply`; lifts against the original policy
  with `BACKEND_MAX_ABI` (Linux) / none (macOS).
- Docs: a "Fitting a policy to the host" section in `src/lib.rs`;
  THREAT_MODEL sentence.

## Technical Context

Rust 1.99, `no_std + alloc` policy crate. Tests: policy-crate unit and
integration tests (`tests/fit.rs`), `tests/spawn_linux.rs` (T1/T2 with the
cap), `tests/spawn_macos.rs`, `just ci`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Only named relaxations of unsupported gaps; otherwise every gap returned and nothing applied; approximations never relaxed | PASS |
| II. Types | `Relaxation`, `Relax`, `Lift`, `Relaxed` | PASS |
| III. Kernel oracle | Fitted cages spawned on T1/T2 and macOS; lifts from the lowering, which the lowering-table tests pin | PASS |
| IV–VII | No child-side change, no global state | PASS |

## Project Structure

```text
crates/procage-policy/src/lower/fit.rs, lower/mod.rs, lib.rs
crates/procage-policy/tests/fit.rs
src/linux/mod.rs, src/macos/mod.rs, src/lib.rs
tests/spawn_linux.rs, tests/spawn_macos.rs
THREAT_MODEL.md
```

## Complexity Tracking

None.
