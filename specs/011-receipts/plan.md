# Implementation Plan: Receipts — evidence of how a run was caged

**Branch**: `011-receipts` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **procage, shared** (`src/receipt.rs`, new; re-exported as
  `procage::{Receipt, …}`):
  - `Receipt` (`#[non_exhaustive]`, serde with `deny_unknown_fields`,
    `"version": 1`, any other refused): `procage` (crate version),
    `policy_digest` (`sha256:<hex>`), `policy` (only with
    `CageOptions::with_policy_in_receipt`), `preset`, `base`, `grants`
    (names), `backend` (`MacOs { apply, os_release, os_build }` |
    `Linux { tier, landlock_abi, errata, kernel }`), `approximations`
    (`{construct, note}`), `relaxations` (`{construct, relaxation, lift,
    subject}`; `subject` only with the policy), `waivers`,
    `enforced_as_written`, `violations` (`{coverage, complete, count,
    dropped}`; `count` absent unless observed), `exit` (`{code, signal,
    ended_by_caller}`).
  - `policy_digest(&Policy)`: SHA-256 of the policy's canonical JSON
    (its serde form; field order fixed, sets sorted) — `sha2` and `serde`
    become dependencies, `procage-policy` with its `serde` feature.
  - `CageFacts` (crate-private): everything known when the cage is made,
    built once per cage, shared by its children (`Arc`).
- **Backends**: each `Cage` builds its `CageFacts` in `with_options`
  (`fit` adds the relaxations); each `Child` keeps an `Arc` to them and a
  `killed` flag set by `kill_all`; `Child::receipt(&mut self) ->
  Option<Receipt>` returns `None` while the run is alive and the receipt
  once it has exited (exit from the cached status, violation summary from
  `violations()`). macOS: `kern.osproductversion` and `kern.osversion` read
  in `macos::sys`; Linux: `/proc/sys/kernel/osrelease`, tier, ABI, errata
  from the plan and the probe.
- **Tests**: `tests/receipts.rs` (new, both systems): fields per backend and
  tier, round trip, refusal of a newer version and of an unknown field, equal
  digests for equal policies and different for any change, no environment
  value / argument / path in the text unless the policy is requested
  (canary strings), `enforced_as_written` false for an approximation, a
  relaxation and a waiver, `ended_by_caller` after `kill_all`, `None` while
  running, coverage `Off` without reporting.
- **Docs**: crate docs section "Receipts" (what it proves, what not; unsigned;
  macOS coverage best effort; `Cage::exec` gives none); site page; README
  feature line; CHANGELOG Added; fix the two "for receipts" doc lines that
  now hold.

## Technical Context

Rust 1.99.1; new dependencies `serde` 1 (derive) and `sha2` 0.11 (RustCrypto,
MIT OR Apache-2.0) in procage; `serde_json` on both systems. Lanes: macOS
26.6.2, Docker Linux 7.0.14 T1/T2.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | A reader refuses newer versions and unknown fields; "not observed" never reads as "none"; `enforced_as_written` false whenever anything was relaxed | PASS |
| II. Types | Typed backend, exit and coverage; digest over the typed serde form, not text | PASS |
| III. Kernel oracle | Receipt fields come from the plan, the probe and the reaped status of caged children on each lane | PASS |
| IV. fork/exec | Nothing added between fork and exec; all built in the parent | PASS |
| V. Hygiene | No environment values, arguments or (by default) paths in a receipt | PASS |
| VI. Private interfaces | None new (`kern.osproductversion` is public sysctl) | PASS |
| VII. Library | No global state; the policy is included only on request; the receipt is the caller's record, documented as not an attestation | PASS |

## Project Structure

```text
crates/procage/Cargo.toml (serde, serde_json, sha2; procage-policy/serde)
crates/procage/src/{lib.rs, receipt.rs (new)}
crates/procage/src/macos/{mod.rs, child.rs, sys.rs}
crates/procage/src/linux/{mod.rs, child.rs}
crates/procage/tests/receipts.rs (new)
crates/procage/tests/native.rs (shape)
deny.toml (if a licence needs listing), CHANGELOG.md, README.md, site/content/docs/receipts.md (new)
```

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| `sha2` dependency | A collision-resistant digest of a security policy | A non-cryptographic hash: two different policies could be made to look equal |
| `serde` always on | The digest is over the policy's documented form | A second, private encoding: two canonical forms to keep equal |
