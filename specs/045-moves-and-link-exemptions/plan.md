# Implementation Plan: Moves between writable directories, and link-check exemptions

**Branch**: `045-moves-and-link-exemptions` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

`Write` gains Landlock's `REFER` right; Landlock's own refusal of a move
that gains rights, T1's mounts and T2's gaps keep protected and hidden
targets out of reach. The link check gains named exemptions for protected
files in stores that are never rewritten in place. The `setsid` message is
documented.

## Technical Context

- **Language**: Rust 2024, MSRV 1.99; no new dependency.
- **Testing**: unit tests for `rights` and the audit walk; the Linux escape
  suite on T1 and T2 (containers) and in the kernel lane (ABI 1 to 11); an
  integration test of the exemption on macOS and Linux T1.

## Design

1. **Rights** (`procage-policy/src/linux.rs`). `rights(Write, handled)`
   includes `REFER`, intersected with `handled` (absent at ABI 1). Literal
   file rules intersect with `FILE_RIGHTS`, which excludes it. The
   `hd-rename-anchors` class stays exact on Linux with the new argument.
2. **Exemptions** (`procage/src/audit.rs`). `Targets::exempting(paths)`;
   `links` skips an exempt literal target or tree root and does not descend
   into an exempt directory, for protected (not hidden) targets, classes and
   globs. `exemptions(paths, resolve)` resolves each where it exists (macOS:
   the policy's resolution; Linux: `canonicalize`) and refuses a relative
   one. `Audit::links_exempt` (the struct is `non_exhaustive`). The receipt
   is unchanged (`ReceiptAudit` is exhaustive and `deny_unknown_fields`).
3. **Options** (`procage/src/{linux,macos}/mod.rs`). `CageOptions.link_exempt`
   and `with_link_exemption(path)`; `cage_audit` returns a `Result`.
4. **Canaries** (`tests/escape_linux.rs`). New
   `r04_files_move_between_writable_directories_and_gain_no_right`; r04 and
   r30 gain cross-directory variants; r08's run-time check is unchanged.
5. **Docs**: lowering table rows `fs-write-subpath` and `hd-rename-anchors`,
   Linux limits (ABI 1) and options, audits, lifetime (`gc.autoDetach`),
   `Lifetime::Run` rustdoc, crate docs, threat model R-04 and R-08 rows,
   changelog.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No approximation added: Landlock enforces moves exactly; T2 gaps unchanged | PASS |
| II | Relative exemption is a typed error (`Unsupported::Setting`) | PASS |
| III | Canaries for each move and each class it touches, on every tier and ABI lane | PASS |
| VII | No new dependency; no public type loses a trait | PASS |
