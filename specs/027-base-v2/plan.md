# Implementation Plan: Base profile V2

**Branch**: `027-base-v2` (local; commits on `main`) | **Date**: 2026-10-31 | **Spec**: [spec.md](spec.md)

## Summary

`Base::V2` (policy, construct `base-v2`, lowering on both systems);
`procage_policy::base::macos_v2` = V1 + measured additions (R3), no new
service (R2); `linux_v2` = V1 (R5). Presets get `v2` functions on base V2
(`build::v2` adds `ipc.unix_sockets`). Tests: V2 pinned, no unfiltered base
rule, preset v2 fixtures, a caged program-set test (installed tools only)
and a refusal test (US2), including the private per-user temp dir. Docs:
base module (V2 table, omissions, "Running developer tools"), lowering
table, crate docs and example on V2.

## Technical Context

Rust 1.99; no dependencies; macOS 26.6.2 for caged tests, Docker for Linux
(content identical to V1); `just ci`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Additions are code, system data and two named personal entries; dirhelper refused on evidence | PASS |
| II. Types | `Base::V2`, construct `base-v2` | PASS |
| III. Kernel oracle | Every addition comes from a denial; caged tests on the kernel | PASS |
| IV–VII | No child-side change, no global state; presets versioned, v1 frozen | PASS |

## Complexity Tracking

None.
