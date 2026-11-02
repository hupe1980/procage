# Implementation Plan: Published spawn benchmarks

**Branch**: `043-benchmarks` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Summary

- `crates/procage/benches/spawn.rs` (`harness = false`): for each case, a
  warm-up then N iterations (default 300; `--quick` 30) of spawning
  `/usr/bin/true` (macOS) or `/bin/true` (Linux) and waiting; prints a table
  with median, p90, p99 and the overhead of the median over plain spawn.
- Cases: plain `std::process::Command`; procage cached (one cage, many
  spawns, `presets::minimal::v3()`); procage first spawn (a new cage per
  iteration, so a compile on macOS); with violation reporting; the tools
  others shell out to — `sandbox-exec -p` with the cage's profile (macOS) and
  `bwrap` with read-only binds of `/usr` (Linux, when installed); Linux runs
  the probed tier and, on T1 hosts, T2 too.
- Header: machine (`hw.model` / `/proc/cpuinfo` model), OS release and build
  or kernel, tier, toolchain, date. Refuses to run inside another sandbox
  (macOS `is_sandboxed`).
- CI: the `gates` job runs `cargo bench --no-run`; the macOS and Linux lanes
  run `cargo bench -p procage --bench spawn -- --quick` (no gating).
- Docs: README "Performance" with the reference numbers; site page;
  the vision's B7 targets replaced by the measurements.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I–VI | No change to the backends | PASS |
| VII | No new dependency; the bench is not part of the package | PASS |
| III | Numbers carry machine, OS build and date | PASS |
