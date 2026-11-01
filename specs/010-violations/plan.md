# Implementation Plan: Violations — what the sandbox denied, and why

**Branch**: `010-violations` (commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- **Policy crate**: `LowerOptions::with_violations()` replaces the unused
  static `tag`. `sbpl::Rule` gains an optional `DenyReason`; the macOS
  lowering sets it on hard-deny (data-class paths included, as their
  class), protect, hide and raw-layer denies (never
  on the run-marker block); `write_profile` renders the messages only when
  reporting is on. `DenyReason::{code, from_code}` is the single encoding.
- **procage, portable** (`src/violation.rs`): `Violation`, `DeniedBy`,
  `Coverage`, `Violations`, and the pure parser
  `parse(event_message, markers) -> Option<(marker, Violation)>`.
- **macOS** (`src/macos/violations.rs`): the process-wide `Monitor` (helper
  under the `/bin/sh` watchdog, reader thread, sinks by marker, fences,
  ready handshake, restart, integrity check of both binaries); fences are
  denials of a forked child (`sys::install_fence`), and `sys::on_read_only_volume`
  (statfs) backs the integrity check.
  `CageOptions::with_violations` lowers with the option, compiles slot 0
  for every such cage, takes a run slot per spawn (also for non-forking
  policies), binds the marker parameters, registers the sink before the
  fork. `Child::violations` / `violation_receiver`; `kill_all` fences
  before freeing the slot and runs the marker search only for forking
  policies.
- **Linux**: `CageOptions::with_violations` (recorded), `Child::violations`
  returning `NotObserved`/`Off`, `violation_receiver` → `None`.
- **Kernel fact** KF-M29: the message format with a parameter message, and
  denial-before-fence ordering.
- Docs: crate section "Violations", README, THREAT_MODEL (diagnostic,
  best-effort, R-17).

## Technical Context

Rust 1.99. New macOS-only dependency: `serde_json` (default features off,
`std`), already in the lock file. Tests: policy unit tests (rendering,
code round-trip, identical-off on every fixture), `src/violation.rs` unit
tests (parser incl. newline forgery), `tests/spawn_macos.rs` (stories),
`tests/escape_macos.rs` (suite with reporting on), `tests/native.rs`
(shape), kernel facts, `just ci`, `just linux`, `just linux-t1`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Reporting changes only messages; identical profile when off (fixture test); escape suite with reporting on; spawning never depends on the monitor | PASS |
| II. Types | `Violation`, `DeniedBy`, `Coverage`, `Violations`, `DenyReason`; no stringly reasons in the API (unknown codes kept as `Unknown`) | PASS |
| III. Kernel oracle | Caged tests read real denials; KF-M29 pins format and ordering | PASS |
| IV. fork/exec, unsafe | One new child-side sequence, the fence: `__mac_syscall` (apply), `open("/")`, `_exit`, all system calls, bytecode compiled in the parent; covered by `fences_survive_a_multithreaded_parent` (dyld churn on 4 threads) | PASS |
| V. Hygiene | `/bin/sh` and `/usr/bin/log` are integrity-checked before every helper start: owned by root, not writable by group or others, on a read-only volume (the sealed system volume, `statfs` `MNT_RDONLY`), the OS equivalent of a digest that survives OS updates; empty environment, close-on-exec, ends with the process | PASS |
| VI. Private interfaces | The unified-log format is undocumented: KF-M29 on every lane; failure → `Unavailable` | PASS |
| VII. Library | The violation monitor is listed allowed global state; no async runtime | PASS |

## Project Structure

```text
crates/procage-policy/src/sbpl.rs, lower/macos.rs, lower/mod.rs, lib.rs, name.rs
crates/procage-policy/tests/ (rendering fixtures)
src/violation.rs (new), src/lib.rs
src/macos/violations.rs (new), src/macos/mod.rs, src/macos/child.rs, src/macos/sys.rs
src/linux/mod.rs, src/linux/child.rs
tests/spawn_macos.rs, tests/escape_macos.rs, tests/native.rs
tests/kernel_facts (KF-M29)
Cargo.toml, README.md, THREAT_MODEL.md
```

If the crate moves under `crates/procage/` first (layout question), the
`src/` and `tests/` paths gain that prefix.

## Complexity Tracking

| Item | Why | Simpler alternative rejected |
|---|---|---|
| A helper process | The only unprivileged source of Seatbelt denials | `OSLogStore` needs Objective-C and admin too; `(with send-signal)` kills instead of reporting |
| Slots for non-forking policies | Per-run attribution needs a per-run message | Static tag per cage mixes concurrent runs |
