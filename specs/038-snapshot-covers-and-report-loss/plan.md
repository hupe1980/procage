# Implementation Plan: Vanished snapshot covers and honest report loss

**Branch**: `038-snapshot-covers-and-report-loss` (local planning; commits on `main`) | **Date**: 2026-11-01 | **Spec**: [spec.md](spec.md)

## Summary

- `linux/sys.rs`: `ChildMount::{Bind, Tmpfs}` gain `optional: bool`. The
  child's loop skips an optional mount that fails with `ENOENT` and the
  `Remount` of the same target that follows (a borrowed `&CStr`, no
  allocation); every other failure fails the spawn.
- `linux/spawn.rs`: `mounts()` marks the cover groups optional and skips a
  cover whose builder fails with `SpawnError::Path` and `ENOENT`; plan
  mounts are built as before.
- Test `a_socket_removed_during_the_spawn_does_not_fail_it`
  (`tests/spawn_linux.rs`, T1).
- Docs: `violation.rs` (module, `Coverage::Observed`, `complete`),
  `site/content/docs/violations.md`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Only snapshot covers, only ENOENT; declared mounts strict; remount skipped with its bind | PASS |
| III. Kernel oracle | Churn test on T1 fails without the fix; escape suite and mask tests unchanged | PASS |
| Honest docs | No claim beyond the measurement | PASS |

## Project Structure

```text
crates/procage/src/linux/{sys.rs, spawn.rs}
crates/procage/tests/spawn_linux.rs
crates/procage/src/violation.rs
site/content/docs/violations.md
```

## Complexity Tracking

None.
