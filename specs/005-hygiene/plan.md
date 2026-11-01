# Implementation Plan: Process hygiene for caged children

**Branch**: `005-hygiene` (committed on `main` per user instruction) | **Date**: 2026-10-30 | **Spec**: [spec.md](spec.md)

## Summary

This feature extends the macOS spawn path of 004:

- **Descriptors**: a descriptor sweep in the child, using `proc_pidinfo` into
  a parent buffer with an `fcntl` fallback. It marks every fd ≥ 3
  close-on-exec except the named ones.
- **Lifetime**: an own process group in every tty mode, and a `Child` handle
  that kills the group plus every descendant it can find on drop (`detach()`
  opts out).
- **Environment**: a shared, pure environment filter with a passthrough
  denylist.
- **Temporary directory**: a per-spawn private `TMPDIR` through a `tmpdir`
  grant.
- **Docs**: the docs and the threat-model release status are updated.

## Technical Context

**Language/Version**: Rust 2024, MSRV 1.99

**Dependencies**: none new. `libc` provides `proc_pidinfo`, `proc_listchildpids` and `killpg`.

**Testing**: `tests/spawn_macos.rs` (caged children, self re-exec, an uncaged intermediary for environment tests); unit tests in `src/hygiene.rs`.

**Performance**: sweep overhead < 5 ms median with 1,000 extra fds and a 1,048,576 soft limit (recorded).

**Constraints**: syscalls only between fork and exec; no enforcement claim without a test.

## The child's call sequence (constitution IV)

| # | Call | Failure → step |
|---|---|---|
| 1 | `setsid()` (Tty::None), or `setpgid(0, 0)` (Inherit) | Session |
| 2 | `setrlimit` for each limit | Rlimit |
| 3 | `proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, buf, len)`, then `fcntl(fd, F_SETFD, FD_CLOEXEC)` for each listed fd ≥ 3 not kept, and `fcntl(fd, F_SETFD, 0)` for each kept fd. A full buffer, or a listing failure, falls back to `fcntl` for every fd in 3..`getdtablesize()` | Fds (new, 6) |
| 4 | `__mac_syscall` apply | Apply |
| 5 | `sandbox_check(self)` | Verify |
| 6 | `sandbox_extension_consume` | Consume |

The buffer and the keep list are owned by the closure, allocated in the parent.

## Constitution Check

| Principle | Compliance | Evidence | Gap |
|---|---|---|---|
| I. Fail closed | A named fd that is not open, and a reserved grant name, are typed errors. A failed sweep is a step error and nothing runs | tests | — |
| II. Types over strings | n/a | | |
| III. Kernel is the oracle | Each hygiene claim has a caged-child test. Statuses unchanged | `spawn_macos` | macOS only |
| IV. Syscalls only; unsafe in sys | The sweep runs only `proc_info`, `fcntl` and `getdtablesize`; new `unsafe` only in `sys` | `unsafe_confined`, `contention` | — |
| V. Hygiene by default | This feature implements V on macOS: fds, env, tty session, lifetime, rlimits | tests | Double fork and pty (022) |
| VI. Private interfaces | n/a (public syscalls) | | |
| VII. Library | Kill-on-drop is overridable (`detach`). The environment denylist is overridable by explicit command variables | tests | — |

**Gate**: PASS.

## Project Structure

```text
src/hygiene.rs          # NEW: pure environment filter (all OSes) + unit tests
src/macos/child.rs      # NEW: Child handle, tree kill, tmpdir cleanup
src/macos/sys.rs        # sweep, setpgid, killpg, proc_listchildpids, testing helpers
src/macos/{mod,spawn}.rs
tests/spawn_macos.rs
THREAT_MODEL.md, README.md, src/lib.rs
```
