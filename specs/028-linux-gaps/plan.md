# Implementation Plan: Unix sockets under trees, and hiding on Linux T2

**Branch**: `028-linux-gaps` (local; commits on `main`) | **Date**: 2026-10-31 | **Spec**: [spec.md](spec.md)

## Summary

- Policy: `Ipc.unix_sockets: Vec<AbsPath>`; remove `Network::UnixSockets` and
  `PolicyError::EmptyUnixSockets`; construct `net-unix-sockets` →
  `ipc-unix-sockets`; `Construct::SPAWN_SNAPSHOT`;
  `LowerOptions::accept_spawn_snapshot` (rename); gap display names the
  option for snapshot constructs.
- macOS lowering: `system-socket` + network bind/inbound/outbound with
  subpath filters; hidden paths deny those operations (within block).
  `canon.rs` resolves the socket paths.
- Linux lowering: with the network off, `socket()` except `AF_UNIX`; ABI ≥ 9
  `RESOLVE_UNIX` rules (exact); T1 below 9 → approximated, plan
  `mask_unix_sockets` + `unix_socket_paths`, abstract scope (ABI ≥ 6); T2
  below 9 → unsupported. `Hide` on T2 → approximated unless a write rule
  reaches it (`hide_by_siblings`); secrets class on T2 → approximated when
  only read rules reach it.
- Linux backend: T1 socket masks from `/proc/net/unix` (in `prepare`, as
  covers); T2 hidden set (`hide_by_siblings` + secrets paths that exist) and
  piecewise expansion in `spawn::ruleset`; `GrantError::Covers`.
- Docs: lowering table, linux module docs, THREAT_MODEL R-09 note, crate
  docs mention; the answer to the consumer.

## Technical Context

Rust 1.99; no new dependencies; tests: policy crate, escape suites (R-09),
spawn_linux (T2 hiding), Docker T1/T2, `just ci`. Constraints: child-side
code unchanged (masks are ordinary mounts; expansion happens in the parent).

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | T2 sockets refused; writable carve-outs on T2 refused; approximations need the named option; symlink siblings and later entries denied | PASS |
| II. Types | `Ipc.unix_sockets`, typed constructs and `GrantError::Covers` | PASS |
| III. Kernel oracle | Canaries on macOS, T1, T2 decide; the socket facts were measured | PASS |
| IV. Syscalls only | No child-side change | PASS |
| V. Hygiene | Unchanged | PASS |
| VI. Private interfaces | `/proc/net/unix` is a documented kernel interface | PASS |
| VII. Library | No global state | PASS |

## Complexity Tracking

None.
