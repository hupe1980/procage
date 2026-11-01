# Implementation Plan: Exec entry

**Branch**: `029-exec-entry` (local planning; commits on `main`) |
**Date**: 2026-10-31 | **Spec**: [spec.md](spec.md)

## Summary

`Cage::exec` / `Cage::exec_with_fds` on both backends (R1–R5): checks first
(nesting, probe, `tmpdir` grant, T1 threads, grants, environment, program
lookup), then the existing child step sequence with the session step in
`Keep` mode, installed as a `pre_exec` hook, then std's `Command::exec`.
`spawn_with_fds` and `exec_with_fds` share one `prepare` per backend.
Docs: a "Helpers" section in the crate docs (helper and outside side,
lifetime per system), the `exec` rustdoc, THREAT_MODEL's lifetime text;
`examples/exec_helper.rs` (portable, via `procage::native`). Tests:
`tests/exec.rs` (`harness = false`).

## Technical Context

**Language/Version**: Rust 1.99, edition 2024. **Dependencies**: none new.
**Testing**: `tests/exec.rs` on macOS and Docker T1/T2; `just ci` (builds and
lints the example). **Constraints**: child-side code keeps its nature
(syscalls only); `unsafe` only in `sys`. **Scope**: ~200 lines code,
~250 lines tests, docs, example.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I. Fail closed | Refusals before the first change; failures after it are errors the docs call fatal; no fallback to an unconfined exec | PASS |
| II. Types | `GrantError::TmpdirWithExec`, `Unsupported::ExecThreads`, session mode enum | PASS |
| III. Kernel oracle | Helper tests on macOS, T1, T2 | PASS |
| IV. Syscalls only | Same step sequence; the session step gains a no-op mode; the new pre-checks run in the caller before any step | PASS |
| V. Hygiene | Same hygiene as spawn except the session (caller-owned lifetime, documented) | PASS (justified: the point of the entry) |
| VI. Private interfaces | No new ones | PASS |
| VII. Library | No new global state | PASS |

## Project Structure

```text
src/macos/{mod.rs,sys.rs,child.rs}   # prepare/spawn/exec, Session, GrantError
src/linux/{mod.rs,sys.rs}            # prepare/spawn/exec, Session, ExecThreads, ppid, threads
src/unix.rs                          # program lookup
src/lib.rs                           # Helpers section
examples/exec_helper.rs
tests/exec.rs (+ Cargo.toml [[test]] harness = false)
justfile (Linux recipes: --test exec)
THREAT_MODEL.md                      # lifetime with exec
```

## Complexity Tracking

None.
