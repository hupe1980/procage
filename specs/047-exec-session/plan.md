# Implementation Plan: A helper's command in a session of its own

**Branch**: `047-exec-session` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Design

1. `sys::Session::Lead` on both backends: `setsid()` unless
   `getsid(0) == getpid()`; `sys::leads()` reports session and group
   leadership for the pre-check.
2. `Cage::exec_session(_with_fds)` → shared `exec_as(.., Session::Lead)`;
   Linux uses the spawn filter for `Lead` and the exec filter for `Keep`;
   the death signal and the program lookup treat `Lead` like `Keep`.
3. `end_session(pid)`: Linux reuses `child::kill_session` (the `/proc`
   session scan of a run's end); macOS lists pids, keeps the user's live
   ones whose `getsid` is `pid`, kills them (repeated for members forked
   meanwhile), then the group.
4. `SpawnError::GroupLeader` on both backends.
5. Tests in `tests/exec.rs`: a plain-child helper with `exec_session`
   (process group allowed, session refused on Linux, a grouped sleeper
   ended by `end_session`); a group-leader helper refused (exit 126, the
   command never ran).

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | The session boundary is enforced on Linux; macOS states its limit | PASS |
| II | Typed refusal (`SpawnError::GroupLeader`) before any change | PASS |
| III | Caged helpers on macOS, T1 and T2 | PASS |
| VII | Additive API; no public type changes shape | PASS |
