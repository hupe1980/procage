# Implementation Plan: Process groups under `Lifetime::Run` on Linux

**Branch**: `046-process-groups` (local planning; commits on `main`) | **Date**: 2026-11-02 | **Spec**: [spec.md](spec.md)

## Design

1. **Lowering** (`procage-policy/src/lower/linux.rs`): `Lifetime::Run`
   denies `setsid`; `setpgid` only when `policy.tty == Tty::Inherit`.
2. **Exec** (`procage/src/linux/mod.rs`): the cage builds a second filter
   with `setpgid` denied, used when the session step keeps the caller's
   (`Session::Keep`).
3. **Ending the run** (`procage/src/linux/child.rs`): `processes()` reads
   pid, parent, session and zombie state from `/proc`; `signal` kills the
   live members of the session whose id is the child's pid (at most 64
   rounds, each killing only members not yet killed), then the group.
4. **Canaries**: `r23_sessions_are_locked` expects `setsid` refused and
   `setpgid` allowed; `r23_a_descendant_in_a_group_of_its_own_dies_with_the_run`
   (a sleeper in its own group, reparented); `exec.rs` checks `setpgid` and
   `setsid` refused for `Cage::exec`; the lowering test covers `Tty::Inherit`.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | The run's boundary is enforced (session plus `setsid` refused), not approximated | PASS |
| III | Canary for a grouped, reparented descendant on T1 and T2; exec checked | PASS |
| VII | No new dependency; no public API change | PASS |
