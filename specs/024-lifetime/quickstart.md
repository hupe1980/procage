# Quickstart: validate lifetime

## macOS (development host)

1. `cargo test -p procage --test escape_macos r23` — all R-23
   canaries run (none ignored) and pass:
   `r23_descendants_die_with_the_run`,
   `r23_a_double_forked_descendant_dies_with_the_run`,
   `r23_descendants_of_an_exited_child_die_with_the_run`,
   `r23_concurrent_runs_are_separate`,
   `r23_a_detached_run_keeps_its_marker`,
   `r23_tree_lifetime_still_reaps`,
   `r23_a_launch_agent_cannot_be_planted`.
2. `cargo test -p procage --test spawn_macos marker` — the marker matches the run only
   (not the caller, not an allow-all `sandbox-exec` process, not another
   run); repeated spawns compile once.
3. Timing: drop of a forking run, before/after (SC-003).

## Linux (Docker)

1. `just linux` (T2) and `just linux-t1` (T1, which also runs T2 cages):
   the Linux canaries (double fork, exited child, user unit) plus
   `r23_sessions_are_locked` and `r23_tree_lifetime_allows_sessions` pass on
   both tiers.

## Gates

- `cargo test -p procage-policy` (ledger, seccomp per arch, presets).
- `cargo test --test threat_model` (R-23 mitigated, evidence exists).
- `just ci`.

## Recorded outcomes (2026-10-31)

- **Baseline (T001)**: macOS R-23: 2 passed, 1 ignored (double fork open);
  `procage-policy` 79 tests after the policy change.
- **macOS 26.6.2**: `escape_macos` r23: 7/7 pass (none ignored); the whole
  suite 22 passed, 3 ignored (R-08, R-25, R-26). Negative control: with the
  marker kill disabled, 5 of the 7 fail (double fork, exited child,
  concurrent, detached, tree). `spawn_macos` 43 passed (marker matches only
  its run: not the caller, not an `(allow default)` `sandbox-exec` process,
  not a second run).
- **Linux T2** (Docker default seccomp) and **T1** (unconfined; T1 and T2
  cages): `escape_linux` 19 passed, 2 ignored; r23 6/6 (double fork, exited
  child, sessions locked `1 1`, tree `ok ok`, descendants, user unit);
  `spawn_linux` 26 passed; lib 17; `unsafe_confined` 2. rustdoc with
  `-D warnings` builds on Linux.
- **Timing (SC-003)**: drop of a forking run median 2.05 ms (p90 2.67 ms)
  against 0.22 ms without fork; spawn unchanged (~0.8 ms cached). Reaping
  the child before the scan cut p90 from 6.6 ms.
- **Compile once (SC-004)**: preparing the same forking policy again does not
  compile; slot 0 uses the cage's bytecode.
- **Gates (SC-006)**: `just ci` passes all 10 gates.
- **Found while implementing**: the kernel-facts compile check compiled
  lowered profiles without the run-marker parameters (an unbound param is
  a boolean); it now binds placeholder values. The exited-child canary
  asserted the child's exit status, which races with the harness writing to
  a pipe the test closed; it now only waits.
