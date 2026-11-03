## Security Convergence — 020-python

Commit `523e41c` · 2026-11-03T20:12:15Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 7 |
| verified | 7 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `bindings/python/tests/test_procage.py::EscapeSubset::test_the_callers_environment_is_not_copied` | With a secret in os.environ and env= naming one variable, a caged env prints that variable and not the secret, on macOS 26.6.2 and Linux T1 and T2 from the built wheel; spawn sets only env= entries (bindings/python/src/lib.rs, Cage::spawn). |
| SR-002 | verified | test | `bindings/python/tests/test_procage.py::Concurrency::test_spawns_from_several_threads_complete` | 80 spawns from four Python threads complete; the binding spawns through procage's Rust child sequence and registers no hook that runs in the child (no preexec option exists in the API). |
| SR-003 | verified | test | `bindings/python/tests/test_procage.py::Policies::test_a_gap_raises_with_the_gaps` | An unknown JSON field, an unknown preset, a bad version or relative workspace and an unknown relaxation raise PolicyError; a gap raises CapabilityGapError with the gaps on both systems; the accept hints name options without applying them (test_a_gap_says_which_option_accepts_it). |
| SR-004 | verified | test | `bindings/python/tests/test_procage.py::Lifetime::test_interpreter_exit_kills_live_runs` | A sleep started by a child interpreter is dead after that interpreter exits; test_collecting_a_run_kills_it shows the same for a collected Run; kill ends a run. |
| SR-005 | verified | test | `.github/workflows/release.yml::pypi` | Release run 41709283676 (tag v0.6.0 on 523e41c) built the wheels with SHA-pinned actions, tested each built file, and uploaded them with PyPI Trusted Publishing from the pypi environment (limited to v* tags) with no stored token; the first attempt was refused with invalid-publisher until the trusted publisher matched, so publishing fails closed. |
| SR-006 | verified | test | `bindings/python/tests/test_procage.py::EscapeSubset::test_reading_outside_the_workspace_is_refused` | CI run 41706008599 ran wheel.sh all (build as released, install fresh, 29 tests and the shell tool example) green on macOS 26 and 27, Ubuntu 24.04 x86_64 and arm64 and 26.04 on both tiers; the release tested the three published wheels before upload; the docs claim only those platforms. |
| SR-007 | verified | test | `bindings/python/tests/test_procage.py::Concurrency::test_waiting_releases_the_interpreter` | While one thread waits on a one-second run, the main thread ticks more than 100 times; spawn, wait, communicate and violations run inside py.detach. |
