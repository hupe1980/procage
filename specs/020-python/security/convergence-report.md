## Security Convergence — 020-python

Commit `4928124` · 2026-11-03T19:00:34Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 7 |
| verified | 5 |
| implemented, unverified | 2 SR-005, SR-006 |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: NOT CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `bindings/python/tests/test_procage.py::EscapeSubset::test_the_callers_environment_is_not_copied` | With a secret in os.environ and env= naming one variable, a caged env prints that variable and not the secret, on macOS 26.6.2 and Linux T1 and T2 from the built wheel; spawn sets only env= entries (bindings/python/src/lib.rs, Cage::spawn). |
| SR-002 | verified | test | `bindings/python/tests/test_procage.py::Concurrency::test_spawns_from_several_threads_complete` | 80 spawns from four Python threads complete; the binding spawns through procage's Rust child sequence and registers no hook that runs in the child (no preexec option exists in the API). |
| SR-003 | verified | test | `bindings/python/tests/test_procage.py::Policies::test_a_gap_raises_with_the_gaps` | An unknown JSON field, an unknown preset, a bad version or relative workspace and an unknown relaxation raise PolicyError; a gap raises CapabilityGapError with the gaps on both systems; the accept hints name options without applying them (test_a_gap_says_which_option_accepts_it). |
| SR-004 | verified | test | `bindings/python/tests/test_procage.py::Lifetime::test_interpreter_exit_kills_live_runs` | A sleep started by a child interpreter is dead after that interpreter exits; test_collecting_a_run_kills_it shows the same for a collected Run; kill ends a run. |
| SR-005 | implemented-unverified | review | `.github/workflows/release.yml:73` | The wheel and pypi jobs use actions pinned to full SHAs (workflows gate passes), test the built wheel before upload and publish with pypa/gh-action-pypi-publish in the pypi environment with id-token write and no secret; not yet run, and PyPI's trusted publisher must name release.yml and the pypi environment. |
| SR-006 | implemented-unverified | review | `.github/workflows/ci.yml:106` | Every facts lane runs bindings/python/wheel.sh all (build as released, install fresh, 26 tests and the example); passed locally on macOS and Linux T1 and T2, not yet on the CI lanes. |
| SR-007 | verified | test | `bindings/python/tests/test_procage.py::Concurrency::test_waiting_releases_the_interpreter` | While one thread waits on a one-second run, the main thread ticks more than 100 times; spawn, wait, communicate and violations run inside py.detach. |
