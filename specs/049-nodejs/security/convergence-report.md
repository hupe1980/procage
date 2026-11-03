## Security Convergence — 049-nodejs

Commit `f72c024` · 2026-11-03T21:27:12Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
| Open blocking threats | 0  |
| Security requirements | 8 |
| verified | 6 |
| implemented, unverified | 2 SR-005, SR-006 |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: NOT CONVERGED**

Appended tasks: T011, T012

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `bindings/nodejs/test/procage.test.js::escape subset::process.env is not copied` | With a secret in process.env and env naming one variable, a caged env prints that variable and not the secret, on macOS and Linux T1 and T2 from the packed package; the addon sets only env entries. |
| SR-002 | verified | test | `bindings/nodejs/test/procage.test.js::concurrency::many runs at once, and the event loop stays free` | Six runs started from one event loop complete together; spawn is an AsyncTask on the libuv pool through procage's Rust child sequence, and the API has no hook that runs in the child. |
| SR-003 | verified | test | `bindings/nodejs/test/procage.test.js::policies::a gap throws with the gaps` | Unknown fields, unknown presets, bad versions, relative workspaces and unknown relaxations throw PolicyError; a gap throws CapabilityGapError (instanceof ProcageError) with gaps; the Linux test shows the accepting option named without being applied. |
| SR-004 | verified | test | `bindings/nodejs/test/procage.test.js::lifetime::aborting ends the run` | Timeout, AbortSignal, Symbol.asyncDispose and the exit of a child Node process each leave the run's process dead; collection drops the Child through the addon's finaliser. |
| SR-005 | implemented-unverified | review | `.github/workflows/release.yml:142` | The node and npm jobs use SHA-pinned actions, test each addon from a packed package, check the tag and the three addons, pack with the contents check and run npm publish --provenance with id-token write in the npm environment and no token; not yet run, and npm's trusted publisher for procage must name release.yml and the npm environment. |
| SR-006 | implemented-unverified | review | `.github/workflows/ci.yml:112` | Every facts lane runs bindings/nodejs/build.sh all (build, pack with the contents check, 25 tests and the example from the tarball; Node 22 on Linux, 26 on macOS); passed locally on macOS and Linux T1 and T2, not yet on the CI lanes. |
| SR-007 | verified | test | `bindings/nodejs/test/procage.test.js::concurrency::many runs at once, and the event loop stays free` | While six one-second runs proceed, a 20 ms interval never waits more than 500 ms; wait, output and violations are AsyncTasks on the pool. |
| SR-008 | verified | test | `bindings/nodejs/test/procage.test.js::loader::loads the packaged addon whatever the environment says` | With NAPI_RS_NATIVE_LIBRARY_PATH set to another path the import loads the packaged addon; the loader builds the file name from platform and arch beside index.js and throws UnsupportedError on any other platform or without glibc. |
