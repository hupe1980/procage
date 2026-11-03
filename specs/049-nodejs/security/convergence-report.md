## Security Convergence — 049-nodejs

Commit `0ea56cd` · 2026-11-03T22:44:53Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
| Open blocking threats | 0  |
| Security requirements | 8 |
| verified | 8 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `bindings/nodejs/test/procage.test.js::escape subset::process.env is not copied` | With a secret in process.env and env naming one variable, a caged env prints that variable and not the secret, on macOS and Linux T1 and T2 from the packed package; the addon sets only env entries. |
| SR-002 | verified | test | `bindings/nodejs/test/procage.test.js::concurrency::many runs at once, and the event loop stays free` | Six runs started from one event loop complete together; spawn is an AsyncTask on the libuv pool through procage's Rust child sequence, and the API has no hook that runs in the child. |
| SR-003 | verified | test | `bindings/nodejs/test/procage.test.js::policies::a gap throws with the gaps` | Unknown fields, unknown presets, bad versions, relative workspaces and unknown relaxations throw PolicyError; a gap throws CapabilityGapError (instanceof ProcageError) with gaps; the Linux test shows the accepting option named without being applied. |
| SR-004 | verified | test | `bindings/nodejs/test/procage.test.js::lifetime::aborting ends the run` | Timeout, AbortSignal, Symbol.asyncDispose and the exit of a child Node process each leave the run's process dead; collection drops the Child through the addon's finaliser. |
| SR-005 | verified | test | `.github/workflows/release.yml::npm` | Release run 41732927065 (v0.7.1 on 0ea56cd) built each addon with SHA-pinned actions, tested it from a packed package, checked the tag and the three addons, packed with the contents check and published with npm Trusted Publishing (OIDC, environment npm limited to v* tags, no token); npm shows procage@0.7.1 with SLSA provenance. 0.7.0's upload failed closed (the tarball path was read as a repository) and the GitHub release waited. |
| SR-006 | verified | test | `bindings/nodejs/test/procage.test.js::escape subset::reading outside the workspace is refused` | CI runs 41726108698 and 41730028663 ran build.sh all (build, pack with the contents check, 25 tests and the example from the tarball) green on macOS 26 and 27 (Node 26) and Ubuntu 24.04 x86_64 and arm64 and 26.04 on both tiers (Node 22); the published package installs from npm and runs a caged command on macOS 26.6.2. |
| SR-007 | verified | test | `bindings/nodejs/test/procage.test.js::concurrency::many runs at once, and the event loop stays free` | While six one-second runs proceed, a 20 ms interval never waits more than 500 ms; wait, output and violations are AsyncTasks on the pool. |
| SR-008 | verified | test | `bindings/nodejs/test/procage.test.js::loader::loads the packaged addon whatever the environment says` | With NAPI_RS_NATIVE_LIBRARY_PATH set to another path the import loads the packaged addon; the loader builds the file name from platform and arch beside index.js and throws UnsupportedError on any other platform or without glibc. |
