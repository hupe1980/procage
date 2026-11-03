# Implementation Plan: Node.js bindings

**Branch**: `049-nodejs` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Measured before planning (macOS 26.6.2, Node 26)

- napi 3 / napi-derive 3 build a `cdylib` Node loads; synchronous calls,
  `AsyncTask` (libuv thread pool) and `async` methods return promises.
- The macros emit `#[allow(unsafe_code)]` on their glue, which a
  `forbid(unsafe_code)` refuses (E0453); with `deny(unsafe_code)` the
  crate builds and an `unsafe` block of ours fails to compile.

## Layout: `bindings/nodejs`

- `Cargo.toml`, `build.rs` (`napi_build::setup`), `src/lib.rs`: crate
  `procage-node`, `cdylib`, `publish = false`, a workspace member. Its
  lints copy the workspace's, except `unsafe_code = "deny"` (see above).
- `package.json` (`"type": "module"`, `exports` with types, `engines`
  `node >=22.12`, `files`: the JavaScript, the declarations and
  `procage.*.node`), `index.js`, `index.d.ts`, `test/`, `examples/`,
  `build.sh`, README and licences. Replaces `packaging/npm`.

## Native addon (`src/lib.rs`)

| JavaScript | Rust |
|---|---|
| `Policy.preset(name, version, workspace?)`, `fromJson`, `toJson`, `workspace` | the presets and the versioned serde format, as in Python |
| `new Cage(policy, { violations, relax, acceptSpawnSnapshot })` | `Cage::with_options` or `Cage::fit` |
| `cage.spawn(argv, { cwd, env, grants, stdin })` (async task) | `Command` with exactly `env`, the preset's workspace as default `cwd`, `Grants`; spawned on the thread pool |
| `run.pid`, `run.wait()` (async), `run.output(input?, timeoutMs?)` (async: writes, reads both pipes, waits) | `try_wait` polled on a pool thread, the handle's mutex held per poll |
| `run.kill()` | `kill_all` |
| `run.violations()` (async), `run.receiptJson()` | as in Python |
| collection of a `Run` | the addon's finaliser drops the `Child`: the run ends |

Errors: the addon throws `Error`s whose `code` names the kind
(`PolicyError`, `CapabilityGapError`, …) and whose message for a gap is a
JSON document with the gaps and their accept hints; `index.js` turns each
into its class. The accept hints use the JavaScript spelling
(`acceptSpawnSnapshot: true`, `relax: ["waive:trust-handoff"]`).

## JavaScript module (`index.js`, `index.d.ts`)

- **Loader**: `procage.${platform}-${arch}${libc}.node` beside
  `index.js` (`darwin-arm64`, `linux-x64-gnu`, `linux-arm64-gnu`), loaded
  with `createRequire(import.meta.url)`; nothing else is consulted (no
  environment variable, no working directory). Another platform or musl
  throws `UnsupportedError` naming it (SR-008).
- `run(policyOrCage, command, options)`: `command` is an array, or a
  string with `shell: true`; `encoding` `"utf8"` (default) or `"buffer"`;
  `input` string or `Uint8Array`; `timeout` in milliseconds (kills, then
  rejects with `TimeoutError`); `signal` (`AbortSignal`: kills, rejects
  with the signal's reason); `check: true` rejects with `ExitError` (the
  result attached) on a non-zero exit. Resolves to `{ command, exitCode,
  signal, stdout, stderr, violations, receipt }`.
- `Run`: `pid`, `wait()`, `output()`, `kill()`, `violations()`,
  `receipt()`, `[Symbol.dispose]` and `[Symbol.asyncDispose]` (kill and
  release), so `await using run = await cage.spawn(...)` cleans up.
- Exit: a `Set` of live runs, killed on `process.on("exit")`.

## Build and release

- `build.sh build` compiles the addon for the host (Linux:
  `cargo zigbuild --target <arch>-unknown-linux-gnu.2.28`, tools from
  pinned PyPI versions as for the wheels) and copies it to
  `procage.<platform>.node`; `build.sh test` packs the package
  (`npm pack`), installs the tarball into a scratch project and runs the
  tests and the example against it; `all` does both.
- CI: each facts lane sets up Node (pinned action) and runs `build.sh all`.
- Release: a `node` job per platform builds, tests from the packed
  package and uploads its `.node`; an `npm` job in the `npm` environment
  (tags `v*` only) downloads the three, packs once, checks the tarball
  holds exactly the expected files, and runs `npm publish --provenance`
  with OIDC (npm's trusted publisher for `procage`: `release.yml`,
  environment `npm`). The GitHub release waits for it too.

## Tests (`test/procage.test.js`, `node:test`, no dependency)

The escape subset of the Python package (outside reads and writes, a
secret, the network, `process.env` not copied), policies and gaps with
hints, `check`, `shell`, `encoding`, `input`, timeout, `AbortSignal`,
`await using`, exit of a child Node process killing its runs, many runs
at once with a timer firing on time meanwhile, violations, the receipt,
the loader refusing an override, and the example.

## Decisions (implementation)

- **Node versions in CI.** The package claims Node 22.12 and later, so the
  Linux lanes and the release's addon jobs test on Node 22, the macOS
  lanes on 26 (the current LTS); locally both ran on Linux T1 and T2. The
  disposal test calls `Symbol.asyncDispose` directly: `await using` is
  syntax Node 22 cannot parse (the method exists there; the README shows
  the syntax for Node 24 and later). `node --test` takes a file glob, as
  Node 22 takes no directory.
- **Linux in containers.** `just node-linux` builds the addon in the Rust
  image (as root, after installing `venv` for the zig tools) into a scratch
  directory, then packs and tests in the official Node image as uid 65534,
  clearing any local addon from the copied package first.
- **Paths.** A trailing slash is dropped (a `file:` URL of a directory ends
  with one, and procage's paths refuse it); the Python binding does the
  same now, so `"/abs/project/"` names the project in both.
- **Errors across the boundary.** The addon throws `procage:{json}`
  (kind, message, gaps); `index.js` rebuilds the class, so `instanceof`
  works and the gap hints are formatted in JavaScript spelling.
- **Versions.** A `versions` gate in `just ci` keeps
  `bindings/nodejs/package.json` at the crates' version; the release
  checks the tag against it.
- **Measured.** 25 tests pass from the packed package on macOS 26.6.2
  (Node 26; the Linux-only hint test skipped), Linux 7.0 T1 (Node 22) and
  T2 (Node 26).

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No default differs from Rust; gaps throw with hints, nothing accepted silently; the loader fails closed | PASS |
| II | Policies only through presets and the versioned format | PASS |
| III | The escape subset runs from the packed package on every lane | PASS |
| IV | No `unsafe` of ours (`deny`, which the napi macros' generated glue needs instead of `forbid`); no JavaScript in the child | PASS (recorded) |
| V | Only `env` is passed explicitly; runs end on kill, disposal, abort, timeout, collection and exit | PASS |
| VI | No private interface added | PASS |
| VII | No global state in Rust; the live-run set is JavaScript's | PASS |

**Remaining gaps**: Bun and Deno untested; no musl or Intel macOS binary;
a process killed with `SIGKILL` runs no exit hook (Linux children still
die with their parent).
