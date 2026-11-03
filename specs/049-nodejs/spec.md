# Feature Specification: Node.js bindings

**Feature Branch**: `049-nodejs` (planning directory; commits land on `main`)

**Created**: 2026-11-03

**Status**: Implemented

**Input**: Agent tools are written in TypeScript as often as in Python: coding agents, editor extensions and MCP servers that run shell commands for a model. The name `procage` is reserved on npm. A binding that installs with `npm install procage` and reads like the Node APIs developers know would make procage the sandbox those tools reach for.

## Context

The binding wraps the Rust library as the Python package does
(spec 020): no policy semantics of its own, policies from presets or the
versioned JSON format, every error typed. It follows the Python package's
names where Node has no stronger convention, so one mental model serves
both, and Node's conventions where it does: promises, milliseconds,
`AbortSignal`, strings for text output, explicit resource management.

## Clarifications

### Session 2026-11-03

Decided by the project's scope rule (best-in-class, no overengineering).

- Q: Which binding technology? → A: napi-rs (Node-API): stable ABI across
  Node versions, async work on the libuv thread pool, and the most used
  Rust binding for Node. Its macros mark their own glue `allow(unsafe_code)`,
  which the workspace's `forbid` refuses; the crate denies `unsafe_code`
  instead, so no `unsafe` of ours compiles (measured).
- Q: How is it distributed? → A: One npm package, `procage`, carrying
  prebuilt binaries for macOS arm64 and Linux x86_64 and aarch64 (glibc
  2.28, as the wheels) and loading the one for the host. No per-platform
  packages: one name, one trusted publisher, no optional-dependency
  resolution to fail.
- Q: Which Node versions and module format? → A: Node 22.12 and later
  (the maintained LTS lines; `require` of ES modules works), ES modules,
  with TypeScript declarations shipped beside the JavaScript. No build step
  for users and none in the package.
- Q: What is the surface? → A: `Policy` (`preset(name, version,
  { workspace })` remembering the workspace as the default working
  directory, `fromJSON`, `toJSON`), `Cage(policy, { violations, relax,
  acceptSpawnSnapshot })`, `run(policyOrCage, command, options)` returning a
  promise of `{ exitCode, signal, stdout, stderr, violations, receipt }`,
  and `cage.spawn(...)` returning a `Run` with `pid`, `wait()`,
  `output()`, `kill()`, `violations()`, `receipt()`. Options: `shell`,
  `cwd`, `env`, `grants`, `input`, `timeout` (milliseconds), `signal`
  (`AbortSignal`), `encoding` (`"utf8"` default, `"buffer"`), `check`.
  `Run` supports `using`/`await using` (`Symbol.dispose`,
  `Symbol.asyncDispose`).
- Q: How do errors reach JavaScript? → A: Classes extending `Error`:
  `ProcageError` and `PolicyError`, `CapabilityGapError` (`gaps`, each
  naming the option that would accept it, also in the message),
  `UnsupportedError`, `AlreadySandboxedError`, `GrantError`, `SpawnError`,
  `TimeoutError`, and `ExitError` for `check: true`; `instanceof` works.
- Q: What ends a run? → A: `kill()`, disposal, an aborted signal, a
  timeout, garbage collection of the `Run`, and the exit of the Node
  process (`beforeExit` and `exit` hooks); as in Python, a process killed
  with `SIGKILL` runs no hook.
- Q: Where does the code live? → A: `bindings/nodejs`, one directory
  (crate `procage-node`, a workspace member not published to crates.io,
  beside `package.json`, the JavaScript, the declarations, tests and an
  example), as `bindings/python`. The npm name reservation in
  `packaging/npm` is replaced.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a command caged from Node (Priority: P1)

A TypeScript agent tool runs a model's command in a workspace.

**Independent Test**: `npm install procage`, build a policy from a preset
for a workspace, `await run(policy, "make test", { shell: true })`, read
the exit code, output and violations, on each platform.

**Acceptance Scenarios**:

1. **Given** a preset and a workspace, **When** a command runs, **Then** it
   is caged exactly as from Rust (the binding's tests run the escape subset
   of the Python package).
2. **Given** a policy the host cannot enforce, **Then** the promise rejects
   with `CapabilityGapError` whose message names the option that would
   accept each gap.
3. **Given** an aborted signal, an elapsed timeout, a disposed or collected
   `Run`, or the process exiting, **Then** every process of the run is
   killed.

---

### User Story 2 - Plug into an agent tool (Priority: P2)

**Acceptance Scenarios**:

1. **Given** the documented example, **Then** a shell tool for an agent or
   an MCP server runs its commands through procage with a few lines.

### Edge Cases

- Many runs at once: each waits on the thread pool; the event loop stays
  free.
- `worker_threads`: a cage made in one thread is used in that thread.
- Running inside another sandbox: the same refusal as from Rust.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The package MUST expose presets and the versioned JSON
  format, cage construction with options (violations, named relaxations,
  the spawn snapshot), spawning with arguments or a shell command line,
  working directory, an explicit environment and grants, waiting, killing,
  output, violations and the receipt.
- **FR-002**: Every Rust error MUST become an instance of a typed error
  class with the same information.
- **FR-003**: The binding MUST NOT run JavaScript between fork and exec,
  and MUST NOT block the event loop while procage spawns, waits or reads.
- **FR-004**: The package MUST be built and tested in CI on every target
  platform and published by the release workflow with npm Trusted
  Publishing and provenance, no stored token.
- **FR-005**: The binding MUST NOT copy `process.env` into the command;
  only `env` is set explicitly.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The binding MUST NOT copy process.env into the command; only variables passed in env are set explicitly, and the policy environment rules decide the rest.
  - Mitigates: `threat.env-leak` via `mitigation.explicit-env`
  - Given a secret variable in process.env and a preset policy, when a caged command prints its environment, then the secret is absent
  - Given the same and env naming one variable, when the command prints its environment, then that variable is present and the secret absent
- **SR-002** (P1): The binding MUST NOT run JavaScript in the child between fork and exec, and MUST spawn off the event loop thread.
  - Mitigates: `threat.python-in-child` via `mitigation.rust-spawn`
  - Given many concurrent runs started from one event loop, when they all run, then every spawn completes
- **SR-003** (P1): A policy MUST reach the cage only through the presets or the versioned format, an unknown field or invalid value MUST throw PolicyError, a gap MUST throw CapabilityGapError with the gaps, and the binding MUST add no default the Rust API does not have.
  - Mitigates: `threat.silent-weakening` via `mitigation.same-semantics`
  - Given a JSON policy with an unknown field, when Policy.fromJSON is called, then PolicyError is thrown
  - Given a policy the host cannot enforce, when a Cage is made, then CapabilityGapError is thrown with the gaps
- **SR-004** (P1): Every process of a run MUST be killed when it is killed, disposed, aborted, timed out, collected, or the Node process exits.
  - Mitigates: `threat.orphaned-run` via `mitigation.end-on-release`
  - Given a running command and an AbortSignal, when the signal aborts, then its processes are dead
  - Given a running command when the Node process exits, when the process exits, then its processes are dead
- **SR-005** (P1): The package MUST be built from the tagged commit by actions pinned to full SHAs and published with npm Trusted Publishing and provenance from a protected environment, with no stored token.
  - Mitigates: `threat.wheel-tampering` via `mitigation.trusted-publishing`
  - Given the release workflow, when the workflows gate runs, then every action is SHA-pinned and the publish job uses OIDC in the npm environment with provenance
- **SR-006** (P2): Every published platform MUST run the escape subset and the shell tool example from the packed package on its CI lane, and the docs MUST claim no platform beyond them.
  - Mitigates: `threat.untested-wheel` via `mitigation.tested-wheels`
  - Given each platform lane, when the Node tests run against the installed package, then reads and writes outside the workspace, secrets and the network are refused and the example runs
- **SR-007** (P3): Spawn, wait and the reading of output MUST NOT block the event loop.
  - Mitigates: `threat.gil-starvation` via `mitigation.release-gil`
  - Given a run of one second, when a timer is due meanwhile, then it fires on time
- **SR-008** (P1): The package MUST load its native addon only from its own directory by a fixed name for the host platform, ignoring environment variables and the working directory, and MUST throw a typed error on an unsupported platform.
  - Mitigates: `threat.binary-substitution` via `mitigation.fixed-loader`
  - Given an environment variable naming another addon, when the package is imported, then the packaged addon is loaded
  - Given an unsupported platform, when the package is imported, then it throws UnsupportedError naming the platform
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: The binding's escape subset passes from the packed package on
  every platform.
- **SC-002**: The example shell tool runs caged commands end to end.

## Assumptions

- The serialised policy format is stable within a minor version.

## Out of Scope

- Bun and Deno (Node-API may work; untested, so unclaimed); browsers;
  Windows; new terminals and the proxy (as in Python, added on demand).
