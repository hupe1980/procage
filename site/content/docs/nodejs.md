+++
title = "Node.js: the procage package"
description = "npm install procage: presets or JSON policies, a cage, caged runs with promises, AbortSignal and timeouts, violations and receipts, typed errors that say how to fix a gap."
weight = 81

[extra]
group = "Guides"
nav = "Node.js"
+++

The `procage` package on npm binds the Rust crate: the same presets, the same lowering, the same refusals. One package carries prebuilt addons for macOS on Apple silicon and Linux x64 and arm64 (glibc 2.28 or later) and loads the one for the host, from its own directory only; Node.js 22.12 or later; TypeScript declarations included. Each CI lane builds and packs the package as the release does and runs the binding's escape tests from the packed tarball, on Node 22 (Linux) and 26 (macOS).

```ts
import { Policy, run } from "procage";

const policy = Policy.preset("agent_workspace", 3, { workspace: "/abs/project" });
const done = await run(policy, "npm test", { shell: true, timeout: 600_000 });
console.log(done.exitCode, done.stdout, done.violations);
```

## Policies and cages

- `Policy.preset(name, version, { workspace })`: `minimal`, `agent_readonly`, `agent_workspace`, `build`, versions 1 to 3 (use 3). The workspace becomes the runs' working directory. See [presets](@/docs/presets.md).
- `Policy.fromJSON(doc)` and `policy.toJSON()`: the versioned serialised format; unknown fields are refused.
- `new Cage(policy, { violations, relax, acceptSpawnSnapshot, allow })`: a policy the host cannot enforce throws `CapabilityGapError`, whose `gaps` name each construct and, in `accept`, the option that would accept it; the message lists them. Nothing is accepted unless passed. `allow` accepts approximations by construct name, such as `allow: ["exec-program"]` for `"exec": "program"` on Linux (see [which exec setting](@/docs/policies.md#which-exec-setting)). See [fitting](@/docs/fitting.md).

## Runs

`run(policyOrCage, command, options)` resolves to `{ command, exitCode, signal, stdout, stderr, violations, receipt }`. `command` is an array, or a string with `shell: true`. Options: `cwd`, `env` (the only variables set explicitly; `process.env` is never copied), `grants`, `input`, `timeout` (milliseconds; the run is ended and `TimeoutError` thrown), `signal` (an `AbortSignal`; aborting ends the run), `check` (`ExitError` on a non-zero exit), `encoding` (`"utf8"` or `"buffer"`).

`cage.spawn(command, options)` resolves to a `Run`: `pid`, `wait()`, `output({ input, timeout })`, `kill()`, `violations()` (see [violations](@/docs/violations.md)), `receipt()` (see [receipts](@/docs/receipts.md)), and `Symbol.dispose`/`Symbol.asyncDispose`, so `await using run = await cage.spawn(…)` ends the run at the end of the block (the syntax needs Node 24).

Spawning, waiting and reading run on the libuv thread pool: many runs proceed at once and the event loop stays free. No JavaScript runs in the child; the child sequence is procage's own system calls. A run ends, and every process it started is killed, on `kill()`, `close()`, disposal, an aborted signal, a timeout, garbage collection of the `Run`, or the exit of the Node process. A process killed with `SIGKILL` runs no exit hook: on Linux the child still dies with its parent; on macOS it does not.

## Running Node inside the cage

The presets let the child run the system's programs (`/usr`, `/bin`, Homebrew). A Node installed elsewhere (nvm, Volta, a CI tool cache) needs an exec rule for its directory: add `{ access: "exec", target: { subpath: path.dirname(fs.realpathSync(process.execPath)) } }` to the preset's `toJSON().fs` and load it with `Policy.fromJSON`. Without it the spawn is refused with `SpawnError` (`Operation not permitted`).

## Errors

All extend `ProcageError`: `PolicyError`, `CapabilityGapError` (`.gaps`), `UnsupportedError` (also: no addon for this platform), `AlreadySandboxedError`, `GrantError`, `SpawnError`, `TimeoutError` and `ExitError` (both with `.result`).

## A shell tool for agents

[`bindings/nodejs/examples/shell-tool.js`](https://github.com/hupe1980/procage/blob/main/bindings/nodejs/examples/shell-tool.js) is one function, `shell(command, workspace)`, for an agent or an MCP server: it runs a command line caged in a workspace and returns its exit code, output and refusals. CI runs it on every lane.

Not in the package yet: new terminals, the egress proxy, `explain` and `suggest`; Bun and Deno are untested.
