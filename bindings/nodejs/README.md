# procage

Run commands caged by the operating system's sandbox, from Node.js. On
macOS procage applies Seatbelt profiles through libsandbox (no
`sandbox-exec`); on Linux it uses Landlock, seccomp and, where the host
allows, user namespaces. This package binds the Rust crate
[`procage`](https://crates.io/crates/procage): the same presets, the same
checks, the same refusals.

```sh
npm install procage
```

macOS on Apple silicon and Linux x64 and arm64 (glibc 2.28 or later),
Node.js 22.12 or later. TypeScript declarations included; no build step,
no dependencies. Every platform runs the binding's escape tests in CI from
the packed package.

```ts
import { Policy, run } from "procage";

const policy = Policy.preset("agent_workspace", 3, { workspace: "/abs/project" });
const done = await run(policy, "npm test", { shell: true, timeout: 600_000 });
console.log(done.exitCode, done.stdout, done.violations);
```

`agent_workspace` lets the command read and write the workspace (its
working directory), run the system's programs and nothing else: no
network, no secrets of the user's home, no writes outside the workspace.
Other presets: `minimal`, `agent_readonly`, `build` (adds loopback
networking; macOS only). Any policy can also be loaded from procage's
versioned JSON format with `Policy.fromJSON`.

## `run`

```ts
const done = await run(policyOrCage, ["git", "status"], {
  cwd,            // default: the preset's workspace
  env: { CI: 1 }, // the only variables set explicitly; process.env is never copied
  input: "…",     // written to standard input
  timeout: 60_000,          // ms; then the run is ended: TimeoutError
  signal: controller.signal, // aborting ends the run
  check: true,              // non-zero exit: ExitError (with .result)
  encoding: "buffer",       // default "utf8"
});
// { command, exitCode, signal, stdout, stderr, violations, receipt }
```

A string command needs `shell: true` (`/bin/sh -c`). Paths may be strings
or `file:` URLs. Spawning, waiting and reading happen on the thread pool,
so many runs proceed at once and the event loop stays free.

## Cages and runs

```ts
const cage = new Cage(policy, { violations: true }); // reuse for many runs
await using run = await cage.spawn(["node", "tool.js"]); // Node 24+: ends the run at the block's end
const { exitCode, stdout } = await run.output();
```

`Run` has `pid`, `wait()`, `output({ input, timeout })`, `kill()`,
`violations()` and `receipt()`. A run ends, and every process it started is
killed, on `kill()`, `close()`, disposal, an aborted signal, a timeout,
garbage collection, or the exit of the Node process.

## Errors

All extend `ProcageError`: `PolicyError`, `CapabilityGapError`,
`UnsupportedError`, `AlreadySandboxedError` (the caller is itself
sandboxed, macOS), `GrantError`, `SpawnError`, `TimeoutError`, `ExitError`.
When the host cannot enforce part of a policy, `CapabilityGapError` names
the option that would accept each gap, for example on Linux:

```text
hd-secrets: new Cage(policy, { acceptSpawnSnapshot: true }) accepts it
hd-trust-handoff: new Cage(policy, { relax: ["waive:trust-handoff"] }) accepts it
```

Nothing is accepted unless you pass it.

## An agent's shell tool

[`examples/shell-tool.js`](https://github.com/hupe1980/procage/blob/main/bindings/nodejs/examples/shell-tool.js)
is one function, `shell(command, workspace)`, for an agent or an MCP
server: it runs the command caged and returns the exit code, the output
and what the sandbox refused.

Documentation: <https://hupe1980.github.io/procage/docs/nodejs/>. Read the
[threat model](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md)
for what an OS sandbox does and does not stop.

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
