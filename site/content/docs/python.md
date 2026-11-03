+++
title = "Python: the procage package"
description = "pip install procage: presets or JSON policies, a cage, caged runs with pipes, violations and receipts, typed exceptions, and runs that end with their objects."
weight = 80

[extra]
group = "Guides"
nav = "Python"
+++

The `procage` package on PyPI binds the Rust crate: the same presets, the same lowering, the same refusals. Wheels exist for macOS on Apple silicon and Linux x86_64 and aarch64 (manylinux_2_28), for CPython 3.11 and later; each CI lane builds the wheel as the release does and runs the binding's escape tests from it. There is no Intel macOS wheel: procage does not test Intel Macs.

```python
import procage

ws = "/abs/project"
policy = procage.Policy.preset("agent_workspace", 3, workspace=ws)
cage = procage.Cage(policy, violations=True)
done = procage.run(cage, "make test", shell=True, text=True, timeout=600)
print(done.returncode, done.stdout, done.violations)
```

`procage.run` reads like `subprocess.run`: `text=`, `check=` (raises `subprocess.CalledProcessError`), `shell=` (`/bin/sh -c`), `input=`, `timeout=`; every path may be a `pathlib.Path`, and the package ships type information.

## Policies

- `Policy.preset(name, version, workspace=None)`: `minimal`, `agent_readonly`, `agent_workspace`, `build`, versions 1 to 3 (use 3); every preset but `minimal` needs an absolute workspace. See [presets](@/docs/presets.md).
- `Policy.from_json(text)` and `policy.to_json()`: the versioned serialised format. Unknown fields are refused, so a field written by a newer procage is never silently dropped.

Python never writes sandbox rules: a policy is a preset or a document.

## Cages

`Cage(policy, violations=False, relax=(), accept_spawn_snapshot=False)` lowers the policy for this host. A policy the host cannot enforce raises `CapabilityGapError`, whose `gaps` name each construct and, in `accept`, the option that would accept it; the message lists them (`hd-trust-handoff: Cage(..., relax=["waive:trust-handoff"]) accepts it`). Nothing is accepted unless passed. `relax` accepts named relaxations (`leave-out-protect`, `leave-out-hide`, `no-unix-sockets`, `signals-same-user`, `no-loopback`, `waive:<class>`) and applies only those the host needs; `cage.relaxed` lists them. On Linux pass `accept_spawn_snapshot=True` for the masks taken from the file system at spawn, and on tier T2 `relax=["waive:trust-handoff"]` for the workspace presets. See [fitting](@/docs/fitting.md).

## Runs

`cage.spawn(args, cwd=, env=, grants=, stdin="null", stdout="pipe", stderr="pipe")` returns a `Run`; without `cwd` a preset's run starts in its workspace (`policy.workspace`):

- `pid`, `poll()`, `wait(timeout=None)`, `await wait_async()`, `communicate(input=None, timeout=None)`, `kill()`;
- `violations()`: dicts with `pid`, `process`, `operation`, `target`, `denied_by`, `repeats` and the sentence `message` (see [violations](@/docs/violations.md));
- `receipt()`: the run's [receipt](@/docs/receipts.md) as a dict once the child has exited.

`procage.run(policy_or_cage, args, input=None, timeout=None, text=False, check=False, shell=False, **spawn)` runs to the end and returns `Completed(returncode, stdout, stderr, violations, receipt)`; on a timeout it ends the run and raises `TimeoutError`.

Only the variables in `env` are set explicitly; the policy's environment rules decide which of the calling process's variables reach the child, and `os.environ` is never copied. Spawning, waiting and reading release the interpreter lock, and no Python code runs in the child: the child sequence is procage's own system calls.

For asyncio, `await procage.run_async(...)`, `await run.communicate_async(...)` and `await run.wait_async()` take the same arguments as their blocking twins and wait on worker threads, so many runs proceed at once; cancelling the awaiting task ends the run, so a cancelled tool call leaves no caged process behind.

A run ends, and every process it started is killed, when the `Run` is closed (`with` or `close()`), garbage-collected, or the interpreter exits (an `atexit` hook). A process killed with `SIGKILL` runs no hook: on Linux the child still dies with its parent; on macOS it does not.

## Errors

`procage.Error` and its subclasses: `PolicyError` (a document, preset or relaxation), `CapabilityGapError` (`.gaps`), `UnsupportedError`, `AlreadySandboxedError` (the caller is itself sandboxed, macOS), `GrantError`, `SpawnError` (anything else, including the child step that failed). Messages are procage's own.

## A shell tool for agents

[`bindings/python/examples/shell_tool.py`](https://github.com/hupe1980/procage/blob/main/bindings/python/examples/shell_tool.py) is one function, `shell(command, workspace)`, that runs a command line caged in a workspace and returns its exit code, output and refusals: register it as a tool with any framework that calls Python functions. CI runs it on every wheel lane.

Not in the package yet: new terminals (`Tty::NewPty`), the egress proxy, `explain` and `suggest`; each is added when a consumer asks.
