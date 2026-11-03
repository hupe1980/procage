# procage

Run commands caged by the operating system's sandbox, from Python. On macOS
procage applies Seatbelt profiles through libsandbox (no `sandbox-exec`); on
Linux it uses Landlock, seccomp and, where the host allows, user namespaces.
This package binds the Rust crate [`procage`](https://crates.io/crates/procage):
the same presets, the same checks, the same refusals.

```sh
pip install procage
```

Wheels: macOS on Apple silicon, Linux x86_64 and aarch64 (manylinux_2_28),
CPython 3.11 and later. Every wheel platform runs the binding's escape tests
in CI.

```python
import procage

policy = procage.Policy.preset("agent_workspace", 3, workspace="/abs/project")
done = procage.run(policy, "make test", shell=True, text=True, timeout=600)
print(done.returncode, done.stdout)
```

A preset's runs start in its workspace unless `cwd=` says otherwise.
`procage.run` reads like `subprocess.run`: `text=`, `check=` (raises
`subprocess.CalledProcessError`), `shell=`, `input=`, `timeout=`; paths may
be `pathlib.Path`.

`agent_workspace` lets the command read and write the workspace, run the
system's programs and nothing else: no network, no secrets of the user's
home, no writes outside the workspace. Other presets: `minimal`,
`agent_readonly`, `build` (adds loopback networking; macOS only). Any
policy can also be loaded from procage's versioned JSON format with
`Policy.from_json`.

## Runs

```python
cage = procage.Cage(policy, violations=True)       # reuse for many runs
with cage.spawn(["python3", "tool.py"], env={"MODE": "ci"}) as run:
    out, err = run.communicate(timeout=60)
    print(run.returncode, run.violations())
```

- Only the variables in `env=` are set explicitly; the policy decides which
  of your process's variables reach the child. `os.environ` is never
  copied.
- `stdin`, `stdout` and `stderr` are `"pipe"`, `"null"` (stdin's default)
  or `"inherit"`.
- `Run.poll()`, `wait(timeout)`, `await wait_async()`, `communicate()`,
  `kill()`, `violations()` and `receipt()`. Blocking calls release the
  interpreter lock.
- A run ends, and every process it started is killed, when the `Run` is
  closed, garbage-collected, or the interpreter exits.

When the host cannot enforce part of a policy, `Cage` raises
`CapabilityGapError`, and its message names the option that would accept
each gap, for example on Linux:

```text
hd-secrets: Cage(..., accept_spawn_snapshot=True) accepts it
hd-trust-handoff: Cage(..., relax=["waive:trust-handoff"]) accepts it
```

Nothing is accepted unless you pass it.

## asyncio

```python
done = await procage.run_async(policy, "pytest -q", shell=True, text=True)
```

`run_async`, `Run.communicate_async` and `Run.wait_async` take the same
arguments as their blocking twins; the waiting happens on worker threads,
so many runs proceed at once. Cancelling the awaiting task ends the run:
a cancelled tool call leaves no caged process behind.

## Errors

`procage.Error` and its subclasses `PolicyError`, `CapabilityGapError`
(`.gaps` lists what the host cannot enforce), `UnsupportedError`,
`AlreadySandboxedError` (the caller is itself sandboxed, macOS),
`GrantError` and `SpawnError`.

## An agent's shell tool

[`examples/shell_tool.py`](https://github.com/hupe1980/procage/blob/main/bindings/python/examples/shell_tool.py)
is one function, `shell(command, workspace)`, that any agent framework can
register as a tool: it runs the command caged and returns the exit code,
the output and what the sandbox refused.

Documentation: <https://hupe1980.github.io/procage/docs/python/>. Read the
[threat model](https://github.com/hupe1980/procage/blob/main/crates/procage/THREAT_MODEL.md)
for what an OS sandbox does and does not stop.

Licensed under either of Apache License, Version 2.0 or MIT license at your
option.
