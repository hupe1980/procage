# Implementation Plan: Python bindings

**Branch**: `020-python` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Measured before planning

- PyO3 0.30 with `abi3-py311` builds under `unsafe_code = "forbid"` (the
  macros need no `unsafe` of ours) and as a plain `cargo build`, so the
  crate can be a workspace member; maturin 1.x builds a
  `cp311-abi3-macosx_11_0_arm64` wheel from it (prototype, macOS 26.6.2).

## Layout

`bindings/python`, one directory, as maturin expects (`pyproject.toml`
beside the crate's `Cargo.toml`):

- `Cargo.toml`, `src/lib.rs`: crate `procage-py`, a `cdylib` named
  `_native`, `publish = false`, `[lib] test = false, doctest = false` (no
  libpython needed by `cargo test --workspace`), workspace lints (unsafe
  forbidden), a workspace member. Depends on `procage` and
  `procage-policy` (`serde`).
- `pyproject.toml` (maturin backend, `python-source = "python"`,
  `module-name = "procage._native"`, version from the crate),
  `python/procage/__init__.py` (the public API), `tests/` (stdlib
  `unittest`, no test dependency), `examples/shell_tool.py`, `wheel.sh`.

*Decision (implementation):* a first cut put the crate in
`bindings/python` and the Python side in `bindings/python` (the
name-reservation folder), joined by `manifest-path`. Checked against
maturin's project layout and Rust workspaces with Python bindings
(tokenizers and OpenDAL: `bindings/python`; delta-rs: `python/`), the
binding is one self-contained directory; `packaging/` named a reservation
stub, not a binding. `packaging/npm` stays as the npm name reservation.

## Native module (`_native`)

| Python | Rust |
|---|---|
| `Policy.preset(name, version, workspace=None)` | `presets::{minimal, agent_readonly, agent_workspace, build}::v1..v3`; an unknown name or version, or a missing or relative workspace: `PolicyError` |
| `Policy.from_json(text)`, `policy.to_json()` | the versioned serde format (unknown fields refused) |
| `Cage(policy, violations=False, relax=(), accept_spawn_snapshot=False)` | `CageOptions::default().with_lower(..)`, `.with_violations()`; with `relax`: `Cage::fit` with `Relax` named relaxations (`leave-out-protect`, `leave-out-hide`, `no-unix-sockets`, `signals-same-user`, `no-loopback`, `waive:<class>`); the relaxations taken are on `cage.relaxed` |
| `cage.spawn(args, cwd=None, env=None, grants=None, stdin=, stdout=, stderr=)` | `std::process::Command` with exactly `env` as explicit variables (never `os.environ`), `Grants::bind`, `Stdio::{piped, null, inherit}`; the interpreter lock is released for the spawn |
| `Run.pid`, `poll()`, `wait(timeout)`, `kill()` | `try_wait` polled with the lock released and the handle's mutex held only per poll, so `kill` (`kill_all`) from another thread gets through |
| `run.communicate(input=None, timeout=None)` | the pipes taken out of the handle, written and read on threads with the lock released |
| `run.violations()` | `Child::violations()` as dicts (`pid`, `process`, `operation`, `target`, `denied_by`, `repeats`, `message`) |
| `run.receipt()` | `Child::receipt()` as JSON, parsed in Python; `None` while running |
| dropping a `Run` | dropping the `Child`: the run ends |

Errors: `procage.Error` and its subclasses `PolicyError`,
`CapabilityGapError` (`.gaps`: dicts with `construct`, `target`, `kind`,
`subject`), `UnsupportedError`, `AlreadySandboxedError`, `GrantError`,
`SpawnError`; the message is the Rust `Display`. `TimeoutError` (builtin)
for `wait` and `communicate` timeouts.

The child sequence is the Rust one; the binding registers no hook that
runs in the child, and since procage forks through libc, Python's at-fork
handlers do not run either (FR-003).

## Python package

- `procage.run(policy_or_cage, args, input=None, timeout=None, **spawn)`
  returns `Completed(returncode, stdout, stderr, violations, receipt)`.
- asyncio: `run_async`, `Run.communicate_async`, `Run.wait_async` await
  the blocking calls on worker threads (`asyncio.to_thread`); cancelling
  the awaiting task kills the run (a cancelled tool call leaves no caged
  process).
- An `atexit` hook kills every run still alive (`weakref.WeakSet`).
- `Policy`, `Cage`, `Run`, exceptions re-exported; type hints in a
  `py.typed` package with an `_native.pyi` stub.

## Wheels and CI

- Build: `maturin build --release --strip`; Linux with
  `--zig --compatibility manylinux_2_28` for `x86_64` and `aarch64`
  (tools from pinned PyPI versions in a virtual environment; no third-party
  action). macOS arm64 only (spec, Clarifications).
- CI: on each facts lane (macos-26, xcode-27, ubuntu-24.04 T1/T2,
  ubuntu-24.04-arm T1/T2, ubuntu-26.04 T1/T2) a step builds the wheel as
  the release does, installs it in a fresh virtual environment and runs
  `python -m unittest` and the example.
- Release: a `wheels` job (macOS arm64, Linux x86_64 and aarch64) builds
  and uploads artifacts; a `pypi` job in the protected `pypi` environment
  downloads them and publishes with `pypa/gh-action-pypi-publish` (OIDC,
  full-SHA pins). PyPI's trusted publisher for `procage` must name
  `release.yml` and the environment `pypi` (a one-time setting on PyPI).
- `just python`: build, install into a scratch venv, run the tests; part of
  `just ci`'s neighbours (`ci-all`), not of `ci` (it needs maturin).

## Tests (`bindings/python/tests`, the escape subset)

On the kernel through the wheel: a read and a write outside the workspace
are refused; a secret of the `secrets` class is refused; the network is
refused; a variable in `os.environ` does not reach the child while `env=`
does; an unknown JSON field and an invalid preset raise `PolicyError`; a
gap raises `CapabilityGapError` with gaps (Linux: `build::v3`, no loopback;
macOS: a policy with a Linux layer, an approximation not accepted);
deleting a running `Run` and interpreter exit (a subprocess interpreter)
kill its processes; spawns from several Python threads complete; another
thread runs while one waits; violations name the denied path (macOS) or
call (Linux); the receipt parses. The example runs a command and prints
its output.

## Decisions (implementation)

- **One script.** `bindings/python/wheel.sh` builds the wheel as the
  release does (`build OUT`), installs it fresh and runs the tests and the
  example (`test DIR`); `just python`, CI and the release use it, so CI
  tests what the release ships. maturin 1.16.0 and ziglang 0.17.0 are
  pinned. maturin finds zig through the tools' Python, so their virtual
  environment goes first on `PATH`.
- **Linux in a container.** The test image has no `venv`: `just
  python-linux` builds as root after installing it, then runs the tests as
  uid 65534 (`setpriv`), as the T1 and T2 lanes do.
- **Python on CI.** `actions/setup-python` (full-SHA pin, no cache) gives
  CPython 3.13 on every lane: the macOS images' default `python3` may be
  older than 3.11.
- **Defaults.** `stdin` defaults to `"null"` (a caged child reads no
  terminal unless asked), `stdout` and `stderr` to `"pipe"`.
- **Shapes.** Violations and gaps are built as dicts in Rust (neither type
  serialises); the receipt crosses as its JSON form. `CapabilityGapError`
  carries `(message, gaps)`, and the package adds the `gaps` property.
- **Developer experience.** `run` reads like `subprocess.run` (`text=`,
  `check=` with `CalledProcessError`, `shell=`, `input=` as `str`), every
  path may be `os.PathLike`, a typed stub (`_native.pyi`, `py.typed`)
  ships, and each gap names the `Cage` option that would accept it (from
  procage's own tables: the spawn snapshot, or the relaxation that answers
  the construct) in `gaps[i]["accept"]` and in the message. Nothing is
  accepted without the option, so no default differs from Rust (SR-003).
  A preset remembers its workspace (`policy.workspace`), the default
  working directory of its runs, so a call needs no `cwd=`; the working
  directory confines nothing. No `from __future__ import annotations`: every annotation used is valid
  at runtime on 3.11.
- **Measured (macOS 26.6.2, Linux 7.0 container T1 and T2).** 22 tests
  pass from the built wheel on each.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | No binding default differs from Rust; unknown fields refused; gaps raise | PASS |
| II | Policies only through presets and the versioned format | PASS |
| III | The escape subset runs from the built wheel on every wheel lane | PASS |
| IV | No `unsafe`; no Python in the child | PASS |
| V | Only `env=` is passed explicitly; runs end on release and at exit | PASS |
| VI | No private interface added | PASS |
| VII | No global state in Rust; the at-exit registry is Python's; no async runtime | PASS |

**Remaining gaps**: no Intel macOS wheel; new terminals and the proxy are
not exposed; a process killed with SIGKILL skips `atexit` (Linux's death
signal still ends the child; macOS runs end only with the parent's exit
handling).
