"""procage: run commands caged by the operating system's sandbox.

macOS uses Seatbelt; Linux uses Landlock, seccomp and, where the host allows,
user namespaces. A policy comes from a preset or from procage's versioned
JSON format; Python never writes sandbox rules itself.

    import procage

    policy = procage.Policy.preset("agent_workspace", 3, workspace="/abs/project")
    done = procage.run(policy, "git status", shell=True, text=True)
    print(done.returncode, done.stdout, done.violations)

It reads like `subprocess.run` (`text=`, `check=`, `shell=`, `timeout=`).

A run ends, and every process it started is killed, when its `Run` is closed
or collected, or when the interpreter exits. See
https://hupe1980.github.io/procage/docs/python/ for the API and its limits.
"""

import asyncio
import atexit
import json
import os
import subprocess
import threading
import weakref
from dataclasses import dataclass, field
from importlib.metadata import PackageNotFoundError, version as _version
from typing import Any, Mapping, Sequence, Union

StrPath = Union[str, "os.PathLike[str]"]

from . import _native
from ._native import (
    AlreadySandboxedError,
    CapabilityGapError,
    Error,
    GrantError,
    Policy,
    PolicyError,
    SpawnError,
    UnsupportedError,
)

try:
    __version__ = _version("procage")
except PackageNotFoundError:  # pragma: no cover - not installed
    __version__ = "0.0.0"

__all__ = [
    "AlreadySandboxedError",
    "Cage",
    "CapabilityGapError",
    "Completed",
    "Error",
    "GrantError",
    "Policy",
    "PolicyError",
    "Run",
    "SpawnError",
    "UnsupportedError",
    "run",
    "run_async",
]

# `CapabilityGapError(message, gaps)`: the gaps as a property.
CapabilityGapError.gaps = property(  # type: ignore[attr-defined]
    lambda self: self.args[1] if len(self.args) > 1 else []
)

_live: "weakref.WeakSet[Run]" = weakref.WeakSet()
_live_lock = threading.Lock()


@atexit.register
def _end_every_run() -> None:
    with _live_lock:
        runs = list(_live)
    for r in runs:
        r.close()


class Cage:
    """A prepared policy; spawn any number of runs from it, from any thread.

    `violations=True` records what the sandbox denied (`Run.violations`).
    `relax` names relaxations to fit a host that cannot enforce everything:
    `leave-out-protect`, `leave-out-hide`, `no-unix-sockets`,
    `signals-same-user`, `no-loopback` or `waive:<class>`; the ones applied
    are in `relaxed`. `accept_spawn_snapshot=True` accepts the Linux
    approximations taken from the file system at spawn. A policy the host
    cannot enforce raises `CapabilityGapError`.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        violations: bool = False,
        relax: Sequence[str] = (),
        accept_spawn_snapshot: bool = False,
    ) -> None:
        self._native = _native.Cage(
            policy,
            violations=violations,
            relax=list(relax),
            accept_spawn_snapshot=accept_spawn_snapshot,
        )

    @property
    def relaxed(self) -> list[str]:
        """The relaxations applied, as sentences."""
        return self._native.relaxed

    def spawn(
        self,
        args: Sequence[StrPath] | str,
        *,
        shell: bool = False,
        cwd: StrPath | None = None,
        env: Mapping[str, str] | None = None,
        grants: Mapping[str, StrPath] | None = None,
        stdin: str = "null",
        stdout: str = "pipe",
        stderr: str = "pipe",
    ) -> "Run":
        """Starts `args` caged, in `cwd` or else the preset's workspace;
        with `shell=True`, `args` is one command line for `/bin/sh -c`.

        Only the variables in `env` are set explicitly; the policy decides
        which of this process's variables reach the child (`os.environ` is
        never copied). `grants` binds the policy's declared grants to paths.
        `stdin`, `stdout` and `stderr` are `"pipe"`, `"null"` or `"inherit"`.
        """
        native = self._native.spawn(
            _argv(args, shell),
            cwd=None if cwd is None else os.fspath(cwd),
            env=None if env is None else {str(k): str(v) for k, v in env.items()},
            grants=None if grants is None else {str(k): os.fspath(v) for k, v in grants.items()},
            stdin=stdin,
            stdout=stdout,
            stderr=stderr,
        )
        r = Run(native)
        with _live_lock:
            _live.add(r)
        return r


def _argv(args: Sequence[StrPath] | str, shell: bool) -> list[str]:
    if shell:
        if not isinstance(args, str):
            raise TypeError("with shell=True, args is one command line (a str)")
        return ["/bin/sh", "-c", args]
    if isinstance(args, str):
        raise TypeError("args is a list; pass shell=True to run a command line")
    return [os.fspath(a) for a in args]


class Run:
    """A caged command. Closing or collecting it ends the run: the child and
    every process it started are killed."""

    def __init__(self, native: Any) -> None:
        self._native = native
        self.returncode: int | None = None

    @property
    def pid(self) -> int:
        return self._native.pid

    def poll(self) -> int | None:
        """The exit code once the child has exited (minus the signal number
        when a signal ended it), else `None`."""
        if self.returncode is None:
            self.returncode = self._native.poll()
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        """Waits for the exit; `TimeoutError` after `timeout` seconds."""
        if self.returncode is None:
            self.returncode = self._native.wait(timeout)
        return self.returncode

    async def wait_async(self, timeout: float | None = None) -> int:
        """`wait` for asyncio, on a worker thread. Cancelling the awaiting
        task ends the run."""
        return await _ending_on_cancel(self, asyncio.to_thread(self.wait, timeout))

    def communicate(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes | None, bytes | None]:
        """Writes `input`, reads standard output and error to the end and
        waits; `(stdout, stderr)`, `None` for a stream that is not a pipe."""
        out, err = self._native.communicate(input, timeout)
        self.returncode = self._native.poll()
        return out, err

    async def communicate_async(
        self, input: bytes | None = None, timeout: float | None = None
    ) -> tuple[bytes | None, bytes | None]:
        """`communicate` for asyncio, on a worker thread. Cancelling the
        awaiting task ends the run."""
        return await _ending_on_cancel(self, asyncio.to_thread(self.communicate, input, timeout))

    def kill(self) -> None:
        """Ends the run now: kills the child and every process of the run."""
        self._native.kill()

    def violations(self) -> list[dict[str, Any]]:
        """What the sandbox denied, when the cage records violations."""
        return self._native.violations()

    def receipt(self) -> dict[str, Any] | None:
        """How the run was caged, once the child has exited (this ends the
        run); `None` while it runs."""
        text = self._native.receipt_json()
        return None if text is None else json.loads(text)

    def close(self) -> None:
        """Ends the run and releases the handle."""
        self._native.close()

    def __enter__(self) -> "Run":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


async def _ending_on_cancel(r: "Run", work: Any) -> Any:
    """Awaits `work`; a cancelled task ends the run, so the worker thread
    returns and no caged process outlives the cancelled call."""
    task = asyncio.ensure_future(work)
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        r.kill()
        await asyncio.gather(task, return_exceptions=True)
        raise


@dataclass
class Completed:
    """A finished run: its exit code, output (`str` with `text=True`),
    violations and receipt."""

    args: list[str]
    returncode: int
    stdout: bytes | str | None
    stderr: bytes | str | None
    violations: list[dict[str, Any]] = field(default_factory=list)
    receipt: dict[str, Any] | None = None

    def check_returncode(self) -> None:
        """Raises `subprocess.CalledProcessError` for a non-zero exit."""
        if self.returncode:
            raise subprocess.CalledProcessError(
                self.returncode, self.args, self.stdout, self.stderr
            )


def _prepare(
    policy: Policy | Cage, input: bytes | str | None, spawn: dict[str, Any]
) -> tuple[Cage, bytes | None]:
    cage = policy if isinstance(policy, Cage) else Cage(policy)
    if isinstance(input, str):
        input = input.encode()
    if input is not None:
        spawn.setdefault("stdin", "pipe")
    return cage, input


def _completed(
    r: Run,
    argv: list[str],
    out: bytes | None,
    err: bytes | None,
    text: bool,
    check: bool,
) -> Completed:
    done = Completed(
        args=argv,
        returncode=r.wait(),
        stdout=out if not text or out is None else out.decode(errors="replace"),
        stderr=err if not text or err is None else err.decode(errors="replace"),
        violations=r.violations(),
        receipt=r.receipt(),
    )
    if check:
        done.check_returncode()
    return done


def run(
    policy: Policy | Cage,
    args: Sequence[StrPath] | str,
    *,
    input: bytes | str | None = None,
    timeout: float | None = None,
    text: bool = False,
    check: bool = False,
    shell: bool = False,
    **spawn: Any,
) -> Completed:
    """Runs `args` caged to the end, like `subprocess.run`: `text=True`
    decodes the output (UTF-8), `check=True` raises
    `subprocess.CalledProcessError` for a non-zero exit, `shell=True` runs
    one command line with `/bin/sh -c`. On a timeout the run is ended and
    `TimeoutError` raised. Other keywords go to `Cage.spawn`."""
    cage, data = _prepare(policy, input, spawn)
    with cage.spawn(args, shell=shell, **spawn) as r:
        try:
            out, err = r.communicate(data, timeout)
        except TimeoutError:
            r.kill()
            raise
        return _completed(r, _argv(args, shell), out, err, text, check)


async def run_async(
    policy: Policy | Cage,
    args: Sequence[StrPath] | str,
    *,
    input: bytes | str | None = None,
    timeout: float | None = None,
    text: bool = False,
    check: bool = False,
    shell: bool = False,
    **spawn: Any,
) -> Completed:
    """`run` for asyncio: the same keywords and result. The blocking parts
    run on worker threads with the interpreter lock released; cancelling
    the awaiting task ends the run."""
    cage, data = _prepare(policy, input, spawn)
    r = await asyncio.to_thread(cage.spawn, args, shell=shell, **spawn)
    with r:
        try:
            out, err = await r.communicate_async(data, timeout)
        except TimeoutError:
            r.kill()
            raise
        return await asyncio.to_thread(_completed, r, _argv(args, shell), out, err, text, check)
