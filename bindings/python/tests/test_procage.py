"""The binding on the kernel: the escape subset and the API, run from the
installed wheel with the standard library only (python -m unittest)."""

import gc
import json
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from pathlib import Path

import procage

MACOS = sys.platform == "darwin"


def workspace() -> str:
    return os.path.realpath(tempfile.mkdtemp(prefix="procage-py-"))


def cage(policy: procage.Policy, **kw) -> procage.Cage:
    """A cage as a Linux user makes one: the spawn-time approximations
    accepted, and the trust-handoff waiver where the tier needs it (fit
    relaxes only what the host cannot enforce)."""
    if not MACOS:
        kw.setdefault("accept_spawn_snapshot", True)
        kw.setdefault("relax", ["waive:trust-handoff"])
    return procage.Cage(policy, **kw)


def sh(c: procage.Cage, script: str, **kw) -> procage.Completed:
    return procage.run(c, ["/bin/sh", "-c", script], timeout=60, **kw)


def gone(pid: int, within: float = 5.0) -> bool:
    end = time.monotonic() + within
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.02)
    return False


class EscapeSubset(unittest.TestCase):
    """What the cage refuses, observed through the binding."""

    def setUp(self) -> None:
        self.ws = workspace()
        self.outside = workspace()
        Path(self.outside, "f").write_text("outside")
        self.cage = cage(procage.Policy.preset("agent_workspace", 3, workspace=self.ws))

    def test_the_workspace_is_usable(self) -> None:
        done = sh(self.cage, "echo hi > f && cat f", cwd=self.ws)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, b"hi\n")

    def test_reading_outside_the_workspace_is_refused(self) -> None:
        done = sh(self.cage, f"cat '{self.outside}/f'", cwd=self.ws)
        self.assertNotEqual(done.returncode, 0)
        self.assertNotIn(b"outside", done.stdout)

    def test_writing_outside_the_workspace_is_refused(self) -> None:
        done = sh(self.cage, f"echo x > '{self.outside}/g'", cwd=self.ws)
        self.assertNotEqual(done.returncode, 0)
        self.assertFalse(Path(self.outside, "g").exists())

    def test_a_secret_is_refused(self) -> None:
        if MACOS:
            # Every account has it; listing it reads nothing.
            target = Path.home() / "Library/Keychains"
            self.assertTrue(target.is_dir())
            done = sh(self.cage, f"ls '{target}'", cwd=self.ws)
            self.assertNotEqual(done.returncode, 0)
            return
        secret = Path.home() / ".aws" / f"procage-canary-{os.getpid()}"
        secret.parent.mkdir(exist_ok=True)
        secret.write_text("key")
        try:
            done = sh(self.cage, f"cat '{secret}'", cwd=self.ws)
            self.assertNotEqual(done.returncode, 0)
            self.assertNotIn(b"key", done.stdout)
        finally:
            secret.unlink()

    def test_the_network_is_refused(self) -> None:
        script = "import socket; socket.create_connection(('1.1.1.1', 53), 3)"
        done = procage.run(self.cage, ["/usr/bin/python3", "-c", script], cwd=self.ws, timeout=60)
        self.assertNotEqual(done.returncode, 0)
        self.assertRegex(done.stderr, rb"PermissionError|Operation not permitted|Permission denied")

    def test_the_callers_environment_is_not_copied(self) -> None:
        os.environ["PROCAGE_PY_SECRET"] = "s3cret"
        try:
            done = procage.run(self.cage, ["/usr/bin/env"], env={"VISIBLE": "1"}, cwd=self.ws)
        finally:
            del os.environ["PROCAGE_PY_SECRET"]
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(b"s3cret", done.stdout)
        self.assertIn(b"VISIBLE=1", done.stdout)


class Policies(unittest.TestCase):
    def test_an_unknown_field_is_refused(self) -> None:
        with self.assertRaises(procage.PolicyError):
            procage.Policy.from_json('{"version": 1, "bogus": 1}')

    def test_presets_need_a_known_name_and_an_absolute_workspace(self) -> None:
        for args in (("nope", 3, "/tmp"), ("agent_workspace", 9, "/tmp"), ("agent_workspace", 3, "rel")):
            with self.assertRaises(procage.PolicyError, msg=str(args)):
                procage.Policy.preset(*args)
        with self.assertRaises(procage.PolicyError):
            procage.Policy.preset("agent_workspace", 3)

    def test_json_round_trips(self) -> None:
        p = procage.Policy.preset("agent_readonly", 3, workspace=workspace())
        again = procage.Policy.from_json(p.to_json())
        self.assertEqual(json.loads(again.to_json()), json.loads(p.to_json()))

    def test_a_gap_raises_with_the_gaps(self) -> None:
        if MACOS:
            doc = json.loads(procage.Policy.preset("minimal", 3).to_json())
            doc["linux"] = {"syscalls_deny": [], "landlock_extra": []}
            policy, construct = procage.Policy.from_json(json.dumps(doc)), "linux-layer"
        else:
            policy, construct = procage.Policy.preset("build", 3, workspace=workspace()), "net-loopback"
        with self.assertRaises(procage.CapabilityGapError) as caught:
            procage.Cage(policy, accept_spawn_snapshot=True)
        self.assertIsInstance(caught.exception, procage.Error)
        self.assertIn(construct, [g["construct"] for g in caught.exception.gaps])

    def test_a_gap_says_which_option_accepts_it(self) -> None:
        # The data classes are approximations a caller accepts by name; the
        # message says how, and nothing is accepted without it.
        doc = json.loads(procage.Policy.preset("agent_workspace", 3, workspace=workspace()).to_json())
        policy = procage.Policy.from_json(json.dumps(doc))
        if MACOS:
            doc["linux"] = {"syscalls_deny": [], "landlock_extra": []}
            with self.assertRaises(procage.CapabilityGapError) as caught:
                procage.Cage(procage.Policy.from_json(json.dumps(doc)))
            gap = caught.exception.gaps[0]
            self.assertEqual(gap["accept"], [])
            return
        with self.assertRaises(procage.CapabilityGapError) as caught:
            procage.Cage(policy)
        hinted = [g for g in caught.exception.gaps if g["accept"]]
        self.assertTrue(hinted, caught.exception.gaps)
        self.assertIn("accepts it", str(caught.exception))

    def test_a_relaxation_name_is_checked(self) -> None:
        with self.assertRaises(procage.PolicyError):
            procage.Cage(procage.Policy.preset("minimal", 3), relax=["waive:nope"])


class Lifetime(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = workspace()
        self.cage = cage(procage.Policy.preset("agent_workspace", 3, workspace=self.ws))

    def test_collecting_a_run_kills_it(self) -> None:
        r = self.cage.spawn(["/bin/sleep", "300"], cwd=self.ws)
        pid = r.pid
        del r
        gc.collect()
        self.assertTrue(gone(pid))

    def test_interpreter_exit_kills_live_runs(self) -> None:
        script = textwrap.dedent(
            f"""
            import procage, sys
            cage = procage.Cage(
                procage.Policy.preset("agent_workspace", 3, workspace={self.ws!r}),
                {'' if MACOS else 'accept_spawn_snapshot=True, relax=["waive:trust-handoff"],'}
            )
            run = cage.spawn(["/bin/sleep", "300"], cwd={self.ws!r})
            print(run.pid, flush=True)
            """
        )
        out = subprocess.run([sys.executable, "-c", script], capture_output=True, timeout=60, check=True)
        self.assertTrue(gone(int(out.stdout)), out.stderr)

    def test_kill_ends_a_run(self) -> None:
        r = self.cage.spawn(["/bin/sleep", "300"], cwd=self.ws)
        r.kill()
        self.assertLess(r.wait(timeout=5), 0)
        self.assertTrue(gone(r.pid))

    def test_wait_times_out(self) -> None:
        with self.cage.spawn(["/bin/sleep", "300"], cwd=self.ws) as r:
            with self.assertRaises(TimeoutError):
                r.wait(timeout=0.2)


class Concurrency(unittest.TestCase):
    def setUp(self) -> None:
        self.ws = workspace()
        self.cage = cage(procage.Policy.preset("agent_workspace", 3, workspace=self.ws))

    def test_spawns_from_several_threads_complete(self) -> None:
        errors: list[BaseException] = []

        def work() -> None:
            try:
                for _ in range(20):
                    done = procage.run(self.cage, ["/bin/echo", "ok"], cwd=self.ws, timeout=60)
                    assert done.returncode == 0 and done.stdout == b"ok\n", done
            except BaseException as e:  # noqa: BLE001 - reported below
                errors.append(e)

        threads = [threading.Thread(target=work) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])

    def test_waiting_releases_the_interpreter(self) -> None:
        r = self.cage.spawn(["/bin/sleep", "1"], cwd=self.ws)
        ticks = 0
        waiter = threading.Thread(target=r.wait)
        waiter.start()
        while waiter.is_alive():
            ticks += 1
            time.sleep(0.001)
        self.assertGreater(ticks, 100)

    def test_wait_async(self) -> None:
        import asyncio

        r = self.cage.spawn(["/bin/sh", "-c", "exit 3"], cwd=self.ws)
        self.assertEqual(asyncio.run(r.wait_async(timeout=30)), 3)

    def test_run_async_runs_concurrently(self) -> None:
        import asyncio

        async def both() -> list[procage.Completed]:
            return await asyncio.gather(
                *(procage.run_async(self.cage, f"sleep 1; echo {i}", shell=True, cwd=self.ws, text=True) for i in range(4))
            )

        start = time.monotonic()
        done = asyncio.run(both())
        self.assertLess(time.monotonic() - start, 3.5)
        self.assertEqual([d.stdout for d in done], [f"{i}\n" for i in range(4)])

    def test_cancelling_run_async_ends_the_run(self) -> None:
        import asyncio

        marker = Path(self.ws, "pid")

        async def cancel() -> int:
            task = asyncio.ensure_future(
                procage.run_async(self.cage, f"echo $$ > '{marker}'; exec sleep 300", shell=True, cwd=self.ws)
            )
            while not marker.exists() or not marker.read_text().strip():
                await asyncio.sleep(0.02)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            return int(marker.read_text())

        self.assertTrue(gone(asyncio.run(cancel())))


class LikeSubprocess(unittest.TestCase):
    """`run` reads like subprocess.run."""

    def setUp(self) -> None:
        self.ws = Path(workspace())
        self.cage = cage(procage.Policy.preset("agent_workspace", 3, workspace=self.ws))

    def test_text_shell_and_paths(self) -> None:
        done = procage.run(self.cage, "echo $((6*7))", shell=True, cwd=self.ws, text=True)
        self.assertEqual(done.stdout, "42\n")
        done = procage.run(self.cage, [Path("/bin/cat")], input="in", cwd=self.ws, text=True)
        self.assertEqual(done.stdout, "in")

    def test_check_raises_called_process_error(self) -> None:
        with self.assertRaises(subprocess.CalledProcessError) as caught:
            procage.run(self.cage, "exit 7", shell=True, cwd=self.ws, check=True)
        self.assertEqual(caught.exception.returncode, 7)

    def test_a_preset_runs_in_its_workspace(self) -> None:
        done = procage.run(self.cage, "pwd", shell=True, text=True)
        self.assertEqual(done.stdout.strip(), str(self.ws))
        self.assertEqual(procage.Policy.preset("minimal", 3).workspace, None)

    def test_args_and_shell_must_agree(self) -> None:
        with self.assertRaises(TypeError):
            procage.run(self.cage, "echo hi", cwd=self.ws)
        with self.assertRaises(TypeError):
            procage.run(self.cage, ["echo", "hi"], shell=True, cwd=self.ws)


class Records(unittest.TestCase):
    def test_violations_name_what_was_denied(self) -> None:
        ws, outside = workspace(), workspace()
        Path(outside, "f").write_text("x")
        c = cage(procage.Policy.preset("agent_workspace", 3, workspace=ws), violations=True)
        if MACOS:
            done = sh(c, f"cat '{outside}/f'", cwd=ws)
            targets = [v["target"] for v in done.violations]
            self.assertIn(f"{outside}/f", targets, done.violations)
        else:
            # Linux reports refused system calls: leaving the run's session.
            done = procage.run(c, ["/usr/bin/python3", "-c", "import os; os.setsid()"], cwd=ws, timeout=60)
            self.assertIn("setsid", [v["operation"] for v in done.violations], done.violations)
        self.assertTrue(all(v["message"] for v in done.violations))

    def test_the_receipt_parses(self) -> None:
        ws = workspace()
        done = procage.run(cage(procage.Policy.preset("agent_workspace", 3, workspace=ws)), ["/usr/bin/true"], cwd=ws)
        self.assertEqual(done.returncode, 0)
        self.assertIn("backend", done.receipt)

    def test_an_undeclared_grant_is_refused(self) -> None:
        ws = workspace()
        c = cage(procage.Policy.preset("agent_workspace", 3, workspace=ws))
        with self.assertRaises(procage.GrantError):
            c.spawn(["/usr/bin/true"], grants={"nope": ws})


class Example(unittest.TestCase):
    def test_the_shell_tool_runs_a_command(self) -> None:
        example = Path(__file__).resolve().parent.parent / "examples" / "shell_tool.py"
        ws = workspace()
        out = subprocess.run(
            [sys.executable, str(example), ws, "echo caged > note && cat note"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("caged", out.stdout)


if __name__ == "__main__":
    unittest.main()
