"""A shell tool for an agent framework, caged by procage.

Register `shell` as a tool with any framework that calls plain Python
functions: it runs one command line in the workspace and returns what the
model needs to read, including what the sandbox refused. The model's
commands can read and write the workspace, run the system's programs and
nothing else: no network, no secrets, no writes outside the workspace.

    python shell_tool.py /abs/workspace "ls -la"
"""

import sys

import procage

_cages: dict[str, procage.Cage] = {}


def _cage(workspace: str) -> procage.Cage:
    """One cage per workspace, reused by every call."""
    if workspace not in _cages:
        policy = procage.Policy.preset("agent_workspace", 3, workspace=workspace)
        options: dict = {"violations": True}
        if sys.platform != "darwin":
            # Linux: accept the masks taken at spawn, and waive trust-handoff
            # where the tier cannot keep it beside a write rule.
            options.update(accept_spawn_snapshot=True, relax=["waive:trust-handoff"])
        _cages[workspace] = procage.Cage(policy, **options)
    return _cages[workspace]


def shell(command: str, workspace: str, timeout: float = 60.0) -> str:
    """Run `command` with /bin/sh in `workspace`, caged, and report the exit
    code, the output and any refusal."""
    try:
        done = procage.run(
            _cage(workspace), command, shell=True, timeout=timeout, text=True
        )
    except TimeoutError:
        return f"timed out after {timeout} s"
    report = [f"exit code: {done.returncode}"]
    if done.stdout:
        report.append(done.stdout)
    if done.stderr:
        report.append("stderr:\n" + done.stderr)
    for v in done.violations:
        report.append("refused: " + v["message"])
    return "\n".join(report)


if __name__ == "__main__":
    print(shell(sys.argv[2], sys.argv[1]))
