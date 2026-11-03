# Feature Specification: Python bindings

**Feature Branch**: `020-python` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Implemented

**Input**: Agent frameworks written in Python now expect a local OS sandbox for shell and code tools (a major agent SDK ships local macOS and Linux sandbox clients in Python and JavaScript; popular frameworks' default local shell has none, and third-party backends are appearing). The name `procage` is reserved on PyPI. A thin, safe binding would make procage that backend.

## Context

The binding wraps the existing library; it adds no policy semantics of its
own. Policies come from presets or from the documented serialised format, so
Python code never builds profile text.

## Clarifications

### Session 2026-11-01

- Q: Which platforms? → A: Wheels for macOS arm64 and manylinux x86_64
  and aarch64, one stable-ABI wheel per platform (amended 2026-11-03: no
  macOS x86_64 wheel, see below).
- Q: Async? → A: Blocking calls that release the interpreter lock, plus
  asyncio twins (`run_async`, `communicate_async`, `wait_async`, amended
  2026-11-03) that wait on worker threads and end the run when the
  awaiting task is cancelled; no Python runtime dependency.
- Q: Node.js? → A: Not now; reconsidered when a JavaScript consumer asks.

### Session 2026-11-03

Decided by the project's scope rule (best-in-class, no overengineering).

- Q: An Intel macOS wheel? → A: No. procage names Intel Macs untested and
  no CI lane runs one; a wheel that is never tested would contradict
  FR-004. The wheels are macOS arm64 and manylinux_2_28 x86_64 and aarch64.
- Q: Which Python versions? → A: One stable-ABI (abi3) wheel per platform
  for CPython 3.11 and later (3.10 reached end of life in October 2026).
- Q: What is the Python surface? → A: `Policy` (from a preset by name,
  version and workspace, or from the documented JSON format; `to_json`),
  `Cage(policy, violations=, relax=, accept_spawn_snapshot=)`,
  `cage.spawn(args, cwd=, env=, grants=, stdin=, stdout=, stderr=)` with
  `"pipe"`, `"null"` or `"inherit"`, a `Run` with `pid`, `poll`, `wait`,
  `wait_async`, `communicate`, `kill`, `violations()` and `receipt()`, and
  `procage.run(...)` for the common case. Violations and receipts are plain
  dicts from the serialised forms. New terminals and the proxy are left
  out until a consumer asks.
- Q: How do errors reach Python? → A: One base class `procage.Error` and a
  subclass per kind: `PolicyError` (an invalid document or preset),
  `CapabilityGapError` (with `.gaps`, a list of dicts),
  `UnsupportedError`, `AlreadySandboxedError`, `GrantError` and
  `SpawnError` (everything else, with the step where the child failed);
  each carries the Rust message.
- Q: What ends a run when Python lets go of it? → A: Dropping the `Run`
  (garbage collection) ends it as dropping the Rust handle does, and an
  `atexit` hook ends every run still alive when the interpreter exits.
- Q: Where does the code live? → A: In one directory, `bindings/python`:
  the binding crate (`procage-py`, a workspace member not published to
  crates.io) beside its `pyproject.toml`, the Python package, tests and
  example, as maturin expects and as Rust workspaces with bindings lay it
  out (tokenizers, OpenDAL); `bindings/` leaves room for other languages.
  No sdist: the wheels cover every supported platform.
- Q: What is the framework example? → A: A framework-neutral shell tool
  (`examples/shell_tool.py`): one function that runs a command in a
  workspace cage and returns its output and violations, which any agent
  framework can register as a tool; CI runs it.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Run a command caged from Python (Priority: P1)

**Independent Test**: `pip install procage`, then build a cage from a preset
for a workspace, run a command with arguments and environment, read its
output, exit code and violations, on each platform.

**Acceptance Scenarios**:

1. **Given** a preset and a workspace, **When** a command runs, **Then** it is
   caged exactly as from Rust (the binding's tests run a subset of the escape
   suite).
2. **Given** a policy the host cannot enforce, **Then** Python receives a
   typed exception listing the gaps.
3. **Given** the run object garbage-collected or the interpreter exiting,
   **Then** every process of the run is killed.

---

### User Story 2 - Plug into an agent framework (Priority: P2)

**Acceptance Scenarios**:

1. **Given** the documented example, **Then** a framework's shell tool runs
   its commands through procage with a few lines of glue.

### Edge Cases

- Forking interpreters (multiprocessing): spawning from a child interpreter
  works; documented limits.
- Running inside another sandbox: the same refusal as from Rust.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The package MUST expose: presets and base versions, policy from
  the serialised format, cage construction with options (violations, fit with
  named relaxations), spawn with grants, wait, kill, output pipes, violations
  and the receipt.
- **FR-002**: Every Rust error MUST map to a typed Python exception with the
  same information.
- **FR-003**: The binding MUST NOT run Python code between fork and exec.
- **FR-004**: Wheels MUST be built and tested in CI on every target platform
  and published by the release workflow (PyPI Trusted Publishing, no stored
  token).
- **FR-005**: The binding MUST release the interpreter lock while it spawns,
  waits or reads, and MUST end every run when its object is collected or the
  interpreter exits.

<!-- threatspec:begin -->
### Security Requirements *(managed by ThreatSpec — edit threat-model.yaml)*

- **SR-001** (P1): The binding MUST NOT copy the caller environment into the command; only variables passed in env= are set explicitly, and the policy environment rules decide the rest.
  - Mitigates: `threat.env-leak` via `mitigation.explicit-env`
  - Given a secret variable in os.environ and a preset policy, when a caged command prints its environment, then the secret is absent
  - Given the same and env= naming one variable, when the command prints its environment, then that variable is present and the secret absent
- **SR-002** (P1): The binding MUST NOT run Python code in the child between fork and exec.
  - Mitigates: `threat.python-in-child` via `mitigation.rust-spawn`
  - Given Python threads holding locks while the binding spawns, when many commands are spawned from several threads, then every spawn completes
- **SR-003** (P1): A policy MUST reach the cage only through the presets or the versioned format, an unknown field or invalid value MUST raise PolicyError, a gap MUST raise CapabilityGapError with the gaps, and the binding MUST add no default the Rust API does not have.
  - Mitigates: `threat.silent-weakening` via `mitigation.same-semantics`
  - Given a JSON policy with an unknown field, when Policy.from_json is called, then PolicyError is raised
  - Given a policy the host cannot enforce, when a Cage is made, then CapabilityGapError is raised with the gaps
- **SR-004** (P1): Every process of a run MUST be killed when the Run object is collected or the interpreter exits.
  - Mitigates: `threat.orphaned-run` via `mitigation.end-on-release`
  - Given a running command whose Run is deleted, when the object is collected, then its processes are dead
  - Given a running command when the interpreter exits, when the interpreter exits, then its processes are dead
- **SR-005** (P1): Wheels MUST be built from the tagged commit by actions pinned to full SHAs and published with PyPI Trusted Publishing from a protected environment, with no stored token.
  - Mitigates: `threat.wheel-tampering` via `mitigation.trusted-publishing`
  - Given the release workflow, when the workflows gate runs, then every action is SHA-pinned and the publish job uses OIDC in the pypi environment
- **SR-006** (P2): Every published wheel platform MUST run the binding escape subset and the shell tool example from the built wheel on its CI lane, and the docs MUST claim no platform beyond them.
  - Mitigates: `threat.untested-wheel` via `mitigation.tested-wheels`
  - Given each wheel platform lane, when the Python tests run against the installed wheel, then reads and writes outside the workspace, secrets and the network are refused and the example runs
- **SR-007** (P3): Spawn, wait and the reading of output MUST release the interpreter lock.
  - Mitigates: `threat.gil-starvation` via `mitigation.release-gil`
  - Given one thread waiting on a long command, when another Python thread runs, then it makes progress
<!-- threatspec:end -->

## Success Criteria *(mandatory)*

- **SC-001**: The binding's escape subset passes on every wheel platform.
- **SC-002**: A framework example runs caged commands end to end.

## Assumptions

- The serialised policy format is stable within a minor version.

## Out of Scope

- Node.js bindings; Windows.
