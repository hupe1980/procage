# Feature Specification: Python bindings

**Feature Branch**: `020-python` (planning directory; commits land on `main`)

**Created**: 2026-11-01

**Status**: Draft

**Input**: Agent frameworks written in Python now expect a local OS sandbox for shell and code tools (a major agent SDK ships local macOS and Linux sandbox clients in Python and JavaScript; popular frameworks' default local shell has none, and third-party backends are appearing). The name `procage` is reserved on PyPI. A thin, safe binding would make procage that backend.

## Context

The binding wraps the existing library; it adds no policy semantics of its
own. Policies come from presets or from the documented serialised format, so
Python code never builds profile text.

## Clarifications

### Session 2026-11-01

- Q: Which platforms? → A: Wheels for macOS arm64 and x86_64 and manylinux
  x86_64 and aarch64, one stable-ABI wheel per platform.
- Q: Async? → A: Blocking calls that release the interpreter lock, plus an
  asyncio-friendly wait; no Python runtime dependency.
- Q: Node.js? → A: Not now; reconsidered when a JavaScript consumer asks.

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
  and published by the release workflow.

## Success Criteria *(mandatory)*

- **SC-001**: The binding's escape subset passes on every wheel platform.
- **SC-002**: A framework example runs caged commands end to end.

## Assumptions

- The serialised policy format is stable within a minor version.

## Out of Scope

- Node.js bindings; Windows.
