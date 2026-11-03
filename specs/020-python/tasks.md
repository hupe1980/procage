# Tasks: Python bindings

## Phase 1: Foundational

- [X] T001 `bindings/python`: crate `procage-py` (cdylib `_native`, publish = false, no test harness, workspace lints) beside its maturin `pyproject.toml` (python source, module name, version from the crate, abi3-py311); the name-reservation sources removed — Cargo.toml, bindings/python/
- [X] T002 [SR-003] `Policy` (presets by name and version with a workspace; `from_json`, `to_json`) and the exception classes with the Rust messages — bindings/python/src/lib.rs, bindings/python/python/procage/__init__.py

## Phase 2: User Story 1 — Run a command caged from Python (P1)

- [X] T003 [SR-002] [SR-003] [SR-007] [US1] `Cage` (violations, relax by name, spawn snapshot) and `spawn` with args, cwd, explicit env, grants and stdio modes, the interpreter lock released, no hook in the child — bindings/python/src/lib.rs
- [X] T004 [SR-001] [SR-004] [SR-007] [US1] `Run`: pid, poll, wait with timeout, kill from any thread, communicate, violations as dicts, receipt; dropping ends the run; `procage.run`, `wait_async`, the atexit hook — bindings/python/src/lib.rs, bindings/python/python/procage/__init__.py
- [X] T005 [SR-001] [SR-002] [SR-003] [SR-004] [SR-006] [SR-007] [US1] The escape subset and API tests through the installed wheel — bindings/python/tests/

## Phase 3: User Story 2 — Plug into an agent framework (P2)

- [X] T006 [SR-006] [US2] The framework-neutral shell tool example, run by the tests — bindings/python/examples/shell_tool.py

## Phase 4: Wheels, CI and release

- [X] T007 [SR-006] `just python` and a CI step on every facts lane: build the wheel as the release does, install it fresh, run the tests and the example — justfile, .github/workflows/ci.yml
- [X] T008 [SR-005] Release: wheel jobs (macOS arm64, manylinux_2_28 x86_64 and aarch64) and a PyPI job with Trusted Publishing in the `pypi` environment, full-SHA pins — .github/workflows/release.yml

## Phase 5: Polish

- [X] T009 Docs: bindings/python README, site page `python.md`, README section, CHANGELOG, THREAT_MODEL scope line — bindings/python/README.md, site/content/docs/python.md, README.md, CHANGELOG.md
- [X] T010 `just ci`, `just python`, Linux in containers; quickstart; status Implemented; commit on `main`

## Phase 6: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-03 (commit 4928124).

- [X] T011 [SR-005] Add a test for SR-005 (Wheels MUST be built from the tagged commit by actions pinned to full SHAs and published with PyPI Trusted Publishing from a protected environment, with no stored token) — touchpoints: .github/workflows/release.yml [converge: implemented-unverified; The wheel and pypi jobs use actions pinned to full SHAs (workflows gate passes), test the built wheel before upload and publish with pypa/gh-action-pypi-publish in the pypi environment with id-token write and no secret; not yet run, and PyPI's trusted publisher must name release.yml and the pypi environment.]
- [X] T012 [SR-006] Add a test for SR-006 (Every published wheel platform MUST run the binding escape subset and the shell tool example from the built wheel on its CI lane, and the docs MUST claim no platform beyond them) — touchpoints: .github/workflows/ci.yml, bindings/python/tests/test_procage.py, bindings/python/wheel.sh [converge: implemented-unverified; Every facts lane runs bindings/python/wheel.sh all (build as released, install fresh, 26 tests and the example); passed locally on macOS and Linux T1 and T2, not yet on the CI lanes.]
