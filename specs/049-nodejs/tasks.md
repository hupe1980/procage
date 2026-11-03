# Tasks: Node.js bindings

## Phase 1: Foundational

- [X] T001 `bindings/nodejs`: crate `procage-node` (cdylib, publish = false, lints with `unsafe_code = "deny"`, napi build script) and `package.json`; the npm reservation removed — Cargo.toml, bindings/nodejs/, packaging/npm/
- [X] T002 [SR-003] [SR-008] Addon `Policy` and the typed error protocol; the fixed loader and error classes in `index.js` — bindings/nodejs/src/lib.rs, bindings/nodejs/index.js

## Phase 2: User Story 1 — Run a command caged from Node (P1)

- [X] T003 [SR-001] [SR-002] [SR-003] [SR-007] [US1] `Cage` and async `spawn` (explicit env, workspace as default cwd, grants), `Run` with async `wait`, `output`, `violations`, `kill`, the receipt; collection ends a run — bindings/nodejs/src/lib.rs
- [X] T004 [SR-004] [US1] `run()` with `shell`, `encoding`, `input`, `timeout`, `signal`, `check`; `Run` disposal; exit hook; `index.d.ts` — bindings/nodejs/index.js, bindings/nodejs/index.d.ts
- [X] T005 [SR-001] [SR-002] [SR-003] [SR-004] [SR-006] [SR-007] [SR-008] [US1] Tests from the packed package — bindings/nodejs/test/procage.test.js

## Phase 3: User Story 2 — Plug into an agent tool (P2)

- [X] T006 [SR-006] [US2] The shell tool example, run by the tests — bindings/nodejs/examples/shell-tool.js

## Phase 4: Build, CI and release

- [X] T007 [SR-006] `build.sh` (build, pack, test from the tarball), `just node`, `just node-linux`, a CI step on every facts lane — bindings/nodejs/build.sh, justfile, .github/workflows/ci.yml
- [X] T008 [SR-005] Release: per-platform addon jobs, an npm job with Trusted Publishing and provenance in the `npm` environment, the GitHub release after it — .github/workflows/release.yml

## Phase 5: Polish

- [X] T009 Docs: package README, site page `nodejs.md`, README, CHANGELOG, specs index — bindings/nodejs/README.md, site/content/docs/nodejs.md, README.md, CHANGELOG.md, specs/README.md
- [X] T010 `just ci`, `just node`, Linux T1/T2; quickstart; status Implemented; commit on `main`

## Phase 6: Security Convergence

**Purpose**: Close security gaps found by ThreatSpec converge on 2026-11-03 (commit f72c024).

- [X] T011 [SR-005] Add a test for SR-005 (The package MUST be built from the tagged commit by actions pinned to full SHAs and published with npm Trusted Publishing and provenance from a protected environment, with no stored token) — touchpoints: .github/workflows/release.yml [converge: implemented-unverified; The node and npm jobs use SHA-pinned actions, test each addon from a packed package, check the tag and the three addons, pack with the contents check and run npm publish --provenance with id-token write in the npm environment and no token; not yet run, and npm's trusted publisher for procage must name release.yml and the npm environment.]
- [X] T012 [SR-006] Add a test for SR-006 (Every published platform MUST run the escape subset and the shell tool example from the packed package on its CI lane, and the docs MUST claim no platform beyond them) — touchpoints: .github/workflows/ci.yml, bindings/nodejs/build.sh, bindings/nodejs/test/procage.test.js [converge: implemented-unverified; Every facts lane runs bindings/nodejs/build.sh all (build, pack with the contents check, 25 tests and the example from the tarball; Node 22 on Linux, 26 on macOS); passed locally on macOS and Linux T1 and T2, not yet on the CI lanes.]
