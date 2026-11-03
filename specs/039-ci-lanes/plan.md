# Implementation Plan: CI lanes for the releases people run

**Branch**: `039-ci-lanes` (local planning; commits on `main`) | **Date**: 2026-11-03 | **Spec**: [spec.md](spec.md)

## Design

1. **Lane assertions.** The kernel-facts runner
   (`crates/procage-kernel-facts/tests/kernel_facts.rs`) reads
   `PROCAGE_KF_EXPECT_MACOS` (major version) and `PROCAGE_KF_EXPECT_ARCH`
   next to the expected tier and ABI. A mismatch prints a `MISMATCH` line
   naming what it expected and what it measured, and fails the step. The
   header already prints the release, build or kernel, architecture,
   sandbox status, tier, Landlock ABI and errata.
2. **macOS lanes.** The `macos` job becomes a matrix over `macos-26`,
   `xcode-27` and `macos-15` (all arm64), each with its expected major
   version. Every lane runs every suite.
3. **Linux lanes.** The `linux` matrix covers `ubuntu-24.04`,
   `ubuntu-24.04-arm` and `ubuntu-26.04`, each as shipped (T2) and with
   Ubuntu's documented sysctl lifted (T1). The tests run as the runner user
   in every job, and each job sets its expected architecture.
4. **Gate.** `just workflows`, in `ci` and in the CI gates job, checks:
   - every `uses:` is pinned to a full 40-character SHA with a version
     comment;
   - top-level `permissions: contents: read` in every workflow, and no
     job-level `permissions:` in `ci.yml`;
   - no `secrets.` in `ci.yml`;
   - no `pull_request_target` or `workflow_run` trigger;
   - no `github.event` or `github.head_ref` inside a `run:` script;
   - no cache steps and no `continue-on-error`;
   - the runner labels in `ci.yml` equal the labels in the README's
     platform table.
5. **Docs.**
   - The README platform table gets one row per lane: label, release and
     build or kernel, architecture, measured tier and date.
   - SECURITY links that table and names the supported procage version
     (0.4.x).
   - The site's "Where they have run" and its getting-started line list the
     lanes.
6. **Base profiles.** A new frozen base version is added only if a program
   in the base program set fails on macOS 27 or 15. V1 to V3 stay
   byte-identical, as the preset fixture test already checks on every run.
7. **Measurement decides.** If a lane cannot pass (no runner, a failing
   suite), it is removed and its release named untested. A lane that never
   reaches T1 keeps only its T2 job, and the docs say T1 is unavailable
   there without host changes.

## Constitution Check

| Principle | Check | Status |
|---|---|---|
| I | Claims only from green lanes; mismatches fail, never pass silently | PASS |
| III | Each lane cages real children on its own kernel and OS build | PASS |
| VII | Frozen bases stay byte-identical; any new entry is a new version. No API change (0.4.1) | PASS |
| Workflow | The gate runs in `just ci` and in CI; no new tool | PASS |

Principles II, IV, V and VI do not apply: no change to library code beyond
the kernel-facts runner.
