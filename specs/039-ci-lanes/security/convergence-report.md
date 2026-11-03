## Security Convergence — 039-ci-lanes

Commit `412ed89` · 2026-11-03T08:37:50Z

| Metric | Value |
|---|---|
| Threats (active) | 11 |
| Open blocking threats | 0  |
| Security requirements | 8 |
| verified | 8 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | scan | `justfile::workflows` | The gate rejects any uses line without a 40-hex SHA and a version comment; run against a tag pin it failed naming file and line, and it passes on the current workflows. |
| SR-002 | verified | scan | `justfile::workflows` | The gate requires top-level contents read in every workflow, refuses job-level permissions and secrets in ci.yml and the pull_request_target and workflow_run triggers; ci.yml declares contents read only, so fork pull requests cannot push. |
| SR-003 | verified | scan | `justfile::workflows` | The gate refuses github.event and github.head_ref expressions anywhere and any cache step; both negative cases were run and failed the gate; the workflows have no caches. |
| SR-004 | verified | test | `crates/procage-kernel-facts/tests/kernel_facts.rs::main` | With PROCAGE_KF_EXPECT_ARCH=x86_64 and PROCAGE_KF_EXPECT_MACOS=27 on macOS 26 arm64 the runner printed ARCH MISMATCH and MACOS MISMATCH and failed; every lane header in CI run 41592279478 shows release, build, arch, sandboxed and tier. |
| SR-005 | verified | review | `crates/procage-kernel-facts/tests/kernel_facts.rs:1458` | Enforcement facts fail with an AlreadySandboxed outcome inside a Seatbelt sandbox, never skip; the workflows gate refuses continue-on-error. |
| SR-006 | verified | scan | `justfile::workflows` | The gate fails when the runner labels of ci.yml and the README lane table differ; the table lists build or kernel, arch, tier and date per lane, names macOS 15 and earlier untested, and SECURITY links it. |
| SR-007 | verified | test | `crates/procage-policy/tests/presets.rs::every_preset_is_pinned` | Base V1 to V3 fixtures are compared byte for byte on every run; the xcode-27 lane (macOS 27.0.1) passed the base program set, so no new base version was needed. |
| SR-008 | verified | review | `.github/workflows/ci.yml:133` | The T1 jobs apply only Ubuntu's documented sysctl, the Lane step logs it and id -un, and the suites run as the runner user; Ubuntu 26.04 reached T1 with that step, so no unavailable note is needed. |
