# Quickstart: validating 001-kernel-facts

## Prerequisites

- macOS 26.6.2 (reference) in a terminal that is **not** inside an agent
  sandbox (check: `just facts` prints `sandboxed: no`).
- Rust 1.99.x plus the `1.99.0` toolchain; targets `thumbv7em-none-eabihf` and
  `x86_64-apple-darwin`; `just`, `cargo-deny`, `cargo-semver-checks`.
- Docker with image `rust:1.99`, for the Linux scenarios.

## Scenarios

| # | Run | Expect | Covers |
|---|---|---|---|
| 1 | `just ci` | every gate prints `==> gate: …` and passes; the facts report ends `0 fail` in under 5 minutes | US1, US4, SC-002, SC-006 |
| 2 | `just facts` | report header with `macos 26.6.2 (25G83)`, date, `sandboxed: no`; KF-M01…M28 PASS | US1, FR-004 |
| 3 | `sandbox-exec -p '(version 1)(allow default)' just facts` (sandboxes the runner on purpose) | `sandboxed: yes`; every enforcement fact FAIL with the already-sandboxed message; none PASS or skip | SR-001, SC-004 |
| 4 | `just kf-linux` | `tier: T2 …`, userns EPERM; T1-only facts N/A; others PASS | US2, SC-003 |
| 5 | `just kf-linux-t1` | `tier: T1`, `fresh_proc=false`; all applicable Linux facts PASS | US2, SC-003 |
| 6 | `PROCAGE_KF_EXPECT_TIER=T1 just kf-linux` | fails: tier mismatch | SR-016 |
| 7 | `just bisect` | per shape a bracket `ok<=N abort>=M` no wider than 10%; matches the constants asserted by KF-M24 | US3, SC-005 |
| 8 | `just kf-rosetta` | the same macOS facts pass under x86_64 | lane parity |
| 9 | Inject `unsafe {}` into `crates/procage-policy/src/lib.rs`, run `just lint` → fails. Add a path dependency whose `license = "GPL-3.0-only"`, run `just deny` → fails. Add `extern crate std;` to the policy crate, run `just no-std` → fails. Revert all three | gates bite | SC-006 |
| 10 | `just planning-paths` after adding a comment that cites the private notes directory to `src/lib.rs` | fails, naming the file; revert | SR-015, SC-007 |

## Expected question answers (recorded at implementation)

The report lists KF-M23…M26 with their asserted answers: path A layout, compile-abort
bracket, consume-before-apply ordering, TIOCSTI. The same answers are recorded
as dated decisions.

## Recorded outcomes (2026-10-29, macOS 26.6.2 25G83 arm64; Docker 7.0.14-linuxkit aarch64)

| # | Outcome |
|---|---|
| 1 | `just ci`: all 9 gates pass. Facts 28/28 in 140 s (SC-002 ✓) |
| 2 | Header `os: macos 26.6.2 (25G83) \| arch: aarch64 \| date: 2026-10-29 \| sandboxed: no`; 28 pass |
| 3 | Under `sandbox-exec`: `sandboxed: yes`; 16/16 enforcement facts FAIL with the outside-sandbox message; 12 compile-only facts pass; 0 skipped (SC-004 ✓) |
| 4 | `just kf-linux`: tier T2 (landlock abi 8, errata 7; userns errno 1); 5 pass, 8 N/A |
| 5 | `just kf-linux-t1`: tier T1 (fresh_proc no); 12 pass, 1 N/A (KF-L12: T2 only) (SC-003 ✓) |
| 6 | `just kf-linux T1` in the T2 container: `TIER MISMATCH: expected T1, measured T2`, exit 1 |
| 7 | `just bisect`: deny-default-allow ok≤15,625 abort≥16,250 (4.0%); allow-default-deny ok≤33,750 abort≥35,000 (3.7%) (SC-005 ✓) |
| 8 | `just kf-rosetta`: arch x86_64, 28/28 pass |
| 9 | unsafe → lint fails; `extern crate std` → no-std fails; GPL path dependency → deny fails **after** fixing the gate to `cargo deny --workspace check` (it first missed it) (SC-006 ✓) |
| 10 | a comment citing the private notes directory in `src/lib.rs` → planning-paths fails (SC-007 ✓) |

CI lanes (macOS images, ubuntu-24.04 x64/arm64, ubuntu-26.04, debian:13) are
defined but have not run: that needs a push, which needs the user's
authorization.
