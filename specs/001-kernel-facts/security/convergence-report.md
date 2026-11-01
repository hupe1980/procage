## Security Convergence — 001-kernel-facts

Commit `24f3263` · 2026-10-29T20:25:18Z

| Metric | Value |
|---|---|
| Threats (active) | 17 |
| Open blocking threats | 0  |
| Security requirements | 17 |
| verified | 17 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/kernel_facts/tests/kernel_facts.rs::main (sandbox precheck); run under sandbox-exec recorded in quickstart.md scenario 3` | Ran the suite under sandbox-exec; header showed sandboxed yes and all 16 enforcement facts failed with the outside-sandbox message, none skipped or passed. |
| SR-002 | verified | test | `tests/kernel_facts/src/lib.rs::tests::controls_and_expectations` | A failed control run becomes SetupFailed, a wrong errno fails with expected errno=1 and the observed errno=13, and a crashed step is never judged; the unexpected-errno path was also observed in real runs. |
| SR-003 | verified | test | `tests/kernel_facts/tests/kernel_facts.rs::m26 (KF-M26 asserts ctty_before_errno=6)` | After setsid the child cannot open /dev/tty (ENXIO) before it opens its own pty, so the inherited terminal is out of reach; the byte is a constant 'k' with no newline. |
| SR-004 | verified | review | `tests/kernel_facts/src/bin/kf-probe/macos.rs SETUID_ARGV and nested(); main.rs::scratch_arg; grep for shells and fork in the runner and probe found none` | Every exec uses an absolute constant path or current_exe with constant step names and validated scratch paths; sudo runs with -n, stdin /dev/null and a 10 s deadline, and completed in 0.03 s. |
| SR-005 | verified | test | `tests/kernel_facts/src/lib.rs::tests::planted_symlinks_are_not_followed; ::tests::scratch_is_private_and_removed` | Exclusive directory and file creation both fail on a planted symlink and leave its target unchanged; scratch dirs are 0700 and removed; no procage-kf-* remained after full runs. |
| SR-006 | verified | test | `tests/kernel_facts/tests/kernel_facts.rs::m17 (KF-M17 observes exit=signal:6 in a child; later facts KF-M18…M28 ran in the same run)` | The 20,000-rule abort is recorded as an observation and the suite continued to completion in every full run. |
| SR-007 | verified | test | `tests/kernel_facts/src/lib.rs::tests::hanging_child_is_killed` | A 30 s child under a 200 ms timeout is killed and reported as Exit::Timeout well within 5 s; the bisection runs only with PROCAGE_KF_BISECT=1. |
| SR-008 | verified | review | `tests/kernel_facts/tests/kernel_facts.rs (steps only via run_step/Command); the only fork is tests/kernel_facts/src/sys/macos.rs::PreparedExec::spawn, exercised by KF-M18` | The runner has no pre_exec or fork. The one fork window issues dup2, __mac_syscall, execve and _exit on memory prepared before fork, and passed 200/200 under contention. |
| SR-009 | verified | test | `tests/kernel_facts/src/sys/macos.rs::tests::missing_symbol_is_named` | An unknown symbol is returned by name; every real symbol resolves. Lints confine unsafe to sys, with SAFETY comments enforced by clippy. |
| SR-010 | verified | review | `.github/workflows/ci.yml:9 (permissions contents read), :27/:35 (40-hex SHA pins), persist-credentials false on every checkout` | Every uses reference is pinned to a full commit SHA, the token is read-only, and no secrets are referenced. |
| SR-011 | verified | test | `justfile deny recipe (cargo deny --workspace check); quickstart.md scenario 9 (GPL path dependency caught)` | An injected GPL-3.0 path dependency failed the gate after the --workspace fix; the lockfile is in the tree and the deny config allows crates.io only. |
| SR-012 | verified | test | `tests/kernel_facts/tests/kernel_facts.rs::header; target/kernel-facts/report-*.txt; question finding doc comments on m23/m25/m26 and the compile-abort bracket constants` | Every run printed OS build or kernel, arch, UTC date and tier. Each finding records date, build, method and whether it is measured or inferred. |
| SR-013 | verified | review | `justfile kf-linux and kf-linux-t1 recipes` | Both recipes run as user 65534, mount the source read-only, and use neither --privileged nor host networking; both ran successfully. |
| SR-014 | verified | test | `tests/kernel_facts/src/lib.rs::emit (asserts the observation alphabet) and ::tests::observations; KF-M19 reports fd_bytes=16, never contents` | Observations are restricted to numbers, flags and tokens by construction. The inherited-fd fact reports the byte count only. |
| SR-015 | verified | test | `justfile planning-paths recipe; quickstart.md scenario 10` | An injected planning path in src/lib.rs failed the gate, and the clean tree passes. |
| SR-016 | verified | test | `tests/kernel_facts/src/lib.rs::tests::broken_measurements_are_absent` | Signal, timeout and error exits count as absent even with ok=1 printed, and derive_tier never rises without every capability; the default-seccomp container measured T2 with userns EPERM. |
| SR-017 | verified | review | `tests/kernel_facts/src/bin/kf-probe/macos.rs::ext_parent (token written to the child's stdin, never in argv or emit) and ::ext_child (reads stdin)` | The token goes only through the stdin pipe, the argv carries the scratch path and order only, and no emit call includes it; the granted directories are inside a 0700 scratch. |
