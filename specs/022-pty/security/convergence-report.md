## Security Convergence — 022-pty

Commit `ad62c07` · 2026-11-03T18:00:53Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
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
| SR-001 | verified | test | `crates/procage/tests/escape_macos.rs::r22_a_new_terminal_keeps_input_injection_inside_the_run` | A child with Tty::NewPty opens a second terminal the test made for read and write and gets an open error, also with terminal injection waived (escape_macos and escape_linux on T1 and T2); pty.rs::without_a_base_the_terminal_works_and_resizes reads and resizes the own terminal with no base on Linux and base V1 (no terminal rule) on macOS; procage-policy tests/base.rs::terminals_by_tty_mode shows exactly the extension class and /dev/tty with and without a base. |
| SR-002 | verified | test | `crates/procage/tests/escape_linux.rs::r22_a_new_terminal_keeps_input_injection_inside_the_run` | TIOCSTI on the child's own new terminal returns EPERM on macOS (hid-control allowed, so the class alone refuses) and on Linux T1 and T2; waived, it succeeds and the byte is echoed only on the run's own controller. |
| SR-003 | verified | test | `crates/procage/tests/pty.rs::concurrent_runs_from_a_busy_parent_get_only_their_own_terminal` | 200 runs from four threads list their open descriptors through ls /dev/fd and see only 0 to 3 (no controller, no other run's terminal); pty.rs::the_run_end_closes_the_terminal_and_kills_its_jobs shows the controller read ending once the run ends, so the parent holds no copy of the device. |
| SR-004 | verified | test | `crates/procage/tests/pty.rs::concurrent_runs_from_a_busy_parent_get_only_their_own_terminal` | Four threads allocating and locking run beside four spawning threads; every child opens /dev/tty, so each got its terminal as controlling terminal from the setsid and TIOCSCTTY step; 20 consecutive passes on macOS after the marker-search fix, and on Linux T1 and T2. |
| SR-005 | verified | test | `crates/procage/tests/pty.rs::the_run_end_closes_the_terminal_and_kills_its_jobs` | An interactive shell starts sleep in the background; dropping the handle kills it within five seconds and the controller read ends, on macOS and Linux T1 and T2. |
| SR-006 | verified | test | `crates/procage/tests/pty.rs::exec_refuses_a_new_terminal` | Cage::exec and Cage::exec_session return Unsupported::Setting for Tty::NewPty and the test process continues; spawn_macos.rs::refusals_before_any_child and native.rs::errors_explain_themselves assert the named setting. |
| SR-007 | verified | review | `crates/procage/src/pty.rs:16` | The Pty rustdoc says the bytes are the cage's untrusted output, escape sequences included, unfiltered, and must not reach a terminal or anything that runs them; the site and THREAT_MODEL repeat it. |
| SR-008 | verified | test | `crates/procage/tests/pty.rs::a_full_screen_program_runs_through_its_terminal` | CI run 41685514406 (ad62c07, released as 0.5.0) ran pty.rs (shell, python3 -i, full-screen, run end, no base, exec refusal, concurrency) green on macOS 26 and 27, Ubuntu 24.04 x86_64 and arm64 and 26.04 on both tiers and the eight kernel lanes; the docs claim only what those tests show. |
