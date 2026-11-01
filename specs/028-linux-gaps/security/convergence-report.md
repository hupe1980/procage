## Security Convergence — 028-linux-gaps

Commit `95a407d` · 2026-10-31T19:33:45Z

| Metric | Value |
|---|---|
| Threats (active) | 4 |
| Open blocking threats | 0  |
| Security requirements | 4 |
| verified | 4 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/escape_macos.rs::r09_unix_sockets_reach_only_their_paths, tests/escape_linux.rs::r09_unix_sockets_reach_only_their_paths` | With ipc.unix_sockets on the workspace and no network, the caged child binds, listens and connects in the workspace, while connecting to a daemon socket outside and opening TCP fail, on macOS (EPERM) and Linux T1 (masked daemon ECONNREFUSED, TCP EPERM). |
| SR-002 | verified | test | `tests/escape_linux.rs::r09_unix_sockets_reach_only_their_paths, crates/procage-policy/tests/gaps.rs::unix_sockets_by_tier_and_abi` | On T1 the host abstract socket gives ECONNREFUSED (separate network namespace); on T2 below ABI 9 the setting is refused naming ipc-unix-sockets, in the canary and in the lowering test. |
| SR-003 | verified | test | `tests/spawn_linux.rs::t2_hide_is_piecewise, tests/spawn_linux.rs::t2_hide_inside_a_writable_tree_is_refused, tests/spawn_linux.rs::t2_a_write_grant_around_a_hidden_path_fails_the_spawn, tests/spawn_linux.rs::t2_reading_everything_except_secrets` | On T2 the hidden file is unreadable directly and through a symbolic-link sibling and a listing is denied while a sibling reads; an entry created after the spawn is denied; a write rule around is refused at preparation and a write grant around fails the spawn naming both; the secrets class keeps a home's .ssh unreadable while reading /. The negative control shows the test fails without the expansion. |
| SR-004 | verified | test | `crates/procage-policy/tests/gaps.rs::reading_everything_needs_exactly_the_spawn_snapshot, tests/spawn_linux.rs::t2_hide_is_piecewise` | accept_spawn_snapshot holds exactly the five SPAWN_SNAPSHOT constructs; without it the secrets and fs-hide approximations are refused with a message naming the option; with it they lower and appear in the degradations; a glob rule stays refused. |
