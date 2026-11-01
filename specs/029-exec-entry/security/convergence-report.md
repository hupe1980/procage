## Security Convergence — 029-exec-entry

Commit `6d05458` · 2026-10-31T18:55:52Z

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
| SR-001 | verified | test | `tests/exec.rs::becomes_the_command, tests/exec.rs::env_clear_keeps_secrets_out` | A helper execs a shell in a cage with a write rule; the shell's write inside succeeds and outside is denied, and with env_clear under passthrough the command sees only A=1 although the helper's environment holds a secret; macOS, Linux T1 and T2. Both paths share prepare and the child sequence (only the session mode differs). |
| SR-002 | verified | test | `tests/exec.rs::the_tmpdir_grant_is_refused, tests/exec.rs::a_missing_program_is_refused, tests/exec.rs::a_threaded_caller_is_refused_on_t1` | Each misuse returns its typed error (GrantError::TmpdirWithExec, an Io NotFound naming the program, Unsupported::ExecThreads with the thread count) and the test process then writes outside every policy successfully. The environment refusal is the spawn path's (spec 026, unit-tested there). |
| SR-003 | verified | test | `tests/exec.rs::becomes_the_command, tests/exec.rs::a_group_kill_ends_everything, tests/exec.rs::descendants_cannot_leave_the_group` | The command prints the helper's pid; killing the group of a shell that started the helper (not led by it) ends the command and its background sleeper on macOS and Linux, and fails if exec starts a session (negative control); on Linux a descendant's setsid fails. |
| SR-004 | verified | review | `src/lib.rs:45, THREAT_MODEL.md:34, src/macos/mod.rs:629` | The crate docs' Helpers section, the exec rustdoc on both backends and the threat model's release status state the per-system lifetime, including that macOS does not reach a descendant in its own session and pointing to Cage::spawn. |
