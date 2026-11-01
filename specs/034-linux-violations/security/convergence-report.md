## Security Convergence — 034-linux-violations

Commit `36ed673` · 2026-11-01T06:27:45Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
| Open blocking threats | 0  |
| Security requirements | 7 |
| verified | 7 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/escape_linux.rs::r32_the_seccomp_listener_stays_out_of_reach` | On T1 and T2 with /proc granted, the caged child counts seccomp listeners among its own descriptors (0) and tries to reopen every listener it sees under /proc/<parent>/fd (0 reopened, the kernel refuses), while its coverage is SystemCalls. The child closes the listener after sendmsg (sys.rs ChildPlan::run); pidfd_getfd and ptrace stay refused by the process-access class. |
| SR-002 | verified | test | `crates/procage/tests/spawn_linux.rs::refused_calls_are_reported_with_their_reason; crates/procage/tests/spawn_linux.rs::a_detached_run_is_still_answered` | Refused ptrace, socket and setsid each return EPERM in the child and appear in the record; a detached run's later refused calls return EPERM instead of blocking. The answer is built only in sys::answer_eperm (error -EPERM, value 0, flags 0) and sent before the violation is built (violations.rs supervise). |
| SR-003 | verified | test | `crates/procage/src/linux/seccomp.rs::notifying_changes_only_eperm_verdicts; crates/procage/tests/escape_linux.rs (PROCAGE_ESCAPE_VIOLATIONS=1, T1 and T2)` | For varied policies on both tiers and ABIs 1–8, the notifying filter has the same instructions as the plain one except EPERM returns, which become SECCOMP_RET_USER_NOTIF; the plain path (notify false) is unchanged and its existing filter tests pass; the Linux escape suite passes 22/22 with reporting on, on both tiers. |
| SR-004 | verified | test | `crates/procage/tests/spawn_linux.rs::without_a_listener_the_run_is_still_confined` | With an outer filter holding a listener on the spawning thread, the reporting child's listener install fails with EBUSY, it installs the plain filter, ptrace still returns EPERM, and the record's coverage is Unavailable naming the busy error. |
| SR-005 | verified | test | `crates/procage/src/linux/seccomp.rs::matches_agrees_with_the_filter; crates/procage-policy/tests/seccomp_reasons.rs::each_origin_names_its_reason; crates/procage/tests/spawn_linux.rs::refused_calls_are_reported_with_their_reason` | Condition::matches equals the BPF interpreter on edge and pseudo-random arguments for every EPERM rule of varied plans; each rule origin carries its reason; the caged test finds process-access, not granted and lifetime for ptrace, socket and setsid. The process name is read before answering and kept only if NOTIF_ID_VALID still holds. |
| SR-006 | verified | test | `crates/procage/tests/spawn_linux.rs::a_flood_is_answered_and_capped` | 20,000 refused ptrace calls all return EPERM; the record holds 10,000 and counts 10,000 dropped, and is complete. |
| SR-007 | verified | test | `crates/procage/tests/spawn_linux.rs::a_record_completes_when_the_run_ends; crates/procage/tests/spawn_linux.rs::a_surviving_descendant_keeps_the_record_open` | A running child's record is incomplete (the receiver already yielded its ptrace), and complete after kill_all; a background descendant keeps the record incomplete after the child exits until kill_all. Crate docs, THREAT_MODEL and the site state that Landlock denials are not reported. |
