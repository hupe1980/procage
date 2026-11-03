## Security Convergence — 017-grant-on-denial

Commit `4f6ceb0` · 2026-11-03T15:26:37Z

| Metric | Value |
|---|---|
| Threats (active) | 6 |
| Open blocking threats | 0  |
| Security requirements | 5 |
| verified | 5 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/suggest_macos.rs::a_denied_file_operation_suggests_exactly_that_path` | Denied read, create and exec outside the policy each give a literal rule on that path with that access; applied, the respawn performs it while the sibling file stays denied, and the diff shows only the rule and the base's metadata reads on its way; a_denied_socket_connect_suggests_the_socket gives the socket path; the unit table in crates/procage/src/suggest.rs covers every file operation prefix. |
| SR-002 | verified | test | `crates/procage/tests/suggest_macos.rs::a_secret_suggests_nothing` | A denial of the secrets class (listing ~/Library/Keychains) yields none on the kernel; spawn_linux.rs::a_refused_call_suggests_its_class_waiver shows none for setsid under Lifetime::Run and a refused socket family; the unit test nothing_without_a_safe_change covers the raw layer, the older-kernel guard, the proxy and unknown kinds. |
| SR-003 | verified | test | `crates/procage/tests/suggest_macos.rs::a_protection_suggests_its_removal_marked_as_weakening` | A protect rule and a hide rule give their removal and a trust-handoff denial its waiver, each with weakens() true, and the respawn performs the operation; the Linux ptrace denial gives the process-access waiver marked weakening; grants and sockets are not marked (unit test only_grants_do_not_weaken). |
| SR-004 | verified | test | `crates/procage/tests/suggest_macos.rs::a_denied_file_operation_suggests_exactly_that_path` | Every case spawns again with the old policy after apply and asserts the operation is still denied; apply takes the policy by reference and returns a new one (crates/procage-policy/src/suggest.rs), and no API takes a running child. |
| SR-005 | verified | test | `crates/procage/tests/suggest_macos.rs::a_protection_suggests_its_removal_marked_as_weakening` | explain::diff of old and new only loosens and names only the suggested rule (with its base metadata reads or rename anchors) or the waived class; the respawned run's receipt lists the trust-handoff waiver; the unit test apply_changes_exactly_one_thing compares each applied policy with the hand-made expected one. |
