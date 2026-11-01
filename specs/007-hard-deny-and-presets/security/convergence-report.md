## Security Convergence — 007-hard-deny-and-presets

Commit `eb66876` · 2026-10-30T09:00:14Z

| Metric | Value |
|---|---|
| Threats (active) | 7 |
| Open blocking threats | 0  |
| Security requirements | 6 |
| verified | 6 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `tests/spawn_macos.rs::hard_deny_secrets` | With a read grant on HOME, listing HOME succeeds while listing ~/.ssh, ~/.aws and ~/.gnupg is refused by the kernel. With secrets waived, ~/.ssh is listable and the plan lists the waiver. Dropping .ssh from the list fails this test and the pinned fixtures. |
| SR-002 | verified | test | `tests/spawn_macos.rs::hard_deny_trust_handoff; tests/spawn_macos.rs::preset_agent_workspace` | In a writable workspace with .git, the child cannot create .git/hooks/pre-commit, .git/config, .gitmodules, .zshrc, .envrc or src/.bashrc, cannot mkdir .vscode, and cannot rename .git; src/main.rs, .git/objects/ab and notes.txt are writable. Waiving trust-handoff allows the hook. Removing the .git unlink deny fails the test. |
| SR-003 | verified | test | `tests/spawn_macos.rs::hard_deny_persistence` | With an explicit write grant on ~/Library/LaunchAgents, creating a plist there is refused and nothing is created. The persistence class is last in the profile, so it wins over the grant. |
| SR-004 | verified | test | `tests/spawn_macos.rs::hard_deny_secrets; tests/spawn_macos.rs::hard_deny_trust_handoff; crates/procage-policy/src/glob.rs::tests::folding` | ~/.SSH is refused, and so are .ZSHRC and .GIT/HOOKS/post-checkout. The patterns are emitted case-folded (unit test). The kernel also matches case-insensitively on this APFS volume (research R1), so the folding is a second guard. |
| SR-005 | verified | test | `crates/procage-policy/tests/presets.rs::every_preset_is_pinned; crates/procage-policy/tests/presets.rs::the_class_lists_are_pinned; crates/procage-policy/tests/presets.rs::presets_round_trip_with_their_tag` | The lowered macOS profile of each preset V1 (workspace /work) equals its fixture, which includes the full class lists. The list sizes and key patterns are asserted, and the presets round-trip with their name and version tag. Injected list and preset changes failed these tests. |
| SR-006 | verified | review | `crates/procage-policy/src/lowering.md; crates/procage-policy/src/presets.rs:1; THREAT_MODEL.md#Release-status` | The lowering table marks hd-secrets, hd-trust-handoff and hd-persistence as n/a on Linux with the note that the Linux spawn backend must implement them before it ships. The presets module docs and the threat-model release status say the same, and the 008 spec carries the requirement. Escape-class statuses are unchanged and the catalog gate passes. |
