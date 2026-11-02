## Security Convergence — 042-explain

Commit `6c4d948` · 2026-11-02T05:55:25Z

| Metric | Value |
|---|---|
| Threats (active) | 8 |
| Open blocking threats | 0  |
| Security requirements | 10 |
| verified | 10 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | test | `crates/procage/tests/oracle.rs::explain_agrees_with_the_kernel` | Asks every expressible preset and the rule-kinds policy 1,277-1,278 questions per lane (macOS, Linux T1 and T2, run 2026-11-02), asserts at least 1,000, fails naming each disagreement, asserts every required rule kind is reached and that flipping any one kind's answers is detected; a non-gap cage error (AlreadySandboxed) panics in fitted(). |
| SR-002 | verified | test | `crates/procage/tests/oracle.rs::explain_agrees_with_the_kernel` | classify() maps 0 to allowed, EACCES/EPERM/EROFS to denied and every other errno (ENOENT included) to Unresolved, which disagreements() counts as a failure; the kernel side is only the caged child's open and caged spawns, no sandbox_check. |
| SR-003 | verified | test | `crates/procage/tests/oracle.rs::the_docs_list_the_proven_operations` | The site page's table lists exactly MODELLED with "proven" for each of the three targets; explain_agrees_with_the_kernel asserts the asked operations equal MODELLED on every lane. |
| SR-004 | verified | test | `crates/procage/tests/oracle.rs::explain_agrees_with_the_kernel` | On T1 the rule-kinds policy asks writes under .git/hooks, .envrc and .vscode in a writable tree; the answers carry SPAWN_COVER ("T1 cover" is a required kind) and agree with the kernel; crates/procage-policy/tests/explain.rs::every_rule_kind_on_macos asserts a path is allowed by the grant with it bound and denied by the default without; the oracle binds the grant and agrees. |
| SR-005 | verified | test | `crates/procage-policy/tests/explain.rs::every_remedy_flips_its_question` | For every denied question of every preset and the kinds policy on three targets, applies the remedy, asserts the question becomes allowed, that an added rule is a literal for the asked path, and that the policy diff equals the remedy's diff; every_rule_kind_on_macos asserts the .git/hooks write is denied by trust-handoff with exactly that waiver. |
| SR-006 | verified | test | `crates/procage-policy/tests/explain.rs::non_canonical_paths_name_their_canonical_form` | Asserts /etc/hosts names /private/etc/hosts, /work/a/../b names /work/b and a relative path has no canonical form (unit test canonical_forms adds // . and trailing separators); pattern_characters_stay_literal asserts /work/a*[b is unaffected by a protect on /work/ab; oracle.rs::explain_follows_links asserts a link to a hidden file gets the hidden file's answer on all three lanes. |
| SR-007 | verified | test | `crates/procage-policy/tests/explain.rs::unmodelled_operations_are_never_guessed` | Asks metadata, unlink, network and signal operations under every preset on every target and asserts NotModelled with Decider::None. |
| SR-008 | verified | test | `crates/procage-policy/tests/explain.rs::diff_covers_every_changed_answer` | For v3 presets and the kinds policy times 18 mutations (rules, base, every waiver, a grant) on three targets, every question whose answer differs is covered by an entry with the matching direction; one_more_writable_path_or_waiver, preset_versions_differ_only_in_their_base (base setting listed, entries from the base or build v2's sockets) and entries_are_tagged_with_their_target cover the other scenarios. |
| SR-009 | verified | test | `crates/procage-policy/tests/explain.rs::explain_is_fast_on_long_paths` | Bounds explain at 1 ms in release (20 ms debug) for a 4,000-byte path under agent_workspace v3 on three targets, measured 0.61 ms by the spawn bench; diff_is_fast_on_large_policies bounds a 10,000-rule diff at 1 s in release (measured about 0.05 s); the regex is a Pike VM and diff sorts without pattern pairs. |
| SR-010 | verified | review | `site/content/docs/explain.md:41` | The page says an answer names the policy's rules and must not be relayed into the cage unfiltered; the crate docs (crates/procage-policy/src/explain/mod.rs module header) and both Cage::explain docs say the same. |
