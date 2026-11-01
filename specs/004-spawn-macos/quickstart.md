# Quickstart: validating 004-spawn-macos

Run these from a plain terminal on macOS: not inside Claude Code's or another
agent's sandbox. Inside a sandbox, the enforcement tests fail by design.

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Enforcement and hygiene tests | `cargo test -p procage --test spawn_macos` | all pass |
| 2 | Contention (SR-004) | `cargo test -p procage --test spawn_macos contention` | 100/100 caged, 0 hangs |
| 3 | `unsafe` confinement (SR-003) | `cargo test -p procage --test unsafe_confined` | pass |
| 4 | Catalog gate still green | `cargo test -p procage --test threat_model` | pass |
| 5 | Packaged docs of both crates | `just package-docs` | pass |
| 6 | Semver with the 0.0.2 bump | `just semver` | pass |
| 7 | All gates | `just ci` | green |
| 8 | Latency (SC-005, recorded) | `cargo test -p procage --release --test spawn_macos latency -- --nocapture` | median overhead printed |

Defects to inject (each must fail a named test):

1. The apply call is skipped, so the child runs uncaged.
2. Path resolution is skipped.
3. The nesting check is skipped.
4. Tokens are consumed before apply.
5. The environment is not cleared.

## Recorded outcomes

Recorded 2026-10-30 on macOS 26.6.2 (25G83), Apple M4 Pro, outside any
sandbox.

| # | Outcome |
|---|---|
| 1 | Pass: 22 caged-child tests (1 ignored, the latency measurement) in under 1 s. |
| 2 | Pass: 100/100 children were caged (`cat` of a denied file gave EPERM) while 4 threads churned dyld; none hung. |
| 3 | Pass: `unsafe` appears only in `src/macos/sys.rs`, each use with a SAFETY comment block. |
| 4 | Pass: the catalog gate passes 18/18 with the release status for 0.0.2. |
| 5 | Pass: `package-docs` packages procage and procage-policy, and builds both docs from the packages alone; `macos/index.html` is present. |
| 6 | Pass: `cargo semver-checks`, 0.0.1 → 0.0.2. |
| 7 | Pass: `just ci`, all 10 gates. The kernel facts gave 28 pass in 132.8 s. |
| 8 | Recorded, release build, `/usr/bin/true` × 50: median plain 1.04 ms, caged 1.27 ms, so 0.23 ms overhead (SC-005 allows ≤ 5 ms). |

Injected defects. Each was caught, and the file was restored byte for byte:

| Defect | Failing tests |
|---|---|
| The apply call is skipped | 13 tests, including `contention_every_child_is_caged_and_none_hangs`, `reads_inside_the_grant_and_is_refused_outside` and `network_only_as_the_policy_says` (verify fails, so nothing runs) |
| Path resolution is skipped | 8 tests, including `a_tmp_spelling_works_as_written`, `glob_characters_in_a_resolved_prefix_are_literal` and `a_grant_binds_for_one_spawn_only` |
| The nesting checks are skipped | `a_caged_process_cannot_spawn_a_nested_cage` |
| Tokens are consumed before apply | `a_grant_binds_for_one_spawn_only` |
| The environment is not cleared | `the_environment_is_the_policys` |

Found during implementation:

1. **The child needs to read the symlinks in its own path spelling.**
   Resolving `/tmp/x` to `/private/tmp/x` fixes the rule, but the child opens
   `/tmp/x`, and that lookup needs `file-read-metadata` on the symlink `/tmp`.
   Path resolution therefore also allows metadata reads of every symlink a
   policy path passes through, and of `/etc`, `/tmp` and `/var` (for grants).
   Measured: metadata on the link alone is enough, and `..` traversal stays
   denied.
2. **Preparing a cage inside a sandbox failed with a misleading path error.**
   `Cage::new` now reports `AlreadySandboxed` first.
3. **Rust programs need `sysctl-read`.** The Rust runtime reads the page size
   through sysctl, so a Rust child under deny-default aborts without it. The
   test child grants it through the raw layer; the base profile (006) has to
   decide.
4. **Process lesson.** The injection script restored files with an old
   modification time, so cargo kept running the defective build. The script
   now refreshes the time on restore; all suites were re-run after a forced
   rebuild.
