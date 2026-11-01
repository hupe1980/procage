# Quickstart: validating 007-hard-deny-and-presets

| # | Scenario | Command |
|---|---|---|
| 1 | Pinned lists and presets | `cargo test -p procage-policy --all-features --test presets` |
| 2 | Lowering table (new rows) | `cargo test -p procage-policy --test lowering_table` |
| 3 | Caged evidence | `cargo test -p procage --test spawn_macos hard_deny_ preset_` |
| 4 | Compile check | `cargo test -p procage-kernel-facts --test policy_compiles` |
| 5 | All gates | `just ci` |

Defects to inject:

1. `.ssh` is dropped from the secrets list.
2. Folding is off and the patterns are case-sensitive. Expected outcome: the
   kernel still denies, so the folding unit test must catch it.
3. The `.git` unlink deny is removed.
4. `agent_readonly` gets write access.

## Recorded outcomes

Recorded 2026-10-30 on macOS 26.6.2 (25G83), outside any sandbox.

| # | Outcome |
|---|---|
| 1 | Pass: 4 tests; four preset fixtures pinned (28–37 lines each); the class lists are pinned. |
| 2 | Pass: the three new rows (macOS exact, Linux n/a with the pending note). |
| 3 | Pass: 7 new caged tests (41 in total). With a `$HOME` read grant, `~/.ssh`, `~/.aws`, `~/.gnupg` and `~/.SSH` were refused and `$HOME` was listable; the secrets waiver allowed `~/.ssh`. Git hooks, `.git/config`, `.gitmodules`, `.zshrc`, `.ZSHRC`, `.envrc`, `.GIT/HOOKS/…`, `src/.bashrc` and `mkdir .vscode` were refused, and so was `mv .git moved`; `src/main.rs`, `.git/objects/ab` and `notes.txt` were writable; the trust-handoff waiver allowed the hook. A write grant on `~/Library/LaunchAgents` did not allow a plist. All four presets behaved as specified. |
| 4 | Pass: the compile check covers every preset and the new tier. |
| 5 | Pass: `just ci`, all 10 gates. The kernel facts gave 28 pass. |

Injected defects:

| Defect | Failing tests |
|---|---|
| `.ssh` dropped from secrets | `the_class_lists_are_pinned`, `every_preset_is_pinned`, `hard_deny_secrets` |
| Folding off | `glob::tests::folding` (the kernel still denies case variants, as R1 measured, so folding is a second guard) |
| `.git` unlink deny removed | `the_class_lists_are_pinned`, `every_preset_is_pinned`, `hard_deny_trust_handoff` |
| `agent_readonly` gets write | `every_preset_is_pinned`, `preset_agent_readonly` |

(`cargo test` stops at the first failing test binary, so the lists show the
first failures, not all of them.)
