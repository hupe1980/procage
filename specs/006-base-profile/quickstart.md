# Quickstart: validating 006-base-profile

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Pinned content, precedence, tty, services | `cargo test -p procage-policy --all-features --test base` | pass |
| 2 | Lowering table with the `base-v1` row | `cargo test -p procage-policy --test lowering_table` | pass |
| 3 | Program set and refusals on the kernel | `cargo test -p procage --test spawn_macos base_` | pass |
| 4 | Well-formedness | `cargo test -p procage-kernel-facts --test policy_compiles` | pass (now includes base V1) |
| 5 | All gates | `just ci` | green |

Defects to inject:

1. The base allows `/Users`.
2. The tty rule is added regardless of the terminal mode.
3. The base rules are emitted after the deny-within-allow block.

## Recorded outcomes

Recorded 2026-10-30 on macOS 26.6.2 (25G83), outside any sandbox.

| # | Outcome |
|---|---|
| 1 | Pass: 6 tests. The macOS lines (with and without `Tty::Inherit`) and the Linux rules at ABI 6 are pinned. |
| 2 | Pass: the `base-v1` row holds on every target and ABI. |
| 3 | Pass: 3 caged tests. All 15 programs of the set ran with correct output (`id -un` and `date +%Z` equal their output outside the cage); a Rust child started without extra rules; a child with `/dev/null` stdio ran; under the base alone `ls $HOME`, `stat $HOME`, a temp-file read, a `/tmp` write and `nc` to loopback were refused. |
| 4 | Pass: the base V1 profile compiles through libsandbox. |
| 5 | Pass: `just ci`, all 10 gates. The kernel facts gave 28 pass. |

Injected defects:

| Defect | Failing tests |
|---|---|
| The base allows `/Users` | `base_names_nothing_personal`, `macos_content_is_pinned`, and the caged `base_grants_nothing_personal` |
| The tty rule is added regardless of the terminal mode | `a_terminal_only_with_inherit`, `macos_content_is_pinned` |
| The base is emitted in the hard-deny block, after protect | `base_allows_come_before_every_deny` |

Note: emitting the base in the deny-within-allow block is *not* a defect.
Rules sort by effect first within a block, so allows still come first and
the profile is identical. The block sort is a second guard on precedence.
