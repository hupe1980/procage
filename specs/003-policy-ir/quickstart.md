# Quickstart: validating 003-policy-ir

Run these from the repository root on the development Mac. Docker is not
needed: nothing in this feature applies a policy.

| # | Scenario | Command | Expected |
|---|---|---|---|
| 1 | Unit and property tests of the policy crate | `cargo test -p procage-policy --all-features` | all pass; each property runs 10,000 cases |
| 2 | Lowering table equals behaviour (SR-006) | `cargo test -p procage-policy --test lowering_table` | every row × target × ABI passes |
| 3 | Escaper round-trip and adversarial paths (SR-001/002/003) | `cargo test -p procage-policy --test escaping` | pass |
| 4 | Precedence, order-independence, waivers (SR-007) | `cargo test -p procage-policy --test precedence` | pass |
| 5 | Guard equivalence and limits (SR-008/009) | `cargo test -p procage-policy --test limits` | pass |
| 6 | Data format round-trip and refusals (SR-010) | `cargo test -p procage-policy --features serde --test format` | pass |
| 7 | Well-formedness through libsandbox (SR-004, FR-024) | `cargo test -p procage-kernel-facts --test policy_compiles` | every reference profile and all 112 operations compile |
| 8 | `no_std` with and without serde (FR-022) | `just no-std` | builds for `thumbv7em-none-eabihf` twice |
| 9 | Fuzzing (SC-007) | `just fuzz-all` (nightly) | 4 targets × ≥60 s, no crash |
| 10 | All gates | `just ci` | green |
| 11 | Docs wording (SR-011) | review of `cargo doc -p procage-policy` output and `policy_compiles.rs` | no enforcement claim |

Defects to inject (each must fail a named test, then be reverted):

1. The escaper stops escaping `"` → `escaping`.
2. The glob compiler stops escaping `.` → `escaping`.
3. `AbsPath` accepts `..` → `paths`.
4. A lowering-table cell is changed from `unsupported` to `exact` → `lowering_table`.
5. The hard-deny block is emitted before the deny-within-allow block → `precedence`.
6. `merge_adjacent` merges rules with different effects → `limits`.
7. `deny_unknown_fields` is removed from `FsRule` → `format`.

## Recorded outcomes

Recorded 2026-10-30 on macOS 26.6.2 (25G83), Apple M4 Pro, rustc 1.99.1;
fuzzing ran on nightly with cargo-fuzz 0.13.2.

| # | Outcome |
|---|---|
| 1 | Pass: 22 unit tests, 39 integration tests in 7 files and 1 doctest, in under 5 s. Each generated-input property runs 10,000 cases. |
| 2 | Pass: all 32 rows, for macOS, T1 at ABI 1/8/12 and T2 at ABI 4/5/6/8/9/12, plus N−1/N for the ABI-dependent cells. `a_changed_cell_is_detected` passes. |
| 3 | Pass, for paths, escaping and gaps. |
| 4 | Pass: 50 shuffles × 35 policies × 13 targets give identical plans; the tier is last; waivers are exact. |
| 5 | Pass: the guarded and unguarded rule lists agree for 10,000 cases × 8 requests; 2,001 raw rules that cannot merge give `LimitExceeded`; a 5,000-literal policy merges to at most 2,000 rules. |
| 6 | Pass: the round-trip includes a non-UTF-8 path; 8 malformed-value kinds and 3 unknown-field kinds are refused; 10,000 mutated documents caused no panic. |
| 7 | Pass: 35 reference profiles, the parameter-backed profile (which fails without its parameter, as expected) and all 112 operations compile. This is well-formedness only. |
| 8 | Pass: `thumbv7em-none-eabihf`, with and without `serde`. |
| 9 | Pass, all four targets for 61 s each with no crash: quote 12,697,540 runs; glob 5,883,907; format 4,994,965; lower 377,600. |
| 10 | Pass: `just ci`, all 10 gates. The kernel facts gave 28 pass, 0 fail, unsandboxed, in 120.2 s. |
| 11 | Reviewed: the crate docs and the lowering table say what lowering produces and state that a plan says nothing about enforcement. `policy_compiles.rs` is labelled as a well-formedness check. Three intent-layer doc lines were rephrased as statements about the policy. |

Injected defects. Each was caught by the named test, and the file was
restored byte for byte (SHA-256 compared):

| Defect | Failing tests |
|---|---|
| The escaper stops escaping `"` | `quoting_round_trips_or_refuses`, `a_hostile_directory_name_stays_one_subpath` |
| The glob compiler stops escaping `.` | `generated_globs_escape_every_literal`, `a_glob_becomes_one_anchored_escaped_pattern` |
| `AbsPath` accepts `..` | `each_refusal_names_its_reason`, `generated_inputs_match_the_rules` |
| The table cell for `fs-protect` on T2 changes from `unsupported` to `exact` | `every_row_matches_the_lowering` |
| The hard-deny block comes before the deny-within-allow block | `blocks_are_in_fixed_order_and_the_tier_is_last` |
| `merge_adjacent` ignores the effect | `merged_rules_never_mix_effects`, `merging_never_changes_a_decision` |
| `deny_unknown_fields` is removed from `FsRule` | `unknown_fields_are_refused` |

Found and fixed during implementation:

- With `unstable-operations`, the escape hatch accepted `default`, which would
  allow allow-by-default. `OperationName` now refuses `default`.
- An unfiltered rule absorbed only its direct neighbour. This was exact but
  left redundant rules. It now absorbs every like rule before it.
