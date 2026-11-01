# Contract: the lowering table

**Source**: `crates/procage-policy/src/lowering.md`. It is included as the
rustdoc of module `procage_policy::lower`, and it is the fixture of
`crates/procage-policy/tests/lowering_table.rs`.

## Format

The table is the first Markdown table after the heading
`## Lowering table`. Its header is exactly:

```text
| Construct | macOS | Linux T1 | Linux T2 | Note |
```

Each row:

- `Construct`: a backticked `Construct` name (data-model.md). It must be
  unique, and every `Construct` variant must appear exactly once.
- Each target cell is one of:
  - `exact`, `approximated`, `unsupported`, `n/a`;
  - `<outcome> (ABI ≥ N) / <outcome>`: the first outcome applies when the
    Landlock ABI is N or higher, and the second otherwise. This form is
    allowed only in the Linux columns.
- `Note`: free text, which may be empty. It states observable differences
  (for example the errno for `fs-hide` on T1).

## Test semantics

For each row and each target, the test builds the row's reference policy
(one per construct, in `tests/common/mod.rs`). It then lowers that policy:

- for macOS;
- for T1 at ABI 1, 8 and 12;
- for T2 at ABI 4, 5, 6, 8, 9 and 12;
- and, for an `ABI ≥ N` cell, also at N−1 and N, where valid for the tier.

Each outcome is checked like this:

| Cell | Without `allow_degrade` | With the construct allowed |
|---|---|---|
| `exact` | `Ok(plan)`, and the plan lists no degradation for the construct | — |
| `approximated` | `Err(Gaps)` with a gap of kind `Approximation` for the construct | `Ok(plan)` with one `Degradation` for it |
| `unsupported` | `Err(Gaps)` with kind `Unsupported` | the same error (degradation cannot help) |
| `n/a` | `Ok(plan)`; the construct contributes nothing | — |

For `n/a`, "contributes nothing" means: the profile or plan equals the plan
of the same policy with that construct removed or waived.

Failure messages name the construct, the target and the ABI.
