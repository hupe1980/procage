# Contract: threat-model gate and recipes

## `tests/threat_model.rs` (runs in `cargo test --workspace`, i.e. `just test`)

The gate reads these files under `CARGO_MANIFEST_DIR`:

- `THREAT_MODEL.md`
- `README.md`
- `src/lib.rs`
- `tests/kernel_facts/tests/kernel_facts.rs`
- every evidence file the catalog names

It prints one line per violation:

```text
threat-model gate: <rule>: <subject>: <detail>
```

The test fails if there is at least one violation.

| Rule | Fails when | SR |
|---|---|---|
| row-format | a table row has ≠ 8 cells or the header differs | SR-004 |
| value | a platform, disposition, status, evidence ref or KF id has the wrong form | SR-004 |
| disposition-status | the pair is not allowed (data-model) | SR-004 |
| baseline-missing / baseline-unknown / duplicate-id | the id set ≠ the published baseline | SR-003 |
| evidence-required | status mitigated or detected and evidence `—` | SR-001 |
| evidence-location | the ref is not under `tests/`, is under `tests/kernel_facts/`, or is not `.rs` | SR-002 |
| evidence-missing | the file is absent or lacks `fn <name>` | SR-001 |
| kernel-fact | an observed-on id is not in the kernel-facts catalog | SR-005 |
| heading | a required heading is missing or out of order | SR-007 |
| release-status | `procage <CARGO_PKG_VERSION>` is absent from Release status | SR-007 |
| harness-note | a harness row has no entry under Harness responsibilities | FR-009 |
| link | the README lacks a link to `THREAT_MODEL.md`, or `src/lib.rs` lacks `pub mod threat_model;` or a doc link to it | FR-010 |

The checks are functions over `&str` inputs. Unit tests in the same file apply
one mutation per rule to the real document and assert that exactly that rule
fires (SC-003).

## justfile

- `planning-paths`: the scanned paths add `THREAT_MODEL.md` and `SECURITY.md`
  (SR-008).
- `package-docs` (new, part of `ci`): it confirms that `cargo package --list
  -p procage --allow-dirty` contains `THREAT_MODEL.md`. It then packages the
  crate, unpacks it into a temp directory outside the workspace, and runs
  `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps` there (SR-006).
