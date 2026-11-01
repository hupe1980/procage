# Contract: catalog and gate rules (009 additions)

Existing rules (002) stay. New or changed rules:

| Rule | Fires when |
|---|---|
| `value` | status is not one of planned, partial, mitigated, detected, documented, retired |
| `disposition-status` | status not allowed for the disposition (see data-model) |
| `evidence-required` | mitigated, detected or partial without evidence |
| `evidence-location` | evidence not in `tests/escape_macos.rs` or `tests/escape_linux.rs`, or the function name does not start with the row id |
| `evidence-missing` | the function does not exist |
| `evidence-ignored` (new) | an evidence function is marked `#[ignore]` |
| `evidence-platform` (new) | mitigated or detected without evidence in the file of every listed platform |
| `canary-missing` (new) | a listed platform's file has no function prefixed with the row id |
| `open-canary` (new) | a mitigated or detected row has an ignored canary in any file |
| `open-variant-note` (new) | a partial row without an `### Open variants` entry |

Defect-injection tests: one per new rule, each asserting that exactly that
rule fires on a mutated copy of the real files.

Release status: a sentence per open variant stays in `## Release status`.
This is reviewed, not machine-checked.
