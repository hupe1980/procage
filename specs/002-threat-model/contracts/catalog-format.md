# Contract: escape-class catalog format

This is the format that the gate enforces and that the escape suite (a later
feature) will parse to require one canary per class.

## Location

`THREAT_MODEL.md`, section `## Escape classes`. The catalog is the first
Markdown table after that heading. The table ends at the first line that does
not start with `|`.

## Table

```text
| Id | Class | Description | Platforms | Disposition | Status | Evidence | Observed on |
|---|---|---|---|---|---|---|---|
| R-21 | Inherited file descriptors | An fd opened before the cage reads or writes past every path rule. | macOS, Linux | mitigate | planned | — | KF-M19 |
```

- The header row must match exactly. Any separator of dashes is accepted.
- Every following `|` line is a row with exactly 8 cells after trimming. Cells
  contain no `|`.
- `—` (U+2014) marks an empty list. List values are separated by `, `.
- Code spans (backticks) are allowed only in Class and Description.

## Harness responsibilities

Under `### Harness responsibilities` (still inside `## Escape classes`):

```text
- **R-07** procage provides … The harness must …
```

Each `harness` row needs exactly one such entry.

## Consumers

- **Gate** (`tests/threat_model.rs`): all rules in [gate.md](gate.md).
- **Escape suite**: every row whose status is not `retired` and whose
  disposition is `mitigate` or `detect` needs a canary named after the id. The
  suite defines its own naming; this format guarantees the rows parse.

## Stability

- Ids are never removed, renumbered or reused. A row that no longer applies
  becomes `retired`.
- Adding a column or changing the header is a format change. It needs this
  contract, the gate and the escape suite to change together.
