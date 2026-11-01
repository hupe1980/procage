# Data Model: 002-threat-model

All entities are text in `THREAT_MODEL.md`. The gate in `tests/threat_model.rs`
parses them into the types below. None of them is public API.

## EscapeClass (one catalog row)

| Field | Type | Rules |
|---|---|---|
| `id` | `R-NN` | `^R-\d\d$`, unique, in the published-id baseline |
| `class` | text | non-empty short name, no `|` |
| `description` | text | non-empty, one line, no exploit steps (SR-010) |
| `platforms` | `Platforms` | `macOS` \| `Linux` \| `macOS, Linux` |
| `disposition` | `Disposition` | `mitigate` \| `detect` \| `harness` |
| `status` | `Status` | `planned` \| `mitigated` \| `detected` \| `documented` \| `retired` |
| `evidence` | `Vec<EvidenceRef>` | `—` = empty; required non-empty for `mitigated` and `detected` |
| `observed_on` | `Vec<KernelFactId>` | `—` = empty; each `^KF-[ML]\d\d$` and present in the kernel-facts catalog |

### Disposition × status

| Disposition | Allowed status |
|---|---|
| mitigate | planned, mitigated, retired |
| detect | planned, detected, retired |
| harness | documented, retired |

A `harness` row also needs an entry `- **R-NN** …` under `### Harness
responsibilities` (FR-009).

## EvidenceRef

`<path>::<fn>`. The path is repo-relative, starts with `tests/`, ends with `.rs`
and is not under `tests/kernel_facts/`. The file must exist and contain
`fn <fn>`.

## KernelFactId

`KF-Mnn` or `KF-Lnn`. Each one is resolved against the `id: "…"` literals in
`tests/kernel_facts/tests/kernel_facts.rs`.

## PublishedBaseline

`const PUBLISHED: [&str; 20]` with R-02…R-12, R-21…R-26 and R-28…R-30. It is
append-only, and the catalog's id set must equal it.

## Document

These `## ` headings must appear in this order (R7):

1. Release status. It must contain `procage <version>`.
2. Adversary
3. Assets
4. Trusted
5. In scope
6. Out of scope
7. Strength
8. Dependencies on undocumented interfaces
9. Non-goals
10. Escape classes. It contains the catalog table and `### Harness
    responsibilities`.

## Violation (gate output)

`{ rule: Rule, subject: String, detail: String }`, printed as
`threat-model gate: <rule>: <subject>: <detail>`.

| Rule | Subject |
|---|---|
| `row-format` | line number |
| `value` | id + field |
| `disposition-status` | id |
| `baseline-missing` | id |
| `baseline-unknown` | id |
| `duplicate-id` | id |
| `evidence-required` | id |
| `evidence-location` | id + ref |
| `evidence-missing` | id + ref |
| `kernel-fact` | id + KF id |
| `heading` | heading |
| `release-status` | the found and the expected version |
| `harness-note` | id |
| `link` | file |
