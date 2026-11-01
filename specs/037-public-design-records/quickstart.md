# Quickstart: Public design records

## Results (2026-11-01)

| Check | Result |
|---|---|
| Public rows | 20 (001–010, 024, 026–030, 032, 034, 036–038); consumer rows moved to the consumer |
| `threatspec check` on every row | no findings (after restoring rows 026–029's task lists, emptied by a script bug on 2026-10-31 and recovered from the session record) |
| `just planning-paths` | passes; fails on a planted decision id |
| Token, e-mail and home-path scan | nothing |
| `just site` | builds (13 pages) |

## Run

```sh
just planning-paths
for d in specs/[0-9]*/; do .specify/extensions/threatspec/scripts/bash/threatspec.sh --feature-dir "$d" check; done
```
