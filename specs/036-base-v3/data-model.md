# Data model: 036-base-v3

| Entity | Fields | Rules |
|---|---|---|
| Quiet rule | deny, ops, filters, `quiet = true` | rendered `(with no-report)`; never carries a reason message |
| Base V3 (macOS) | quiet rules, then V2 allows | quiet block directly after `(deny default)` |
| Violation | + `repeats: u32` | merged on equal (pid, process, operation, target, denied_by); saturating |
