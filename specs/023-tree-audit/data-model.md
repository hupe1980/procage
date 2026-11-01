# Data model

- `LinkAudit` — `Refuse` (default) | `Report` | `Off`.
- `LinkFinding` — `path` (bytes), `links` (the file's link count).
- `HandoffFinding` — `path` (bytes), `kind`: `Created` | `Modified` |
  `Link { target }` (bytes, unresolved) | `Repository`.
- `Audit` — `links: Vec<LinkFinding>`, `links_complete: bool`,
  `handoff: Option<Vec<HandoffFinding>>` (with the handoff audit),
  `handoff_complete: bool`, `visited` (entries examined).
- Receipt `audit` — `{ links, handoff, complete }` counts; paths only when
  the policy is included.
