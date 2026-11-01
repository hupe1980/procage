## Security Convergence — 037-public-design-records

Commit `2a17f99` · 2026-11-01T17:29:58Z

| Metric | Value |
|---|---|
| Threats (active) | 3 |
| Open blocking threats | 0  |
| Security requirements | 3 |
| verified | 3 |
| implemented, unverified | 0  |
| partial | 0  |
| missing | 0  |
| Expired decisions | 0  |
| Source drift | none |

**Status: CONVERGED**

| Requirement | Verdict | Method | Evidence | Justification |
|---|---|---|---|---|
| SR-001 | verified | scan | `just planning-paths (specs/ and .specify/memory/); a scan of specs/ and .specify/ for token patterns, e-mail addresses and home-directory paths` | All 20 public rows were rewritten by one rulebook; the gate's pattern (private-note directory and ids, research-note paths, planning references, consumer and other private project names, home-directory paths, e-mail addresses) finds nothing, and the token scan finds nothing. The five consumer rows moved to the consumer's own repository. |
| SR-002 | verified | review | `specs/README.md` | The README says records describe each change as made, that the README, the threat model and the documentation are authoritative and win where they differ, and explains what each file of a record holds. |
| SR-003 | verified | test | `just planning-paths with a planted decision id in specs/README.md` | The gate exits 1 with the planted line and 0 after it is removed; it also caught its own pattern text in the justfile during development (fixed with a bracket expression). |
