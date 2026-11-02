# Research: process introspection

Measured 2026-11-01/02 on macOS 26.6.2 (25G83), Apple M4 Pro, outside any
sandbox, with small C probes reading `KERN_PROCARGS2` of a same-user
`/bin/sleep`, of the process itself and of its own child, under
`sandbox-exec -p` profiles, then confirmed by the escape-suite canary.

| Profile | Other process | Self, own child | Numeric `hw.ncpu`, `kern.proc.pid` |
|---|---|---|---|
| `(deny default)` alone | readable | readable | — |
| deny-default + `(allow sysctl-read)` + `(allow process-info* (target same-sandbox))` (the 0.1.0 V1–V3 shape) | readable | readable | ok |
| allow-default + `(deny process-info* (target others))` | readable | | |
| `(deny sysctl-read (sysctl-name "kern.procargs2"))` (exact name, any profile) | readable | | |
| `(deny sysctl-read (sysctl-name-prefix "kern.procargs"))` alone, pidinfo not denied explicitly | readable | | ok |
| explicit `(deny sysctl-read)` and `(deny process-info-pidinfo)`, both unfiltered | EPERM | | |
| deny-default + `(deny sysctl-read)` + a named sysctl allowlist + `(deny process-info-pidinfo)` + `(allow process-info-pidinfo (target self) (target children))` (the dropped base V4 shape) | EPERM | readable | ok |
| the same with `(sysctl-name-prefix "kern.")` in the allowlist | readable | | ok |
| V1–V3 + the prefix deny + early `(deny process-info-pidinfo)` + `(allow process-info-pidinfo (target same-sandbox))` (**the built rule**) | **EPERM** | readable (every process of the run) | ok |

- **Decision**: the last row, in the `process-access` hard-deny class, on
  every base and preset: the prefix deny, the early unfiltered pidinfo deny
  and the same-sandbox pidinfo allow. `sysctl-read` stays allowed otherwise,
  so no allowlist is needed and the program set is unaffected.
- **Rationale**: the read passes if either `sysctl-read` or
  `process-info-pidinfo` allows it; the numeric call is matched by unfiltered
  rules and by prefixes, not by an exact `kern.procargs2` name; the default
  deny does not count, so the pidinfo deny must be explicit. Same-sandbox
  (rather than self and children) keeps every process of the run readable.
- **Alternatives rejected**: a frozen base V4 with an unfiltered
  `(deny sysctl-read)` and a sysctl allowlist (the dropped design: a new base
  and presets for no release user, and an allowlist to keep complete).
- **Findings**: Seatbelt does not log `sysctl-read` denials (enforced as
  EPERM, never reported). `ps` is setuid and refused in any cage; `pgrep`
  needs `sysmond`. Both are limits, not tested.
- **Open**: macOS 27 is re-measured on its lane when it exists.
