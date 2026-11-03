# Quickstart: CI lanes for the releases people run

## Validate

```sh
just workflows   # pins, read-only token, triggers, expressions, caches, lane table
```

Push to `main` and read each lane's header in the job log (`os:`, `arch:`,
`sandboxed:`, `tier:`). A lane fails on a `MISMATCH` line.

## Measured (2026-11-03)

| Runner | Release | Arch | Tier |
|---|---|---|---|
| `macos-26` | macOS 26.6.2 (25G83) | aarch64 | — |
| `xcode-27` | macOS 27.0.1 (26A434) | aarch64 | — |
| `ubuntu-24.04` | Ubuntu 24.04.5, Linux 7.0.0-1017-azure | x86_64 | T2 shipped, T1 with the sysctl |
| `ubuntu-24.04-arm` | Ubuntu 24.04.5, Linux 7.0.0-1017-azure | aarch64 | T2 shipped, T1 with the sysctl |
| `ubuntu-26.04` | Ubuntu 26.04.1, Linux 7.0.0-1017-azure | x86_64 | T2 shipped, T1 with the sysctl |

- macOS 27: the base program set runs; no new base version is needed. Base
  V3 quiets about 80 % of the developer-tool reports there (90 % on 26).
- macOS 15.8.2: an identical second profile returns `EPERM` (KF-M05,
  KF-M09, now release-aware), and the developer tools fail under base V2
  and V3. The lane is removed and macOS 15 is named untested.
- Ubuntu 26.04: the documented sysctl still gives tier T1.
- The gate fails on a tag pin, a cache step, and `github.event` in a run
  script (checked by editing `ci.yml` and restoring it).
- CI run 41632414082 (`43faa47`): every lane in the table green.
