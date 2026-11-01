# Quickstart: checking 023

```sh
cargo test -p procage --test audit --test escape_macos r08   # macOS
just linux && just linux-t1                                   # Linux T2, T1
just ci
```

Expected: a pre-existing hard link to a hidden or protected file refuses
the spawn (or is listed in report mode); every handoff artefact a run
leaves is listed once.

## Results, 2026-11-02

| Lane | Result |
|---|---|
| macOS 26.6.2 (25G83), outside any sandbox | `just ci` green; escape suite: the three R-08 canaries pass (R-25, R-26 open); `audit` 5 passed; `receipts` 13 passed; site builds |
| Docker Linux 7.0.14 aarch64, T2 | lib 45, audit 5, escape 30 (+1 open), exec 10, native 5, receipts 14, spawn 47 (+1), unsafe 2; escape with reporting 30 (+1) |
| Docker Linux 7.0.14 aarch64, T1 | the same, exec 20 |

Findings during implementation:

- A real home holds benign multi-link files inside a class directory
  (GnuPG's lock protocol hard-links `public-keys.d/pubring.db.lock`). A file
  is therefore a finding only when it has more names than the check finds
  among the targets: names that all lie inside the protected set give
  nothing away.
- `~/.kube` held 5,359 entries of kubectl caches; walking them made the
  default check cost 44 ms per spawn. Cache directories inside class paths
  are not walked (credentials are not kept in caches); the policy's own
  protect and hide targets are always walked in full.
- Cost of the default link check (release, the `latency` probes): macOS
  overhead over a plain fork and exec 1.26–1.68 ms (about 0.5 ms before; the
  home holds about 150 class entries); Linux T1 median spawn 1.29 ms (1.10
  before), T2 440–470 µs (about 420 before) — within SC-003.
