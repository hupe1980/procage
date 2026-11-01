# Quickstart: checking 011

```sh
cargo test -p procage --test receipts        # macOS (outside any sandbox)
just linux && just linux-t1                   # Linux T2 and T1 (Docker)
just ci
```

Expected: every receipt round-trips, names its backend and tier, says
whether the run was enforced as written, and contains no environment value,
argument or path unless the policy was requested.

## Results, 2026-11-01

| Lane | Result |
|---|---|
| macOS 26.6.2 (25G83), outside any sandbox | `just ci` green (every gate); `receipts` 8 passed (the `fit` case is Linux-only); site builds |
| Docker Linux 7.0.14 aarch64, tier T2 | `receipts` 9 passed; lib 41, spawn 47 (+1), exec 10, native 5, unsafe 2, escape 27 (+2 open), with reporting 27 (+2) |
| Docker Linux 7.0.14 aarch64, tier T1 | the same, exec 20 |

- The reference digest of the default policy is the same on both systems
  (`tests/fixtures/default-policy.digest`).
- Spawn latency (macOS, release, the ignored `latency` probe, overhead over a
  plain fork and exec): 459–610 µs with receipts, 482–656 µs without — the
  same within the probe's noise.
- Linux (Docker, release, the probe's median spawn time): T1 1.10–1.13 ms
  with receipts, 1.08–1.14 ms without; T2 418–532 µs with (four of five runs
  at 418–422), 411–424 µs without — the same within noise.
- After the remediation: `receipts` 12 passed on macOS, 13 on Linux T1 and T2.
