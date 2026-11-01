# Quickstart: 034-linux-violations

```sh
just linux && just linux-t1        # spawn_linux violation tests, escape suite with reporting
just kf-linux && just kf-linux-t1  # KF-L15
cargo test -p procage-policy       # reasons, matches() vs the interpreter
just ci
```

## Results (2026-11-01, Docker Linux 7.0.14 aarch64; macOS 26.6.2)

- T2 / T1: lib 35/35 (incl. verdict-only and `matches` ≡ interpreter), spawn
  46/46 (11 violation tests), escape 22/22 without and with reporting (R-32),
  exec 10/20 (incl. the reporting exec), native 5/5.
- KF-L15 passes on both tiers (kernel facts 7 pass on T2, 14 on T1).
- macOS: `just ci` all gates; the escape suite once had a child die without
  output under load (r23, no 034 code), 8/8 on rerun.
- Found in the lanes: Docker's own profile refuses `bpf` first, so it is not
  reported (an outer filter's EPERM wins over notification); documented.
