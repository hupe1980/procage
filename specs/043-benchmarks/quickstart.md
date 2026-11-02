# Quickstart: checking 043

```sh
cargo bench -p procage --bench spawn             # full run (outside any sandbox on macOS)
cargo bench -p procage --bench spawn -- --quick  # CI's short run
```

## Results, 2026-11-02 (300 iterations per case; overhead = median over a plain spawn)

**Apple M4 Pro, macOS 26.6.2 (25G83)**, outside any sandbox, `presets::minimal::v3`:

| Case | Median | p90 | p99 | Overhead |
|---|---|---|---|---|
| plain spawn | 0.872 ms | 1.282 ms | 1.601 ms | — |
| procage, cached cage | 1.905 ms | 2.206 ms | 2.576 ms | 1.033 ms |
| procage, cached cage, link check off | 1.455 ms | 1.566 ms | 2.097 ms | 0.583 ms |
| procage, new policy per spawn (compiles) | 12.496 ms | 13.046 ms | 13.487 ms | 11.624 ms |
| procage, with violation reporting | 2.677 ms | 3.142 ms | 4.277 ms | 1.805 ms |
| `sandbox-exec -p` (same profile, compiles every time) | 11.821 ms | 12.899 ms | 14.146 ms | 10.949 ms |

**Docker Desktop, Linux 7.0.14-linuxkit aarch64** (same Mac, seccomp and
AppArmor unconfined, as root), bubblewrap 0.12.0:

| Case | Median | p90 | p99 | Overhead |
|---|---|---|---|---|
| plain spawn | 0.181 ms | 0.200 ms | 0.221 ms | — |
| procage, cached cage, T1 | 1.171 ms | 1.275 ms | 12.416 ms | 0.990 ms |
| procage, cached cage, link check off, T1 | 1.134 ms | 1.244 ms | 11.721 ms | 0.953 ms |
| procage, new policy per spawn, T1 | 1.348 ms | 1.624 ms | 9.713 ms | 1.167 ms |
| procage, with violation reporting, T1 | 1.164 ms | 1.257 ms | 13.058 ms | 0.983 ms |
| procage, cached cage, T2 | 0.451 ms | 0.526 ms | 0.569 ms | 0.269 ms |
| procage, cached cage, link check off, T2 | 0.435 ms | 0.517 ms | 0.555 ms | 0.254 ms |
| procage, new policy per spawn, T2 | 0.685 ms | 0.975 ms | 1.023 ms | 0.504 ms |
| procage, with violation reporting, T2 | 0.440 ms | 0.524 ms | 2.887 ms | 0.258 ms |
| `bwrap --ro-bind / / --unshare-all` | 1.628 ms | 2.218 ms | 10.152 ms | 1.446 ms |

Readings:

- macOS: a cached caged spawn costs 1.0 ms over a plain one, about half of
  it the default link check. `sandbox-exec` compiles the profile on every
  run, 10× the cached cost. The earlier 0.3 ms target is not met; the docs
  state the measurement.
- Linux: T1 about 1 ms (namespaces and mounts, within the 1 ms target), T2
  about 0.3 ms; bwrap needs 1.4 ms for less (no Landlock, no seccomp). T1's
  p99 reflects the container's namespace teardown.
