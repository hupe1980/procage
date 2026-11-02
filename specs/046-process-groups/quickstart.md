# Quickstart: validating process groups under `Lifetime::Run`

```sh
cargo test -p procage-policy --test gaps lifetime     # setpgid denied only with Tty::Inherit
just linux-t1 && just linux                            # r23 canaries, exec
```

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | policy tests, `just ci` | passed |
| Linux T1 (container, 7.0, ABI 8) | `just linux-t1`: r23 canaries, `exec.rs` | passed |
| Linux T2 (container, 7.0, ABI 8) | `just linux` | passed |

Security convergence: SR-001 to SR-003 verified (see
`security/convergence-report.md`).
