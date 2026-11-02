# Quickstart: validating the IP network

```sh
cargo test -p procage-policy --test network_ip --test fit --test sockets
cargo test -p procage --test escape_macos r34          # macOS
just linux-t1 && just linux                            # T1 and T2
```

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | `just ci`; `escape_macos` with `tokio,proxy` | passed |
| Linux T1 (container, 7.0, ABI 8) | `just linux-t1` | passed |
| Linux T2 (container, 7.0, ABI 8) | `just linux` | passed |

Security convergence: SR-001 to SR-003 verified (see
`security/convergence-report.md`).
