# Quickstart: validating a helper's command in its own session

```sh
cargo test -p procage --test exec a_session     # macOS
just linux-t1 && just linux                      # T1 and T2
```

## Results (2026-11-02)

| Where | Run | Result |
|---|---|---|
| macOS 26 (arm64) | `tests/exec.rs`, `just ci` | passed |
| Linux T1 (container, 7.0, ABI 8) | `just linux-t1` (exec: 24 cases on both tiers) | passed |
| Linux T2 (container, 7.0, ABI 8) | `just linux` (exec: 12 cases) | passed |

Security convergence: SR-001 to SR-003 verified (see
`security/convergence-report.md`).
